#!/usr/bin/env ruby

=begin

= File
	nfqueue.rb

= Author
  Guillaume Delugré, guillaume(at)security-labs.org

= Info
	This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

=end


require 'rubygems'
require 'ffi'
require 'socket'

module Netfilter

  #
  # This class represents a packet filtered by a Netfilter::Queue.
  #
  class Packet
    
    class Timeval < FFI::Struct #:nodoc:
      layout :tv_sec, :ulong,
        :tv_usec, :ulong
    end

    class Header < FFI::Struct #:nodoc:
      layout :packet_id, :uint32,
        :hw_protocol, :uint16,
        :hook, :uint8
    end

    class HardwareAddress < FFI::Struct #:nodoc:
      layout :hw_addrlen, :uint16,
        :__pad, :uint16,
        :hw_addr, [:uint8, 8]
    end

    DROP    = 0
    ACCEPT  = 1
    STOLEN  = 2
    QUEUE   = 3
    REPEAT  = 4
    STOP    = 5

    attr_reader :id
    attr_writer :data

    def initialize(nfad) #:nodoc:
      @nfad = nfad

      phdr = Queue.nfq_get_msg_packet_hdr(nfad)
      hdr = Header.new(phdr)

      @id = [ hdr[:packet_id] ].pack("N").unpack("V")[0]
    end

    #
    # The packet timestamp.
    #
    def timestamp
      ptv = FFI::MemoryPointer.new :pointer
      tv = Timeval.new(ptv)
      if Queue.nfq_get_timestamp(@nfad, ptv) < 0
        0
      else
        Time.at(tv[:tv_sec])
      end
    end

    #
    # The index of the device the queued packet was received via.
    # If the return index is 0, the packet was locally generated or the input interface is not known (ie. POSTROUTING?).
    #
    def indev
      Queue.nfq_get_indev(@nfad)
    end

    #
    # The index of the physical device the queued packet was received via. 
    # If the returned index is 0, the packet was locally generated or the physical input interface is no longer known (ie. POSTROUTING).
    #
    def phys_indev
      Queue.nfq_get_physindev(@nfad)
    end

    #
    # The index of the device the queued packet will be sent out.
    # It the returned index is 0, the packet is destined for localhost or the output interface is not yet known (ie. PREROUTING?).
    #
    def outdev
      Queue.nfq_get_outdev(@nfad)
    end

    #
    # The index of the physical device the queued packet will be sent out. 
    # If the returned index is 0, the packet is destined for localhost or the physical output interface is not yet known (ie. PREROUTING).
    #
    def phys_outdev
      Queue.nfq_get_physoutdev(@nfad)
    end

    #
    # The source hardware address.
    #
    def hw_addr
      phw = Queue.nfq_get_packet_hw(@nfad)
      return nil if phw.null?

      hw = HardwareAddress.new(phw)
      hw[:hw_addr][0, hw[:hw_addrlen]]
    end

    #
    # The packet contents.
    #
    def data
      if @data.nil?
        pdata = FFI::MemoryPointer.new(:pointer, 1)
        size = Queue.nfq_get_payload(@nfad, pdata)
        if size < 0
          raise QueueError, "nfq_get_payload has failed"
        end
    
        @data = pdata.read_pointer.read_string(size)
      else
        @data
      end
    end
  end

  #
  # Class representing a Netfilter Queue.
  #
  class QueueError < Exception; end
  class Queue
    extend FFI::Library

    ffi_lib 'libnetfilter_queue'

    attach_function 'nfq_open', [], :pointer
    attach_function 'nfq_open_nfnl', [:pointer], :pointer
    attach_function 'nfq_close', [:pointer], :int
    attach_function 'nfq_bind_pf', [:pointer, :uint16], :int
    attach_function 'nfq_unbind_pf', [:pointer, :uint16], :int
    attach_function 'nfq_nfnlh', [:pointer], :pointer
    attach_function 'nfq_fd', [:pointer], :int
    callback :nfq_callback, [:pointer, :pointer, :pointer, :buffer_in], :int
    attach_function 'nfq_create_queue', [:pointer, :uint16, :nfq_callback, :buffer_in], :pointer
    attach_function 'nfq_destroy_queue', [:pointer], :int
    attach_function 'nfq_handle_packet', [:pointer, :buffer_in, :int], :int
    attach_function 'nfq_set_mode', [:pointer, :uint8, :uint32], :int
    attach_function 'nfq_set_queue_maxlen', [:pointer, :uint32], :int
    attach_function 'nfq_set_verdict', [:pointer, :uint32, :uint32, :uint32, :buffer_in], :int
    attach_function 'nfq_set_verdict_mark', [:pointer, :uint32, :uint32, :uint32, :uint32, :buffer_in], :int
    
    attach_function 'nfq_get_msg_packet_hdr', [:pointer], :pointer
    attach_function 'nfq_get_nfmark', [:pointer], :uint32
    attach_function 'nfq_get_timestamp', [:pointer, :pointer], :int
    attach_function 'nfq_get_indev', [:pointer], :int
    attach_function 'nfq_get_physindev', [:pointer], :int
    attach_function 'nfq_get_outdev', [:pointer], :int
    attach_function 'nfq_get_physoutdev', [:pointer], :int
    attach_function 'nfq_get_packet_hw', [:pointer], :pointer
    attach_function 'nfq_get_payload', [:pointer, :pointer], :int

    module CopyMode
      NONE = 0
      META = 1
      PACKET = 2
    end

    #
    # Creates a new Queue at slot _qnumber_.
    #
    def initialize(qnumber, mode = CopyMode::PACKET)
      @conn_handle = Queue.nfq_open
      raise QueueError, "nfq_open has failed" if @conn_handle.null?

      ret = Queue.nfq_unbind_pf(@conn_handle, Socket::AF_INET)
      if ret < 0
        close
        raise QueueError, "nfq_unbind_pf has failed: #{ret}"
      end
      
      if Queue.nfq_bind_pf(@conn_handle, Socket::AF_INET) < 0
        close
        raise QueueError, "nfq_unbind_pf has failed"
      end

      @qhandle = Queue.nfq_create_queue(@conn_handle, qnumber, method(:callback_handler), nil)
      if @qhandle.null?
        close
        raise QueueError, "nfq_create_queue has failed" if @qhandle.null?
      end

      set_mode(mode)
    end

    #
    # Changes the copy mode for the queue.
    #
    def set_mode(mode, range = 0xffff_ffff)
      if Queue.nfq_set_mode(@qhandle, mode, range) < 0
        raise QueueError, "nfq_set_mode has failed"
      end

      self
    end

    #
    # Sets the maximum number of elements in the queue.
    #
    def set_max_length(len)
      if Queue.nfq_set_queue_maxlen(@qhandle, len) < 0
        raise QueueError, "nfq_queue_maxlen has failed"
      end

      self
    end

    #
    # Processes packets in the queue, passing them through the provided callback.
    #
    def process(&callback)
      @callback = callback

      fd = Queue.nfq_fd(@conn_handle)
      raise QueueError, "nfq_fd has failed" if fd < 0

      io = IO.new(fd)
      while data = io.sysread(4096)
        Queue.nfq_handle_packet(@conn_handle, data, data.size)
      end
    end

    #
    # Close the queue.
    #
    def destroy
      LibNetfilterQueue.nfq_destroy_queue(@qhandle)
      close
    end

    #
    # Creates a new Queue with the provided callback.
    # The queue will be automatically destroyed at return.
    #
    def self.create(qnumber, mode = CopyMode::PACKET, &callback)
      queue = self.new(qnumber, mode)
      queue.process(&callback)
      queue.destroy
    end

    private

    def callback_handler(qhandler, nfmsg, nfad, data) #:nodoc:
      packet = Packet.new(nfad)
      verdict = @callback[packet]
      
      data = packet.data

      Queue.nfq_set_verdict_mark(
        qhandler, 
        packet.id, 
        verdict, 
        1,
        data.size, 
        data
      )
    end

    def close #:nodoc:
      Queue.nfq_close(@conn_handle)
    end

  end
end

__END__

# Example

system('sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0')

Netfilter::Queue.create(0) do |packet|
  puts packet.id

  p packet.data
  Netfilter::Packet::ACCEPT
end

