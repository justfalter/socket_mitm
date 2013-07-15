require 'ipaddr'
require 'packetfu'
require 'socket'
require_relative 'local_nfqueue'

require 'eventmachine'

port = ARGV.shift
if port.nil?
  warn "expected a port number"
  exit 1
end
port = port.to_i

class ServerConnection < EM::Connection
  def initialize(client)
    @client = client
  end

  def receive_data(data)
    warn "server -> client #{data.length} bytes"
    @client.send_data(data)
  end

  def unbind
    @client.close_connection()
  end
end

class ClientConnection < EM::Connection
  def initialize(conntrack)
    @conntrack = conntrack
    tcp_src, ip_src = Socket.unpack_sockaddr_in(get_peername)
    ip_dst, tcp_dst = conntrack.get(ip_src, tcp_src)
    if ip_dst.nil?
      close_connection()
      return
    end
    @server = EventMachine.connect ip_dst, tcp_dst, ServerConnection, self
    super()
  end

  def receive_data(data)
    warn "client -> server #{data.length} bytes"
    @server.send_data(data)
  end

  def unbind
    @server.close_connection() unless @server.nil?
  end
end

class Conntrack
  def initialize
    @mtx = Mutex.new
    @mapping = {}
  end

  def register(iph, tcph)
    @mtx.synchronize do
      @mapping[[iph.ip_src, tcph.tcp_src]] = [iph.ip_dst, tcph.tcp_dst]
    end
  end

  def get(ip, port)
    ip = IPAddr.new(ip).to_i
    @mtx.synchronize do 
      ip_dst, tcp_dst = @mapping.delete [ip, port]
      return nil if ip_dst.nil?
      ip_dst = IPAddr.new(ip_dst, Socket::AF_INET).to_s
      return [ip_dst, tcp_dst]
    end
  end
end

conntrack = Conntrack.new

threads = []
netfilter_thread = Thread.new do
  Netfilter::Queue.create(0) do |nfpacket|
    iph = PacketFu::IPHeader.new
    iph.read(nfpacket.data)
    tcph = PacketFu::TCPHeader.new
    tcph.read(iph.body)
    conntrack.register(iph, tcph)

    Netfilter::Packet::REPEAT
  end
end

threads << netfilter_thread

em_thread = Thread.new do
  EventMachine.run do
    # hit Control + C to stop
    Signal.trap("INT")  { EventMachine.stop }
    Signal.trap("TERM") { EventMachine.stop }

    EventMachine.start_server("0.0.0.0", port, ClientConnection, conntrack)
  end

end
threads << em_thread

loop do
  threads.each do |thr|
    thr.join(0.1)
  end
end
