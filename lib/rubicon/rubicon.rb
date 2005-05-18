require 'osc/osc'
require 'socket'

# SERVER

# OSC commands:
# /hi    'ss' <id> <pass> -- register as client <id> (password optional)
# /osc   'sb' <dst> <pkt> -- send OSC blob <pkt> to client <dst>

# OSC notifications:
# /osc   'sb' <src> <pkt> -- recv OSC blob <pkt> from client <src>
# /error 's'  <msg>       -- recv error <msg>

# RELAY:

# send /notify to get a list of local relays: <name> <ip> <port>
# send OSC packets to local relays to talk to remote peers
# register OSCresponders with local relay addresses to recv from remote peers

# log:
# connections

# security:
#  password
#  hosts.allow

class Array
  def choose
    self[rand(self.size)]
  end
end

class Hash
  def choose
    self[self.keys.choose]
  end
end

class TCPSocket
  def recv_osc(len, flags=0)
    pkt_len = recv(4, flags).unpack('N')[0]
    if pkt_len and pkt_len <= len
      return recv(pkt_len, flags)
    end
    return ''
  end
  def send_osc(data, flags=0)
    send([data.size].pack('N'), flags)
    send(data, flags)
  end
end

module Rubicon
  SERVER_ID             = 'rubicon'
  MAX_PACKET_SIZE       = 2**14
  $log                  = $stdout

  ERROR_NONE            = 0
  ERROR_INVALID_LOGIN   = 1
  ERROR_INVALID_ID      = 2
  ERROR_DUPLICATE_ID    = 3

  ERROR_STRINGS = {
    ERROR_NONE => 'no error',
    ERROR_INVALID_LOGIN => 'invalid login',
    ERROR_INVALID_ID => 'invalid id',
    ERROR_DUPLICATE_ID => 'duplicate id'
  }

  # utility
  class Address
    attr_reader :addr, :port
    def initialize(addr, port)
      @addr = addr
      @port = port
    end
    def Address.parse(str)
      addr, port = str.split(':')
      return self.new(addr, port.to_i)
    end
    def to_a
      [@addr, @port]
    end
    def ==(other)
      other.is_a?(self.class) and
        (other.addr == @addr) and
        (other.port == @port)
    end
    def hash
      @addr.hash ^ @port.hash
    end
  end

  class Queue
    # TODO: implement ringbuffer
    def initialize
      @data = []
    end
    def size
      @data.size
    end
    def empty?
      @data.empty?
    end
    def enqueue(item)
      @data.push(item)
    end
    def dequeue
      @data.delete_at(0)
    end
    def peek
      @data[0]
    end
  end

  module Logger
    def log(fmt, *args)
      if $log
        $log.send(:printf, fmt, *args)
      end
    end
  end

  class ConnectionStats
    def initialize
      @events = {}
    end
    def log_event(tag, incr=1)
      if @events.has_key?(tag)
        @events[tag] += incr
      else
        @events[tag] = incr
      end
    end
    def each_with_index
      @events.each_with_index { |k,v| yield k, v }
    end
  end

  module ConnectionSocket
    attr_accessor :host_id, :stats
    def init_connection_socket
      @stats = ConnectionStats.new
    end
    def error(code)
      begin
        send_osc(OSC::Msg['/error', code].encode)
      rescue
        p $!
      end
    end
  end

  class Server
    include Logger
    def initialize(addr, password=nil)
      @socket = TCPServer.new(*addr)
      @ios = []
      @clients = {}
      @password = password
      @stats = ConnectionStats.new
      update_rios
    end
    protected
    def update_rios
      @rios = [@socket] + @ios
    end
    def check_password(password)
      @password.nil? or (password == @password)
    end
    def log_event(tag, incr=1)
      @stats.log_event(tag, incr)
    end
    def add_client(io)
      io.extend(ConnectionSocket).init_connection_socket
      self.log("add %s:%d\n", io.peeraddr[2], io.peeraddr[1])
      self.log_event('co')
      @ios.push(io)
      update_rios
    end
    def register_client(io, id, password)
      if check_password(password)
        if id == SERVER_ID
          io.error(ERROR_INVALID_ID)
          remove_client(io)
        elsif @clients.has_key?(id)
          io.error(ERROR_DUPLICATE_ID)
          remove_client(io)
        else
          self.log("register %s:%d\n", io.peeraddr[2], io.peeraddr[1])
          io.host_id = id
          @clients[io.host_id] = io
        end
      else
        self.log("invalid login %s:%d\n", io.peeraddr[2], io.peeraddr[1])
        io.error(ERROR_INVALID_LOGIN)
        self.log_event('laf')
        remove_client(io)
      end
    end
    def remove_client(io)
      log("remove %s:%d\n", io.peeraddr[2], io.peeraddr[1])
      io.close
      @ios.delete(io)
      if id = @clients.index(io)
        @clients.delete(id)
      end
      update_rios
    end
    def relay_packet(dst_id, src_io, pkt)
      if dst_io = @clients[dst_id]
        data = OSC::Msg['/osc', src_io.host_id, pkt].encode
        dst_io.send_osc(data)
        bytes = data.size
        src_io.stats.log_event('ps')
        src_io.stats.log_event('bs', bytes)
        dst_io.stats.log_event('pr')
        dst_io.stats.log_event('br', bytes)
      end
    end
    public
    def run
      while true
        rios, _ = IO.select(@rios, nil, nil, 1)
        next unless rios
        client = nil
        packet = nil
        rios.each { |io|
          if io === @socket
            add_client(@socket.accept)
          else
            data = io.recv_osc(MAX_PACKET_SIZE)
            if data.empty?
              remove_client(io)
            else
              begin
                OSC::Packet.decode(data).each_msg { |msg|
                  cmd = msg.addr
                  if io.host_id
                    if cmd == '/osc'
                      relay_packet(msg[0], io, msg[1])
                    elsif cmd == '/stats'
                      # send stats
                      bdl = OSC::Bundle.new(0)
                      msg = OSC::Msg['/stats', SERVER_ID]
                      @stats.each_with_index { |k,v| msg << k << v }
                      bdl << msg
                      @ios.each { |x|
                        msg = OSC::Msg['/stats', x.host_id]
                        x.stats.each_with_index { |k,v| msg << k << v }
                        bdl << msg
                      }
                      io.send_osc(bdl.encode)
                    end
                  else
                    if cmd == '/hi'
                      register_client(io, msg[0], msg[1])
                    else
                      remove_client(io)
                    end
                  end
                }
              rescue OSC::Error
                # we want valid OSC packets
                remove_client(io)
              end
            end
          end
        }
      end
    end
  end

  module RelaySocket
    attr_accessor :host_id
  end

  class Relay
    include Logger
    # TODO: send stats to client
    #       - avg. roundtrip delay
    #       - network 'quality'
    #       - number of bytes sent/recv'd
    #       catch send/recv errors and reconnect to server
    class Options
      attr_accessor :server_addr, :listen_addr, :host_id, :password, :peers
      def initialize
        @server_addr = Address.new('localhost', 7878)
        @listen_addr = Address.new('localhost', 7979)
        @host_id = "blup"
        @password = nil
        @peers = []
      end
    end
    def initialize(opts)
      @server_addr = opts.server_addr
      @client = nil
      @listener = UDPSocket.new
      @listener.bind(*opts.listen_addr)
      @host_id = opts.host_id
      @password = opts.password
      @relays = {}
      opts.peers.each { |name|
        io = UDPSocket.new.extend(RelaySocket)
        io.bind('localhost', 0)
        io.host_id = name
        @relays[io.host_id] = io
      }
      @queue = Queue.new
      @stats = {}
    end
    def connected?
      !@server.nil?
    end
    def connect
      disconnect
      @server = TCPSocket.new(*@server_addr)
      @server.send_osc(OSC::Msg['/hi', @host_id, @password].encode)
      @rios = [@server, @listener] + @relays.values
    end
    def disconnect
      if connected?
        @server.close
        @server = nil
      end
    end
    def ensure_connection
      unless connected?
        $stdout.printf("connecting ... ")
        $stdout.flush
        until connected?
          begin
            connect
            $stdout.printf("done.\n")
          rescue
            sleep(2)
          end
        end
      end
    end
    def handle_listener(io)
      begin
        data, src = io.recvfrom(MAX_PACKET_SIZE)
        OSC::Packet.decode(data).each_msg { |msg|
          if msg.addr == '/notify'
            @client = Address.new(src[3], src[1])
            self.log("notify %s:%d\n", @client.addr, @client.port)
            msg = OSC::Msg['/peers']
            @relays.values.each { |relay|
              msg << relay.host_id << relay.addr[3] << relay.addr[1]
            }
            io.send(msg.encode, 0, *@client)
          end
        }
      rescue
        p $!
      end
    end
    def handle_server(io)
      # unwrap server message
      begin
        data = io.recv_osc(MAX_PACKET_SIZE)
        if data.empty?
          disconnect
          throw :disconnect
        end
        OSC::Packet.decode(data).each_msg { |msg|
          if msg.addr == '/osc'
            if @client and (relay = @relays[msg[0]])
              relay.send(msg[1].data, 0, *@client)
            end
          elsif msg.addr == '/stats'
            # store stats
          elsif msg.addr == '/error'
            self.log("server error: %s\n",
                     ERROR_STRINGS[msg[0]] || "unknown error")
            exit(1)
          end
        }
      rescue
        p $!
      end
    end
    def handle_relay(io)
      # wrap client message
      begin
        data = io.recv(MAX_PACKET_SIZE)
        @queue.enqueue(OSC::Msg['/osc', io.host_id, OSC::Blob.new(data)].encode)
      rescue
        p $!
      end
    end
    def run
      while true
        ensure_connection
        rios, _ = IO.select(@rios, nil, nil, 1)
        next unless rios
        catch (:disconnect) {
          rios.each { |io|
            if io === @listener
              handle_listener(io)
            elsif io === @server
              handle_server(io)
            else
              handle_relay(io)
            end
          }
          until @queue.empty?
            begin
              pkt = @queue.peek
              @server.send_osc(pkt)
              @queue.dequeue
            rescue
              disconnect
              throw :disconnect
            end
          end
        }
      end
    end
  end
  class TestClient
    def initialize(name, relay_addr)
      @name = "/" + name
      @relay_addr = relay_addr
      @socket = UDPSocket.new
      @socket.send(OSC::Msg['/notify'].encode, 0, *@relay_addr)
      @peers = []
    end
    def make_osc_msg
      msg = OSC::Msg[['/test', '/funk', '/micky', '/minny'].choose]
      rand(10).times {
        msg << ['forever', 12, 3.14, OSC::Blob.new("akljsh\0dkajshd")].choose
      }
      msg
    end
    def make_osc_bundle
      bdl = OSC::Bundle[OSC::Time.now + rand(10)]
      rand(10).times {
        bdl << make_osc_msg
      }
      bdl
    end
    def make_osc_packet
      #self.send([:make_osc_msg, :make_osc_bundle].choose)
      OSC::Msg[@name]
    end
    def run
      while true
        sleep(rand(0) * 2)
        ios = IO.select([@socket, $stdin], nil, nil, nil)[0]
        begin
          ios.each { |io|
            if io === @socket
              data, src = @socket.recvfrom(MAX_PACKET_SIZE)
              src_port = src[1]
              OSC::Packet.decode(data).each_msg { |msg|
                if (src_port == @relay_addr.port) && (msg.addr == '/peers')
                  @peers = []
                  0.step(msg.size-1, 3) { |i|
                    @peers << msg[i+1..i+2]
                  }
                  printf("peers: %s\n", @peers.inspect)
                else
                  printf("%s\n", src.inspect)
                  printf("%s\n", msg.inspect)
                end
              }
            elsif io === $stdin
              return 0 if $stdin.eof?
              $stdin.readline
              pkt = make_osc_packet.encode
              for addr in @peers
                @socket.send(pkt, 0, *addr)
              end
            end
          }
        rescue
          p $!
        end
      end
    end
  end
  def Server.main
    res = Rubicon::Server.new(Address.parse(ARGV[0]), ARGV[1]).run
    exit(res)
  end
  def Relay.main
    opts = Relay::Options.new
    opts.server_addr = Address.parse(ARGV[0])
    opts.listen_addr = Address.parse(ARGV[1])
    opts.host_id = ARGV[2]
    opts.password = ARGV[3]
    opts.peers = ARGV[4..-1]
    res = Rubicon::Relay.new(opts).run
    exit(res)
  end
  def TestClient.main
    name = ARGV[0]
    relay_addr = Address.parse(ARGV[1])
    res = Rubicon::TestClient.new(name, relay_addr).run
    exit(res)
  end
end # module Rubicon
