# Prototype program for sniffing TCP traffic and reassembling simple streams.
# No effort is being made to ensure performance or even correctness under
# adversarial circumstances.

# This is annoying - don't clutter the screen with ruby-pcap C warnings.
err_bak, $stderr = $stderr, File.open('/dev/null', 'a')
require 'pcaplet'
$stderr = err_bak
require 'thread'

require 'helpers.rb'
require 'protos.rb'

# Class which interfaces with ruby pcap
class Sniffer

  # Initialize the traffic sniffing state
  def initialize(event_collector, file, tcp_stream, udp_stream, interface)
    @event_collector = event_collector

    # Register our stream handlers
    @tcp_handler = tcp_stream
    @udp_handler = udp_stream

    # Start Ruby-Pcap
    tcpdump_params = "-s 1600"
    tcpdump_params = "#{tcpdump_params} -i #{interface}" if interface
    @sniffer = Pcaplet.new(tcpdump_params)

    @tcp_traffic = Pcap::Filter.new('tcp', @sniffer.capture)
    @udp_traffic = Pcap::Filter.new('udp', @sniffer.capture)
    @sniffer.add_filter(@tcp_traffic | @udp_traffic)
    @sniffer = Pcap::Capture::open_offline(file) if file
  end  # of initialize

  # Start sniffing packets
  def sniff(queue = false)
    # sniff_queue if queue    # potential optimization, turned off for now
    
    # Now read each packet and process it right away
    @sniffer.each_packet do |pkt|
      @event_collector.pkt_count += 1
      @event_collector.bytes += pkt.caplen
      @event_collector.last_pkt = pkt
      case pkt
      when @tcp_traffic
        @tcp_handler.packet(pkt) if @tcp_handler
      when @udp_traffic
        @udp_handler.packet(pkt) if @udp_handler and pkt.udp?  # INVESTIGATE!
      end
    end  # of each_packet    
  end  # of sniff

  # Version of the sniffer that uses multiple threads, may be better for
  # bursty but otherwise low traffic environments.  
  def sniff_queue
    queue = Queue.new
    
    # Spin up a thread that just queues packets (a buffer, if you will)
    qthread = Thread.new do
      @sniffer.each_packet do |pkt|
        queue.push pkt unless queue.length > 1000
      end
    end  # of qthread
    
    # Now read each of those packets
    loop do
      pkt = queue.pop
      @event_collector.pkt_count += 1
      @event_collector.bytes += pkt.caplen
      case pkt
      when @tcp_traffic
        @tcp_handler.packet(pkt) if @tcp_handler
      when @udp_traffic
        @udp_handler.packet(pkt) if @udp_handler and pkt.udp?  # INVESTIGATE!
      end
    end  # of each_packet
  end  # of sniff_queue

end  # of class Sniffer


# Keep state on a TCP or UDP stream
class StreamState
  include ParserHelpers

  # Initialize some variables
  def initialize(src, dst, proto, sport, dport)
    @app_state = nil
    @src, @dst = src, dst
    @proto = proto
    @sport, @dport = sport, dport
    @last_seen = Time.now
    @layer_4 = nil
    
    # Stream position/reconstruction data
    @bytes_up = 0    # src -> dst (src simply means lower of the two IP addrs)
    @bytes_down = 0  # dst -> src

    # Fragmentation data
    @frags_up = nil
    @frags_down = nil
  end

  # Mark these state attributes readable and some writable
  attr_reader :src, :dst, :proto, :sport, :dport, :last_seen, :layer_4, :pkt
  attr_reader :bytes_up, :bytes_down, :frags_up, :frags_down, :app_state
  attr_writer :bytes_up, :bytes_down, :last_seen, :app_state, :pkt

  # Printable version of the state object
  def to_s
    "#{str_ip(@src)}:#{@sport} - #{str_ip(@dst)}:#{@dport}"
  end
  
  
  ####  TCP STATE ONLY!  ####
  def tcp_init(pkt, event_collector)
    @event_collector = event_collector

    # Determine the direction of the communication
    dir = (pkt.src.to_i < pkt.dst.to_i) ? 0 : 1

    # Have we seen a SYN?  If so, mark who initiated the connection
    @syn_seen = pkt.tcp_syn?
    @ack_seen = pkt.tcp_ack?
    if @syn_seen
      @app_state = { :up => {}, :down => {} }
      if pkt.tcp_ack?
        @syn_seen = dir == 0 ? :dst : :src   # Presume we saw the original SYN
      else
        @syn_seen = dir == 0 ? :src : :dst
      end
    end  # of if @syn_seen

    # Set the src->dst and dst->src sequence numbers
    @seq_up = pkt.tcp_seq
    @seq_down = pkt.tcp_ack
    @seq_up, @seq_down = @seq_down, @seq_up if dir == 1

    # Set the src->dst and dst->src segment buffers
    @segments_up = {}
    @segments_down = {}

    # Connection teardown state
    @fin_up, @fin_down = false, false

    # Report the new stream
    @event_collector.send(:tcp_new_stream) do
      c_ip,   s_ip = str_ip(pkt.src.to_i), str_ip(pkt.dst.to_i)
      c_port, s_port = pkt.sport, pkt.dport
      if pkt.tcp_ack?  # Reverse if we've only seen SYN+ACK
        c_ip, s_ip, c_port, s_port = s_ip, c_ip, s_port, c_port
      end
      if pkt.tcp_rst? or pkt.tcp_fin?
        nil
      else
        { :syn_seen => !!@syn_seen, :client_ip => c_ip,
          :server_ip => s_ip, :client_port => c_port,
          :server_port => s_port, :seq => pkt.tcp_seq, :ack => pkt.tcp_ack
        }
      end
    end 
    @layer_4 = :tcp
  end  # of tcp_init
        
  # Mark the new attributes readable/writable
  attr_reader :syn_seen, :seq_up, :seq_down, :fin_up, :fin_down
  attr_reader :segments_up, :segments_down, :ack_seen
  attr_writer :seq_up, :seq_down, :fin_up, :fin_down, :ack_seen
  ####  END OF TCP ONLY  ####
  
  
  ####  UDP STATE ONLY!  ####
  def udp_init(pkt, event_collector)
    @event_collector = event_collector
    @app_state = { :up => {}, :down => {} }
    @layer_4 = :udp
  end
  ####  END OF UDP ONLY  ####
  
end  # of class StreamState


# Interface which defines layer 3 handling
class IP_Handler

  def initialize(event_collector, protocol_parser)
    @event_collector = event_collector
    @protos = protocol_parser
    @states = {}
  end

  # Handle an incoming packet - should be called by the child classes
  def packet(pkt)
    if ((pkt.ip_mf? or pkt.ip_off > 0 ))
$stderr.puts "*** Fragmented packet #{@event_collector.pkt_count}"
      @event_collector.send(:ip_fragmented_packet) do
        { :src_ip => pkt.src, :dst_ip => pkt.dst, :ip_id => pkt.ip_id,
          :ip_proto => pkt.ip_proto, :ip_off => pkt.ip_off,
          :ip_body => pkt.ip_data
        }
      end
    end
  end

  # Identify if this is a new stream or part of one that exists
  def identify_state(pkt, type, make_state = true)
    # Create the id tuple (assumes TCP or UDP currently)
    s_ip, d_ip, sport, dport = pkt.src.to_i, pkt.dst.to_i, pkt.sport, pkt.dport

    # Make sure the same state is identified regarless of direction
    if s_ip > d_ip
      s_ip, d_ip, sport, dport = d_ip, s_ip, dport, sport
    end
    id = [ s_ip, d_ip, type, sport, dport ]

    # Existing state?
    state = @states[id]
    if state
      state.last_seen = pkt.time
      state.pkt = pkt
    end
    return state if state

    # New state
    state = StreamState.new(*id)
    @states[id] = state if make_state
#$stderr.print "States: #{@states.length}  " if make_state
    state.last_seen = pkt.time
    state.pkt = pkt
    state
  end

  # Delete an existing state
  def delete_state(state)
    @states.reject! { |_,v| v == state }
#$stderr.print "States: #{@states.length}  "
  end

end  # of class IP_Handler


# Interface which defines layer 4 handling for UDP only
class UDP_Handler < IP_Handler

  def initialize(event_collector, protocol_parser)
    super(event_collector, protocol_parser)
  end

  # Receive an incoming packet.  Return true if parsed, false if not.
  def packet(pkt)
    super(pkt)
    
    # Only process packets with length right now
    return nil unless pkt.udp_data.length > 0
    
    # Determine the packet's direction (up == src -> dst)
    dir = pkt.src.to_i < pkt.dst.to_i ? :up : :down

    # First, identify if this is a new stream or part of one on which we are
    # already keeping state.
    state = identify_state(pkt, :udp, false)
    state.udp_init(pkt, @event_collector) unless state.layer_4
    @protos.parse(pkt.udp_data, state, dir)
  end  # of packet()
end  # of class UDP_Handler


# Interface which defines layer 4 handling for TCP only
class TCP_Handler < IP_Handler
  FORWARD_WINDOW = 65536
  
  def initialize(event_collector, protocol_parser)
    super(event_collector, protocol_parser)
    @next_prune = 0
  end

  # Receive an incoming packet.  Return true if parsed, false if not.
  def packet(pkt)
    super(pkt)
    ret = nil

    # Let's ignore (for now) packets that are simply ACKs and nothing else
    return nil unless pkt.tcp_syn? or pkt.tcp_fin? or pkt.tcp_rst? or
                      pkt.tcp_data_len > 0
                      
    # Should we be raising a STREAM event?
    if pkt.tcp_data_len > 0 and @event_collector.stream_capture
      @event_collector.stream_capture.each do |sc|
        if (sc[0].nil? or sc[0] == pkt.src.to_i) and   # source IP
           (sc[2].nil? or sc[2] == pkt.dst.to_i) and   # destination IP
           (sc[1].nil? or sc[1] == pkt.sport) and      # source port
           (sc[3].nil? or sc[3] == pkt.dport)          # destination port
          @event_collector.send(sc[4]) do
            state = identify_state(pkt, :tcp, false)
            { :content => pkt.tcp_data, :syn_seen => !!state.syn_seen,
              :src_ip => @protos.str_ip(pkt.src.to_i),
              :dst_ip => @protos.str_ip(pkt.dst.to_i), :src_port => pkt.sport,
              :dst_port => pkt.dport }
          end
        end  # of if match
      end  # of each stream_capture
    end  # of if stream event

    # Determine the packet's direction (up == src -> dst)
    dir = pkt.src.to_i < pkt.dst.to_i ? :up : :down

    # First, identify if this is a new stream or part of one on which we are
    # already keeping state.
    make_state = !(pkt.tcp_fin? or pkt.tcp_rst?)
    state = identify_state(pkt, :tcp, make_state)
    state.ack_seen = pkt.tcp_ack? unless pkt.tcp_rst?
    
    # Check to see if we need to prune some state objects
    if pkt.time.to_i > @next_prune
      @next_prune = pkt.time.to_i + 60   # one minute prune interval
      syn_timeout    = pkt.time - @event_collector.syn_timeout_delay
      stream_timeout = pkt.time - @event_collector.stream_timeout_delay
      @states.each do |_,chk|
        if chk.last_seen < syn_timeout
          # Is this state only a syn so far?
          if not chk.ack_seen
            @event_collector.send(:tcp_connect_failed) do
              { :timeout => true, :src_ip => @protos.str_ip(chk.src.to_i),
                :dst_ip => @protos.str_ip(chk.dst.to_i),
                :src_port => chk.sport, :dst_port => chk.dport, :rst => false }
            end
            delete_state(chk)
 
          # Okay, there's been some traffic.  Has a full timeout occured?
          elsif chk.last_seen < stream_timeout
            @event_collector.send(:tcp_stream_end) do
              { :syn_seen => !!chk.syn_seen, :timeout => true,
                :src_ip => @protos.str_ip(chk.src.to_i),
                :dst_ip => @protos.str_ip(chk.dst.to_i), :rst => false,
                :dst_port => chk.dport, :src_port => chk.sport, :sync => false,
                :fin => false }
            end
            delete_state(chk)
          end  # of if stream_timeout
        end  # of syn_timeout
      end
    end

    # Is this state brand new?  If so, add some TCP-specific information
    state.tcp_init(pkt, @event_collector) unless state.layer_4

    # Let's make sure the sequence numbers are what we expect
    ret = validate_sequence_numbers(pkt, state, dir) if state.app_state
    return nil unless ret

    # If this is a connection we've seen in its entirety, hand it up to
    # the next stage - the protocol parser (layer 7)
    if state.app_state and pkt.tcp_data and pkt.tcp_data.length > 0
      @protos.parse(pkt.tcp_data, state, dir)
    end

    # Is this a FIN or a RST?  Should we close out this state?
    if pkt.tcp_fin?
      state.fin_up   = true if dir == :up
      state.fin_down = true if dir == :down
      @protos.conclude(state, dir)  # Signal the end of this direction
    end
    if pkt.tcp_rst? or (state.fin_up and state.fin_down)
      if not state.ack_seen  # Explicit connection rejection
        @event_collector.send(:tcp_connect_failed) do
          { :timeout => false, :src_ip => @protos.str_ip(pkt.dst.to_i),
            :dst_ip => @protos.str_ip(pkt.src.to_i),
            :src_port => pkt.dport, :dst_port => pkt.sport, :rst => true }
        end
      else  # regular connection termination
        @event_collector.send(:tcp_stream_end) do
          { :syn_seen => !!state.syn_seen,
            :src_ip => @protos.str_ip(pkt.src.to_i),
            :dst_ip => @protos.str_ip(pkt.dst.to_i), :src_port => pkt.sport,
            :dst_port => pkt.dport, :rst => pkt.tcp_rst?, :sync => false,
            :fin => (state.fin_up and state.fin_down), :timeout => false }
        end
        @protos.conclude(state, :up)    # Signal the end of the stream in
        @protos.conclude(state, :down)  # both directions.
      end
      delete_state(state)
    end

    # Finally, if we have a queued packet to inject, inject it now.  This must
    # be done last!
    packet(ret) if ret.class <= ::Pcap::TCPPacket
    true
  end  # of packet()


  # If the sequence number is valid, update the stream attributes.  If not,
  # perform the appropriate response but don't update the stream.  Return true
  # if valid and should continue parsing, false if it shouldn't, and a pkt
  # if there is a queued next packet that needs to be injected into the stream.
  def validate_sequence_numbers(pkt, state, dir)
    expected_seq = dir == :up ? state.seq_up : state.seq_down

    # If we don't have an expected sequence number yet, set one
    expected_seq = pkt.tcp_seq if expected_seq == 0 

    # If we did not expect this sequence number, handle dissonance
    if pkt.tcp_seq != expected_seq
      return nil if pkt.tcp_seq < expected_seq  # OS would ignore this packet

      # The sequence number is high - save it for later?
      
      if pkt.tcp_seq - expected_seq < FORWARD_WINDOW
        segments = dir == :up ? state.segments_up : state.segments_down
        segments[pkt.tcp_seq] = pkt
      else  # This packet is too far in advance, we're aborting on this steram
        @event_collector.send(:tcp_stream_end) do
          { :syn_seen => !!state.syn_seen,
            :src_ip => @protos.str_ip(pkt.src.to_i),
            :dst_ip => @protos.str_ip(pkt.dst.to_i), :src_port => pkt.sport,
            :dst_port => pkt.dport, :rst => false,
            :fin => false, :sync => true, :timeout => false }
        end
        @protos.conclude(state, :up)   # Kill the stream in both directions
        @protos.conclude(state, :down)
        state.app_state = nil  # not parsing anymore
        #delete_state(state)   # don't delete the state, FIN/RST will do it.
      end
      return nil  # in either case, we don't process the packet right now
    
    # Sequence number was what we expected, this is part of our stream
    else
      # If this was a SYN packet, increase next expected sequence number by 1
      # as specified by the TCP RFC.
      expected_seq += 1 if pkt.tcp_syn?

      # Adjust our next expected sequence number
      if dir == :up
        state.seq_up = (expected_seq + pkt.tcp_data_len) % 4294967296
      else
        state.seq_down = (expected_seq + pkt.tcp_data_len) % 4294967296
      end

      # Do we have a queued packet that we received out of order?
      segments = dir == :up ? state.segments_up : state.segments_down
      if segments.length > 0
        queued_pkt = segments[expected_seq]
        segments.reject! { |k,_| k <= expected_seq }  # delete all passed segs
        if queued_pkt
          return queued_pkt 
        end
      end  # of if segments.length > 0
    end
    true
  end  # of validate_sequence_number

end  # of class TCP_Handler
