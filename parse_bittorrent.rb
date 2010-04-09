class Protos

  # It's legitimate to treat the up and down streams as independent but
  # undifferentiated.  So each direction uses the same parser but keeps its
  # own state.  
  def parse_bittorrent(data, state, dir)
    return nil unless data
    dir = state.app_state[dir][:type]
    obj = false
    obj = state.app_state[:req_struct] if dir == :client
    obj = state.app_state[:resp_struct] unless dir == :client
    raise "BitTorrent traffic not client or server" if obj == false
    pos = 0

    # Check our initialization
    unless obj
      obj = Struct.new(
        :state, :buff, :maxlen, :terminator, :protocol, :version, :sha1,
        :peer_id, :msg_type
      ).new
      state.app_state[dir == :client ? :req_struct : :resp_struct] = obj
      obj.state = :protocol_len
#$stderr.puts "NEW STATE OBJECT - #{@event_collector.pkt_count} (#{dir})"
    end
    
    while pos < data.length
      case obj.state

        # This state goes at the top even though it's not first as a subtle
        # optimization.  First state is protocol_len.
        # Optimize this later by skipping messages we don't care about.
        when :message_body
          pos, ret = _copy_bytes(obj, data, pos)
          return true if ret == true
          
          # Raise events based on message contents and type
          if obj.msg_type == 7 and ret[4,4] == "\0\0\0\0" and ret.length > 23
            @event_collector.send(:bittorrent_content_beginning) do
              { :version => obj.version, :dir => dir,
                :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport],
                :peer_id => obj.peer_id, :sha1 => obj.sha1,
                :content_beginning => ret[8, 24]
              }
            end            
          end
          
          # Just get the next message.  So simple.
          _prepare_to_copy(obj, 5)
          obj.state = :message_len
#$stderr.puts "TYPE: #{obj.msg_type}"

        # Use this to skip past messages we don't care about.
        when :message_skip
          rem_data = data.length - pos
          if obj.maxlen >= rem_data
            obj.maxlen -= (data.length - pos)
            return true
          end
          pos += rem_data
          _prepare_to_copy(obj, 5)
          obj.state = :message_len
                    
        # Get the four byte length for each message (and the type code)
        when :message_len
          pos, ret = _copy_bytes(obj, data, pos)
          return true if ret == true
          obj.msg_type = ret[4]
          len = _big_endian(ret[0,4])
#$stderr.puts "MESSAGE LEN/TYPE: #{len}/#{obj.msg_type} (#{@event_collector.pkt_count})"
          raise "BitTorrent message underflow" unless len > 0 or ret[4] == 0
          _prepare_to_copy(obj, len - 1)
          obj.state = :message_skip
          
          # Only go to the message_body state for messages whose bodies we
          # care something about
          obj.state = :message_body if obj.msg_type == 7
          
          # This is a bit strange, sometimes there are zero-length, zero-type
          # headers.  Just skip them.  This takes a tiny bif of finesse
          # since we've already read 5 bytes and the header is only 4.
          if len == 0
#$stderr.puts "ZEROMSG! (#{@event_collector.pkt_count})"
            obj.state = :message_len
            _prepare_to_copy(obj, 5)
            obj.buff = ret[4,1]  # prime the buffer with the byte already read
          end
          
        # Just grabbing a one byte length for the protocol name
        when :protocol_len
#$stderr.puts "PROTO LEN: #{data[pos]}"
          _prepare_to_copy(obj, data[pos])
          obj.state = :get_protocol
          pos += 1
          
        # Get the protocol name (simple, eh?  That's Asperger's!)
        when :get_protocol
          pos, ret = _copy_bytes(obj, data, pos)
          return true if ret == true
          obj.protocol = obj.buff
          _prepare_to_copy(obj, 48)
          obj.state = :get_peer_info
#$stderr.puts "PROTOCOL: #{obj.protocol}"
        
        # Get the SHA1 hash and the peer ID.  Skip the 8 extension bytes.
        when :get_peer_info
          pos, ret = _copy_bytes(obj, data, pos)
          return true if ret == true
          obj.sha1 = "0x" << _hex_value(ret[8,20])
          obj.peer_id = "0x" << _hex_value(ret[28,20])
          _prepare_to_copy(obj, 5)
          obj.state = :message_len
          @event_collector.send(:bittorrent_node) do
            { :version => obj.version, :dir => dir,
              :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport],
              :peer_id => obj.peer_id, :sha1 => obj.sha1 }
          end            
#$stderr.puts "PEER ID: #{obj.peer_id} (#{@event_collector.pkt_count})"
          
      end  # of case
    end  # of while data.length > pos
    true
  end  # of parse_bittorrent

end  # of Protos  
