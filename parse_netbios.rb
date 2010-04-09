class Protos

  # Netbios traffic can be sent over UDP or TCP.  Keep this in mind.
  def parse_netbios(data, state, dir)
    return nil unless data
    req = state.app_state[:req_struct]
    res = state.app_state[:resp_struct]
    pos = 0
    
    # Hand off to the client or server parser as needed.
    dir = state.app_state[dir][:type]
    obj = (dir == :client ? req : res)

    # Check our initialization condition
    unless obj
      obj = Struct.new(
        :state, :buff, :maxlen, :terminator, :tcp, :msg_type, :remaining,
        :src_name, :dst_name
      ).new
      obj.tcp = (state.layer_4 == :tcp)
raise "Netbios over TCP" if obj.tcp
      obj.state = :get_header
      _prepare_to_copy(obj, 14)
      state.app_state[:resp_struct] = obj if dir == :server
      state.app_state[:req_struct] = obj if dir == :client
    end

    while pos < data.length
      case obj.state
        when :get_header
          pos, ret = _copy_bytes(obj, data, pos)
          return obj.tcp if ret == true
          obj.msg_type = mt = ret[0]
          obj.remaining = len = _big_endian(ret[10,2])

          # Message type: DIRECT_UNIQUE, DIRECT_GROUP, BROADCAST
          if mt >= 0x10 and mt <= 0x12
            raise "Netbios name datagram too short (#{len})" unless len >= 68
            _prepare_to_copy(obj, 257, "\x00")
            obj.state = :get_source_name

          # Message type: ERROR
          elsif mt == 0x13
raise "Netbios Error Datagram: <#{ret}>"

          # Message type: QUERY, POSITIVE_QUERY, NEGATIVE_QUERY
          else
            raise "Netbios query datagram too short (#{len})" unless len >= 34
            _prepare_to_copy(obj, 257, "\x00")
            obj.state = :get_destination_name
          end

        when :get_source_name
          pos, ret = _find_terminator(obj, data, pos)
          return obj.tcp if ret == true
          raise "Netbios source name overflow" unless ret

          # Grab the source name and move on to the destination (if room)
          obj.remaining -= (ret.length + 1)
          obj.src_name = _decode_nbname(ret)
          raise "Netbios datagram missing dst_name" unless obj.remaining >= 34
          _prepare_to_copy(obj, 257, "\x00")
          obj.state = :get_destination_name

        when :get_destination_name
          pos, ret = _find_terminator(obj, data, pos)
          return obj.tcp if ret == true
          raise "Netbios destination name overflow" unless ret

          obj.remaining -= (ret.length + 1)
          obj.dst_name = _decode_nbname(ret)

          # Parse a payload or go back to the beginning
          if obj.remaining > 0
            _prepare_to_copy(obj, obj.remaining)
            obj.state = :nb_payload
          else
            obj.state = :get_header
            _prepare_to_copy(obj, 14)
          end

        # This is where we hand data up to the higher-level protocols, like
        # SMB.  Right now it's just a stub.
        when :nb_payload
          pos, ret = _skip_bytes(obj, data, pos)
          return obj.tcp if ret
#$stderr.puts "Skipped #{obj.remaining} bytes of payload"

          # Back to the beginning
          obj.state = :get_header
          _prepare_to_copy(obj, 14)
  
      end  # of case
    end  # of while data
    obj.tcp   # true if this is TCP, false if it's UDP
  end  # of parse_netbios

  # Take a netbios encoded name and decode it.  Does anybody else find this
  # algorithm absurd?  I guess it's better than Base64 encoding.
  def _decode_nbname(str)
    str[0] = 0x20 if str[0] = 0x21
    str.strip!
    return nil unless str.length == 32
    ret = ''
    (str.length/2-1).times do |i| i *= 2
      chr = ((str[i] - 0x41) << 4) + str[i+1] - 0x41
      ret << chr.chr
    end
    ret.strip
  end

end  # of class Protos
