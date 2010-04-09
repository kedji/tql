# Since DNS is UDP-based, we can presume that all of the data is contained
# within the 'data' variable.

class Protos

  def parse_dns_client(data, state, dir)
    return nil unless data
    return false unless data.length > 20
    return false unless data[4, 8] == "\x00\x01\x00\x00\x00\x00\x00\x00"

    # We already have all the data, only parse it if we're sending an event
    @event_collector.send(:dns_query) do
      # Do some initial parsing
      trans_id = _big_endian(data[0,2])
      name = _parse_dns_name(data, 12)
      pos = name.length + 14

      # Get the src & dst address/port
      src, dst, sport, dport = state.src, state.dst, state.sport, state.dport
      src, dst, sport, dport = dst, src, dport, sport unless dir == :up

      # Raise the event itself if this looks properly formatted
      if data.length >= pos + 4
        { :query => name, :transaction_id => trans_id,
          :type => _big_endian(data[pos, 2]), :server_port => dport,
          :class => _big_endian(data[pos+2, 2]), :dir => :client,
          :client_port => sport, :server_ip => str_ip(dst),
          :client_ip => str_ip(src)
        }
      else
        false
      end
    end  # of if sending :dns_query
    true
  end  # of parse_dns_client

  def parse_dns_server(data, state, dir)
    return nil unless data
    return false unless data.length > 28
    return false unless data[4, 3] == "\x00\x01\x00"

    # Do some initial parsing
    trans_id = _big_endian(data[0,2])
    name = _parse_dns_name(data, 12)
    pos = name.length + 18     # start of first answer
    return false unless pos + 8 < data.length

    # Get the src & dst address/port
    src, dst, sport, dport = state.src, state.dst, state.sport, state.dport
    src, dst, sport, dport = dst, src, dport, sport unless dir == :down

    # Now parse out the answers, raising an event for each
    while data[pos]
      return false unless data[pos+15]
      type = _big_endian(data[pos+2, 2])
      len = _big_endian(data[pos+10, 2])
      response = data[pos+12, len]

      # Only parse in this detail if we're going to send the event
      @event_collector.send(:dns_response) do
        cid = _big_endian(data[pos+4, 2])
        ttl = _big_endian(data[pos+6, 4])

        # Do some quick translation of the response based on type
        case type
          when 1  # A
            response = str_ip(_big_endian(response))
          when 5   # CNAME
            response = _parse_dns_name(response, 0)
          when 6   # SOA (zone authority, probably not found)
            response = _parse_dns_name(response, 0)  ## NOT EXACTLY RIGHT
          when 12  # PTR
            response = _parse_dns_name(response, 0)
          #### ADD SOME OTHER TYPES ####
        end  # of case

        # Provide the actual event
        { :query => name, :transaction_id => trans_id, :response => response,
          :type => type, :class => cid, :ttl => ttl, :dir => :server,
          :client_port => sport, :server_ip => str_ip(dst),
          :server_port => dport, :client_ip => str_ip(src)
        }
      end
      pos += 12 + len
    end  # of while data[pos]        
    true
  end  # of parse_dns_server

  # Take a name out of a DNS packet (each segment specifies length)
  def _parse_dns_name(data, pos)
    len = data[pos]
    return nil unless len
    name = data[pos+1, len]
    pos += len + 1
    while data[pos]
      len = data[pos]
      break if len == 0 or len > 127
      name << '.'
      name << data[pos+1, len]
      pos += len + 1
    end
    return name
  end  # of _parse_dns_name

end  # of class Protos  
