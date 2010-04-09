# The is just a stub parser for now.  It detects only the present of client/
# server communication, then stops parsing.

class Protos
  
  # It is unknown until we examine 'dir' whether this is client or server
  # traffic.
  def parse_vnc(data, state, dir)
    return nil unless data
    dir = state.app_state[dir][:type]
    if dir == :client
      return _parse_vnc_client(data, state, dir)
    end
    return _parse_vnc_server(data, state, dir)
  end
  
  # Stub parser for now
  def _parse_vnc_client(data, state, dir)
    req = state.app_state[:req_struct]
    pos = 0

    unless req
      req = state.app_state[:req_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :version
      ).new
      _prepare_to_copy(req, 12)
      req.state = :init
    end
    
    while pos < data.length
      case req.state
      
        when :init
          pos, ret = _copy_bytes(req, data, pos)
          return true if ret == true   # more data to come, but not now
          req.version = "#{ret[4,3].to_i}.#{ret[8,3].to_i}"
          
          # For now, just raise an event and return false to stop parsing
          @event_collector.send(:vnc_detected) do
            { :version => req.version, :dir => dir,
              :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport]
            }
          end
          return false     
      end  # of case
    end  # of while data
    true
  end  # of _parse_vnc_client

  # Stub parser for now
  def _parse_vnc_server(data, state, dir)
    res = state.app_state[:resp_struct]
    pos = 0

    unless res
      res = state.app_state[:resp_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :version
      ).new
      _prepare_to_copy(res, 12)
      res.state = :init
    end
    
    while pos < data.length
      case res.state
      
        when :init
          pos, ret = _copy_bytes(res, data, pos)
          return true if ret == true   # more data to come, but not now
          res.version = "#{ret[4,3].to_i}.#{ret[8,3].to_i}"
          
          # For now, just raise an event and return false to stop parsing
          @event_collector.send(:vnc_detected) do
            { :version => res.version, :dir => dir,
              :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport]
            }
          end
          return false     
      end  # of case
    end  # of while data
    true
  end  # of _parse_vnc_server

end  # of class Protos
