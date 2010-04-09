# The is just a stub parser for now.  It detects only the present of client/
# server communication, then stops parsing.

class Protos
  
  # It is unknown until we examine 'dir' whether this is client or server
  # traffic.
  def parse_ssh(data, state, dir)
    return nil unless data
    dir = state.app_state[dir][:type]
    if dir == :client
      return _parse_ssh_client(data, state, dir)
    end
    return _parse_ssh_server(data, state, dir)
  end
  
  # Stub parser for now
  def _parse_ssh_client(data, state, dir)
    req = state.app_state[:req_struct]
    pos = 0

    unless req
      req = state.app_state[:req_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :version
      ).new
      _prepare_to_copy(req, 130, "\n")
      req.state = :init
    end
    
    while pos < data.length
      case req.state
      
        when :init
          pos, ret = _find_terminator(req, data, pos)
          return true if ret == true   # more data to come, but not now
          return false unless ret      # Not SSH, stop parsing
          req.version = ret
          
          # For now, just raise an event and return false to stop parsing
          @event_collector.send(:ssh_detected) do
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
  end  # of _parse_ssh_client

  # Stub parser for now
  def _parse_ssh_server(data, state, dir)
    res = state.app_state[:resp_struct]
    pos = 0

    unless res
      res = state.app_state[:resp_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :version
      ).new
      _prepare_to_copy(res, 130, "\n")
      res.state = :init
    end
    
    while pos < data.length
      case res.state
      
        when :init
          pos, ret = _find_terminator(res, data, pos)
          return true if ret == true   # more data to come, but not now
          return false unless ret      # Not SSH, stop parsing
          res.version = ret
          
          # For now, just raise an event and return false to stop parsing
          @event_collector.send(:ssh_detected) do
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
  end  # of _parse_ssh_server

end  # of class Protos
