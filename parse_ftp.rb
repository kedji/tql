class Protos

  def parse_ftp_client(data, state, dir)
    return nil unless data
    req = state.app_state[:req_struct]
    res = state.app_state[:resp_struct]
    pos = 0

    # Check the initialization condition
    unless req
      req = state.app_state[:req_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :user, :last_cmd, :fname,
        :endpoint, :password
      ).new
      req.state = :main
      _prepare_to_copy(req, 1026, "\n")
    end 
        
    while pos < data.length
      case req.state

        when :main
          pos, ret = _find_terminator(req, data, pos)
          return true if ret == true   # more data to come, but not now

          # Throw an event and re-sync if the line is too long
          unless ret
            @event_collector.send(:ftp_long_line) do
              cmd = req.buff.split.first
              cmd = nil unless cmd.length < 11
              { :line => req.buff, :user => req.user, :command => cmd,
                :dir => state.app_state[dir][:type],
                :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport]
              }
            end
            req.state = :sync
          else
            # We have an FTP client line, let's parse it.
            req.buff = ''
            params = ret.split
            cmd = (params.shift || '').upcase
            # We have an identifiable command
            req.last_cmd = cmd
            cmd = "RETR" if cmd == "LIST" or cmd == "STOR" # same thing
            case cmd
              when 'USER'
                req.user = params.first

              when 'PASS'
                if params.first
                  req.password = params.first
                  @event_collector.send(:protos_plaintext_password) do
                    { :password => params.first, :user => req.user,
                      :protocol => :ftp,
                      :dir => state.app_state[dir][:type],
                      :server_ip => str_ip(state.app_state[:dst]),
                      :client_ip => str_ip(state.app_state[:src]),
                      :server_port => state.app_state[:dport],
                      :client_port => state.app_state[:sport]
                    }
                  end
                end  # if password was supplied

              # This state sets the endpoint for an 'active' transmission.  It
              # follows the same parser semantics as a 'passive' transfer, but
              # the server sets that with PASV.
              when 'PORT'
                req.endpoint = _ftp_endpoint(params.first, :ftp_port)
                
              when 'RETR'
                req.fname = params.first
                file_endpoints = (global_state[:file_endpoints] ||= [])
          
                # First delete all the old endpoints just in case 
                file_endpoints.reject! { |v| state.last_seen - v[3] > 3600 }
                
                # Now add the new endpoint if it exists
                # Format: [ dst_ip, dst_port, proto, time, filename ]
                if req.endpoint
                  endpoint = req.endpoint.dup
                  endpoint[2] = :ftp_list if req.last_cmd == "LIST"
                  endpoint[2] = :ftp_stor if req.last_cmd == "STOR"
                  endpoint << state.last_seen
                  endpoint << req.fname
                  file_endpoints << endpoint
                end
            end  # of case cmd
          end  # of do we have a line to parse

        when :sync
          i = data.index("\n", pos)
          if i
            pos += i + 1
            req.state = :main
            req.buff = ''
          else
            pos = data.length
          end

      end  # of case state
    end  # of while data
    true            
   end  # of parse_ftp_client
  
  def parse_ftp_server(data, state, dir)
    return nil unless data
    req = state.app_state[:req_struct]
    res = state.app_state[:resp_struct]
    pos = 0
  
    # Check the initialization condition
    unless res
      res = state.app_state[:resp_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :code, :login
      ).new
      res.login = false
      res.state = :main
      _prepare_to_copy(res, 1026, "\n")
    end

    while pos < data.length
      case res.state

        when :main
          pos, ret = _find_terminator(res, data, pos)
          return true if ret == true   # more data to come, but not now

          # Throw an event and re-sync if the line is too long
          unless ret
            @event_collector.send(:ftp_long_line) do
              cmd = res.buff.split.first.to_i
              { :line => req.buff, :user => (req ? req.user : nil),
                :dir => state.app_state[dir][:type], :command => cmd,
                :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport]
              }
            end
            res.state = :sync
          else
            # We have an FTP server line, let's parse it.
            res.buff = ''
            params = ret.split
            cmd = params.shift.to_i
            case cmd

              # User is logging in successfully
              when 230
                user = (req.user rescue nil)
                if user and user != 'anonymous' and not res.login
                  @event_collector.send(:ftp_login) do
                    { :password => (req.password rescue nil), :user => user,
                      :dir => state.app_state[dir][:type],
                      :server_ip => str_ip(state.app_state[:dst]),
                      :client_ip => str_ip(state.app_state[:src]),
                      :server_port => state.app_state[:dport],
                      :client_port => state.app_state[:sport],
                      :success => true
                    }
                  end 
                end  # of if user
                res.login = true

              # User is trying to log in and is failing
              when 221
                user = (req.user rescue nil)
                if user and user != 'anonymous' and not res.login
                  @event_collector.send(:ftp_login) do
                    { :password => (req.password rescue nil), :user => user,
                      :dir => state.app_state[dir][:type],
                      :server_ip => str_ip(state.app_state[:dst]),
                      :client_ip => str_ip(state.app_state[:src]),
                      :server_port => state.app_state[:dport],
                      :client_port => state.app_state[:sport],
                      :success => false
                    }
                  end 
                end  # of if user

              # Entering passive mode
              when 227
                req.endpoint = _ftp_endpoint(params.last, :ftp_pasv) if req
                
            end  # of case cmd
          end  # of do we have a line

      end  # of case state
    end  # of while data
    true
  end  # of parse_ftp_server
  
  # Parse FTP's goofy IP/port 6-tuple, return as an array
  def _ftp_endpoint(str, *opts)
    return nil unless str
    tuple = str.sub('(', '').gsub(',', ' ').split.collect { |x| x.to_i }
    return nil unless tuple.length == 6
    ip = (tuple[0] << 24) + (tuple[1] << 16) + (tuple[2] << 8) + tuple[3]
    port = (tuple[4] << 8) + tuple[5]
    [ ip, port, *opts ]
  end  # of _ftp_endpoint
  
end  # of class Protos
