class Protos

  def parse_imap_client(data, state, dir)
    return nil unless data
    req = state.app_state[:req_struct]
    res = state.app_state[:resp_struct]
    pos = 0

    # Check the initialization condition
    unless req
      req = state.app_state[:req_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :user, :tag
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
            @event_collector.send(:imap_long_line) do
              tag = req.buff.split.first
              tag = nil unless cmd.length != 4
              { :line => req.buff, :user => req.user, :tag => tag,
                :dir => state.app_state[dir][:type],
                :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport]
              }
            end
            req.state = :sync
          else
            # We have an IMAP client line, let's parse it.
            req.buff = ''
            params = ret.split
            tag = params.shift
            cmd = params.shift
            cmd, tag = tag, nil unless cmd    # for lines like "DONE"
            cmd = nil unless cmd and cmd.length < 11
              
            # Make sure we have a command
            unless cmd
              @event_collector.send(:imap_unreadable_line) do
                { :line => ret, :user => req.user, :tag => tag,
                  :dir => state.app_state[dir][:type],
                  :server_ip => str_ip(state.app_state[:dst]),
                  :client_ip => str_ip(state.app_state[:src]),
                  :server_port => state.app_state[:dport],
                  :client_port => state.app_state[:sport]
                }
              end
              next
            end  # of unless cmd

            # We have an identifiable command
            case cmd.upcase
              when 'LOGIN'
                if params.length > 1
                  req.user = params[0].gsub('"', '')
                  @event_collector.send(:protos_plaintext_password) do
                    { :password => params[1].gsub('"', ''), :user => req.user,
                      :protocol => :imap,
                      :dir => state.app_state[dir][:type],
                      :server_ip => str_ip(state.app_state[:dst]),
                      :client_ip => str_ip(state.app_state[:src]),
                      :server_port => state.app_state[:dport],
                      :client_port => state.app_state[:sport]
                    }
                  end
                end  # of if sufficient login parameters

              # when '' -- no more states to examine yet

            end  # of case
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
  end  # of parse_imap_client


  def parse_imap_server(data, state, dir)
    return nil unless data
    req = state.app_state[:req_struct]
    res = state.app_state[:resp_struct]
    pos = 0

    # Check the initialization condition
    unless res
      res = state.app_state[:resp_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :body, :fparser, :base64,
        :file_data, :in_mime, :boundary, :remaining
      ).new
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
            @event_collector.send(:imap_long_line) do
              { :line => req.buff, :user => (req ? req.user : nil),
                :dir => state.app_state[dir][:type], :tag => nil,
                :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport]
              }
            end
            res.state = :sync
          else
            # We have an IMAP server line, let's parse it.
            res.buff = ''
            params = ret.split
            cmd = params.shift
            cmd = nil unless cmd and cmd.length < 5

            # Make sure we have a command
            unless cmd
              @event_collector.send(:imap_unreadable_line) do
                { :line => ret, :user => (req ? req.user : nil),
                  :dir => state.app_state[dir][:type], :tag => nil,
                  :server_ip => str_ip(state.app_state[:dst]),
                  :client_ip => str_ip(state.app_state[:src]),
                  :server_port => state.app_state[:dport],
                  :client_port => state.app_state[:sport]
                }
              end
              next
            end  # of unless cmd
            
            # Let's see if this a FETCH command with email content
            if cmd == '*' and (params[1] || '').upcase == 'FETCH' and
               (params[-1] || '') =~ /^\{[0-9]{1,9}\}/
              res.remaining = params[-1][1..-2].to_i
              res.state = :msg_body
              res.body = ''
              _prepare_to_copy(res, 8194, "\n")
            end  # of if FETCH command
          end  # of IMAP server line
          
        when :msg_body
          pos, ret = _find_terminator(res, data, pos)
          return true if ret == true   # more data to come, but not now

          # Whether this is false or a message, we don't care
          ret = res.buff
          _email_body_line(ret, state, res, dir)
          res.remaining = res.remaining - ret.length - 1
          
          # Check our termination condition
          if res.remaining < 2
            res.state = :main
            _prepare_to_copy(res, 1026, "\n")

            # The message is done, raise an IMAP-specific event
            @event_collector.send(:imap_message) do
              { :body => res.body,     ###### Add support for RCPT and FROM
                :size => res.body.length,
                :dir => state.app_state[dir][:type],
                :server_ip => str_ip(state.app_state[:dst]),  
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport]
              } 
            end

            # Now raise the general email-generic event
            @event_collector.send(:email_message) do
              { :body => res.body, :protocol => :pop3, :to => nil,
                :dir => state.app_state[dir][:type], :from => nil,
                :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport],
                :size => res.body.length
              }
            end
          end  # of if email done
          res.buff = ''
            
      end  # of case
    end  # of while data
    true
  end  # of parse_imap_server

end  # of class Protos
