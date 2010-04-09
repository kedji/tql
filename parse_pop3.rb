class Protos

  def parse_pop3_client(data, state, dir)
    return nil unless data
    req = state.app_state[:req_struct]
    res = state.app_state[:resp_struct]
    pos = 0

    # Check the initialization condition
    unless req
      req = state.app_state[:req_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :user, :last_cmd, :retr_num
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
            @event_collector.send(:pop3_long_line) do
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
            # We have a POP3 client line, let's parse it.
            req.buff = ''
            params = ret.split
            cmd = params.shift
            cmd = nil unless cmd and cmd.length < 11
            
            # Make sure we have a command
            unless cmd
              @event_collector.send(:pop3_unreadable_line) do
                { :line => ret, :user => req.user,
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
            req.last_cmd = cmd.upcase
            case cmd.upcase
              when 'USER'
                req.user = params.first

              when 'APOP'
                req.user = params.first

              when 'PASS'
                if params.first
                  @event_collector.send(:protos_plaintext_password) do
                    { :password => params.first, :user => req.user,
                      :protocol => :pop3,
                      :dir => state.app_state[dir][:type],
                      :server_ip => str_ip(state.app_state[:dst]),
                      :client_ip => str_ip(state.app_state[:src]),
                      :server_port => state.app_state[:dport],
                      :client_port => state.app_state[:sport]
                    }
                  end
                end

              when 'RETR'
                req.retr_num = params.first.to_i

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
  end  # of parse_pop3_client


  def parse_pop3_server(data, state, dir)
    return nil unless data
    req = state.app_state[:req_struct]
    res = state.app_state[:resp_struct]
    pos = 0

    # Check the initialization condition
    unless res
      res = state.app_state[:resp_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :body, :fparser, :base64,
        :file_data, :in_mime, :boundary
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
            @event_collector.send(:pop3_long_line) do
              cmd = res.buff.split.first
              cmd = nil unless cmd.length < 11
              { :line => req.buff, :user => (req ? req.user : nil),       
                :command => cmd,
                :dir => state.app_state[dir][:type],
                :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport]
              }
            end
            res.state = :sync
         else
            # We have a POP3 server line, let's parse it.
            res.buff = ''
            params = ret.split
            cmd = params.shift
            cmd = nil unless cmd and cmd.length < 11

            # Make sure we have a command
            unless cmd
              @event_collector.send(:pop3_unreadable_line) do
                { :line => ret, :user => (req ? req.user : nil),
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
              when '+OK'
                # Look for RETR indicators
                if params.length == 2 and params[1] == 'octets'
                  res.state = :msg_body
                  res.body = ''
                  _prepare_to_copy(res, 8194, "\n")
                end

            end  # of case
          end  # of do we have a line to parse

        # Get the message body
        when :msg_body
          pos, ret = _find_terminator(res, data, pos)
          return true if ret == true   # more data to come, but not now

          # Whether this is false or a message, we don't care
          ret = res.buff
          if ret.length < 4 and ret.strip == '.'
            res.state = :main
            _prepare_to_copy(res, 1026, "\n")

            # The message is done, raise a POP-specific event
            @event_collector.send(:pop3_message) do
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

          else  # more message data
            # Call the generic email parser for following the body
            _email_body_line(ret, state, res, dir)

          end  # of if '.'
          res.buff = ''

        when :sync
          i = data.index("\n", pos)
          if i
            pos += i + 1
            res.state = :main
            res.buff = ''
          else
            pos = data.length
          end

      end  # of case
    end  # of while
    true
  end  # of parse_pop3_server

end  # of class Protos
