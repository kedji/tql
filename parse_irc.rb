class Protos

  # Handle the client-to-server stream of IRC, keep state in req.  This parser
  # uses the same state object and the same parser (weird, eh?).
  def parse_irc_traffic(data, state, dir)
    return nil unless data
    res = req = state.app_state[:req_struct]
    dir = state.app_state[dir][:type]
    pos = 0

    # Check our state initialization condition
    if not req
      req = state.app_state[:req_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :nick, :server, :username,
        :mode, :unused, :real_name, :last_dir, :state_mux
      ).new
      req.state_mux = [ nil, nil, nil, nil ]
    
    # Check our state multiplexing condition
    elsif dir != req.last_dir
      req.last_dir = dir
      req.state_mux, req.state, req.buff, req.maxlen, req.terminator =
        [req.state, req.buff, req.maxlen, req.terminator], *(req.state_mux)
    end  # of state initialization/multiplexing

    # Check it again because of the multiplexor
    unless req.state
      req.last_dir = dir
      req.state = :get_line
      _prepare_to_copy(req, 2048, "\n")
    end

    while pos < data.length
      case req.state

        # Everything in IRC is line-delimited, which makes parsing pretty easy
        when :get_line
          pos, ret = _find_terminator(req, data, pos)

          # Check our overflow condition
          unless ret
            # Thow an event to indicate this condition
            @event_collector.send(:irc_long_line) do
              { :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport],
                :nick => req.nick, :server => req.server, :dir => dir,
                :line => req.buff }
            end
            req.buff = ''
            req.state = :skip_until_newline
          else
            return true if ret == true  # More data to come, but not now
            _parse_irc_line(state, dir, req, ret)
            req.buff = ''
          end

        # If we've encountered a really long line, just spin until we see "\n"
        when :skip_until_newline
          if (ret == data.index("\n", pos))
            pos = ret + 1
            req.state = :get_line
          else
            pos = data.length
          end

      end  # of case
    end  # while pos < data.length
    true
  end  # of parse_irc_traffic

  # Parse all lines with this method, server or client.
  def _parse_irc_line(state, dir, req, line)
    cmd = ''
    line[-1, 1] = '' if line[-1, 1] == "\r"  # strip if necessary

    # Throw the generic IRC line event
    @event_collector.send(:irc_line) do
      { :server_ip => str_ip(state.app_state[:dst]),
        :client_ip => str_ip(state.app_state[:src]),
        :server_port => state.app_state[:dport],
        :client_port => state.app_state[:sport], :line => req.buff,
        :nick => req.nick, :server => req.server, :dir => dir }
    end

    # First let's get the "command" if there is one
    cpos = line.index(' ')
    cmd = line[0, cpos] if cpos
    
    # Commands in IRC put the "verb" up front
    if cmd.upcase == cmd
      case cmd
        # User is initiating login.  More data to come soon.
        when 'NICK'
          req.nick = line.split.last

        # User is providing subsequent login data.  Let's take a peek
        when 'USER'
          line = line.split
          req.username  = line[1] 
          req.mode      = line[2]       # Mode is used for arbitrary data
          req.unused    = line[3]       # So does the "unused" field
          req.real_name = (line[4..-1] || []).join(' ').sub(':', '')

          # Send in a login event
          @event_collector.send(:irc_login) do
            { :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport],
              :nick => req.nick, :server => req.server,
              :username => req.username, :mode => req.mode, :dir => dir,
              :real_name => req.real_name, :unused => req.unused }
          end

        # Better indicator of channel joining than "join"
        when 'MODE'
          if line[cpos+1,1] == '#'   # We're joining a channel
            @event_collector.send(:irc_channel_join) do
              channel = line.split[1]
              { :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport],
                :nick => req.nick, :server => req.server,
                :channel => channel, :dir => dir }
            end
          end  # of if-channel-join

        # Intercept an outgoing message
        when 'PRIVMSG'
          bpos = line.index(':', cpos)
          return nil unless bpos
          recipient = line[cpos...bpos].strip
          msg = line[bpos+1..-1]
          @event_collector.send(:irc_outgoing_msg) do
            { :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport],
              :nick => req.nick, :server => req.server,
              :recipient => recipient, :body => msg, :dir => dir }
          end
          @event_collector.send(:protos_chat_message) do
            { :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport], :dir => dir,
              :chat_dir => :outgoing, :recipient => recipient,
              :sender => req.nick, :protocol => :irc, :content => msg }
          end

        # User is leaving a channel
        when 'PART'          
          if line[cpos+1,1] == '#'   # We're leaving a channel
            @event_collector.send(:irc_channel_part) do
              channel = line.split[1]
              { :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport], 
                :nick => req.nick, :server => req.server,
                :channel => channel, :dir => dir }
            end
          end  # of if-channel-part

      end  # of case cmd

    # Notice messages in IRC put the verb in the middle, start with a ':'
    elsif line[0,1] == ':'
      npos = line.index(' ', cpos+1)  # Find the second space
      cmd2 = line[cpos+1...npos]

      # If this is a number, then we can use it to get the server string
      if cmd2 =~ /^[0-9]{3}$/
        req.server ||= cmd.sub(':', '')

      # If we have a recognized, all-caps word then it's probably a verb!
      elsif cmd2.upcase == cmd2
        case cmd2

          # Someone is sending us (our our channel) a message
          when 'PRIVMSG'
            bpos = line.index(':', npos)
            return nil unless bpos
            recipient = line[npos...bpos].strip
            msg = line[bpos+1..-1]
            return nil if (msg[0] || 0) < 9
            sender = cmd.sub(':', '').split('!')
            @event_collector.send(:irc_incoming_msg) do
              { :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport],
                :nick => req.nick, :server => req.server,
                :recipient => recipient, :body => msg, :dir => dir,
                :sender => sender[0], :sender_location => sender[1] }
            end
            @event_collector.send(:protos_chat_message) do
              unless recipient == req.nick
                recipient = "#{recipient} (#{req.nick})"
              end
              { :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport], :dir => dir,
                :chat_dir => :incoming, :recipient => recipient,
                :sender => sender[0], :protocol => :irc, :content => msg }
            end

        end  # of case cmd2
      end  # of type-of-server-message

    # We don't understand this message.  What the hell is it?
    else 

    end  # of line type
  end  # of _parse_irc_line

end  # of Protos
