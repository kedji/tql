class Protos

  def parse_smtp_server(data, state, dir)
    return nil unless data
    req = state.app_state[:req_struct]
    res = state.app_state[:resp_struct]
    pos = 0

    # Check the initialization condition
    unless res
      res = state.app_state[:resp_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :domain, :esmtp, :tls
      ).new
      res.esmtp = false
      res.state = :main
      _prepare_to_copy(res, 2048, "\n")
    end
    
    while pos < data.length
    
      # Everything uses this state, it just gets a line then interprets it.
      if res.state == :main
        pos, ret = _find_terminator(res, data, pos)
        return true if ret == true  # more data to come, but not now
        
        # Throw an event and re-sync if line too long
        unless ret
          @event_collector.send(:smtp_long_line) do
            { :line => res.buff, :domain => res.domain, :esmtp => res.esmtp,
              :dir => state.app_state[dir][:type], :code => res.buff.to_i,
              :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport]
            }
          end
          res.state = :sync          
        else
          _smtp_server_line(ret, state, res, req, dir)  # Process the line
          res.buff = ''
          
          # As an optimization, abort parsing if we've encountered TLS
          return false if res.tls and (!req or req.tls)
        end  # of if line
        
      # This state simply skips bytes until it finds a newline (LF)
      elsif res.state == :sync
        i = data.index("\n", pos)
        if i
          pos = i+1
          res.state = :main
          res.buff = ''
        else
          pos = data.length
        end
      end  # of which state
    end  # of while data
    
    true
  end  # of parse_smtp_server
  
  # We've intercepted an SMTP server line.  Break it down
  def _smtp_server_line(line, state, res, req, dir)
    code = line.to_i
    
    # The response code should be between 210 and 559
    unless code >= 210 and code <= 559
      @event_collector.send(:smtp_invalid_response) do
        { :line => line.strip, :domain => res.domain, :esmtp => res.esmtp,
          :code => code, :dir => state.app_state[dir][:type],
          :server_ip => str_ip(state.app_state[:dst]),
          :client_ip => str_ip(state.app_state[:src]),
          :server_port => state.app_state[:dport],
          :client_port => state.app_state[:sport]
        }
      end  
      return nil
    end  # of if invalid response code
    
    # Inspect some response codes we care about.  Don't return yet, we still
    # need to deliver the event.
    case code

      # SMTP Service ready    
      when 220
        res.domain = (line[4..-1] || '').split.first
        res.esmtp = true if line.include?('ESMTP')  # also set by EHLO
        res.tls = true if req and req.tls

      # Requested action taken and completed.
      when 250
        res.tls = true if req and defined?(req.tls) and req.tls
        res.esmtp = true if req and defined?(req.esmtp) and req.esmtp
        
    end  # of case code
    
    # Now send the event just in case the user wants to see it
    @event_collector.send(:smtp_response) do
      { :line => line.strip, :domain => res.domain, :esmtp => res.esmtp,
        :code => code, :dir => state.app_state[dir][:type],
        :server_ip => str_ip(state.app_state[:dst]),
        :client_ip => str_ip(state.app_state[:src]),
        :server_port => state.app_state[:dport],
        :client_port => state.app_state[:sport]
      }
    end      
  end

  def parse_smtp_client(data, state, dir)
    return nil unless data
    req = state.app_state[:req_struct]
    res = state.app_state[:resp_struct]
    pos = 0

    # Check the initialization condition
    unless req
      req = state.app_state[:req_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :hello, :esmtp, :tls, :body,
        :in_msg, :from, :rcpt, :in_mime, :boundary, :fparser, :base64,
        :file_data
      ).new
      req.esmtp = false
      req.state = :main
      _prepare_to_copy(req, 8194, "\n")
    end
    
    while pos < data.length
    
      # Everything uses this state, it just gets a line then interprets it.
      if req.state == :main
        pos, ret = _find_terminator(req, data, pos)
        return true if ret == true  # more data to come, but not now
        
        # Throw an event and re-sync if line too long
        unless ret
          @event_collector.send(:smtp_long_line) do
            { :line => req.buff, :hello => req.hello,
              :esmtp => req.esmtp, :domain => (res.domain rescue nil),
              :dir => state.app_state[dir][:type], :code => nil,
              :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport]
            }
          end
          req.state = :sync
        else
          _smtp_client_line(ret, state, res, req, dir)  # Process the line
          req.buff = ''
          
          # As an optimization, abort parsing if we've encountered TLS
          return false if req.tls and (!res or res.tls)
        end  # of if line
        
      # This state simply skips bytes until it finds a newline (LF)
      elsif req.state == :sync
        i = data.index("\n", pos)
        if i
          pos = i+1
          req.state == :main
          req.buff = ''
        else
          pos = data.length
        end
      end  # of which state
    end  # of while data
    
    true
  end  # of parse_smtp_client
  
  # We've intercepted an SMTP client line.  Break it down
  def _smtp_client_line(line, state, res, req, dir)
  
    # Two different states - in-message, or not-in-message
    if req.in_msg
      if line.length < 4 and line.strip == '.'
        req.in_msg = false
        req.in_mime = false  ### are we sure?
        
        # The message is done, raise an SMTP-specific event
        @event_collector.send(:smtp_message) do
          { :body => req.body, :domain => (res ? res.domain : nil),
            :esmtp => (res ? res.esmtp : nil),
            :from => req.from, :to => req.rcpt,
            :dir => state.app_state[dir][:type],
            :server_ip => str_ip(state.app_state[:dst]),
            :client_ip => str_ip(state.app_state[:src]),
            :server_port => state.app_state[:dport],
            :client_port => state.app_state[:sport],
            :size => req.body.length,
          }        
        end
        
        # Now raise the general email-generic event
        @event_collector.send(:email_message) do
          { :body => req.body, :protocol => :smtp, 
            :from => req.from, :to => req.rcpt,
            :dir => state.app_state[dir][:type],
            :server_ip => str_ip(state.app_state[:dst]),
            :client_ip => str_ip(state.app_state[:src]),
            :server_port => state.app_state[:dport],
            :client_port => state.app_state[:sport],
            :size => req.body.length
          }        
        end
        return nil
      end
      
      # Call the generic email parser for following the body
      _email_body_line(line, state, req, dir)
    
    # Not inside email message body
    else
      cmd = line.split.first
      case cmd.upcase
      
        # Initialization
        when 'EHLO'
          req.hello = (line[5..-1] || '').split.first
          req.esmtp = true
        
        # Initialization, old skool (not esmtp)
        when 'HELO'
          req.hello = (line[5..-1] || '').split.first
          
        # MAIL FROM
        when 'MAIL'
          req.from = (line[10..-1]||'').split.first.gsub('<','').gsub('>','')

        # RCPT TO
        when 'RCPT'
          rcpt = line[8..-1].strip
          rcpt = rcpt.gsub('>', '').gsub('<', '').gsub(',', ' ').split
          req.rcpt = rcpt.select { |x| x.include?('@') }
          
        # Starting the email body
        when 'DATA'
          req.in_msg = true
          req.body = ''
          
        # A TLS conversation has been requested
        when 'STARTTLS'
          req.tls = true

      end if cmd  # of case cmd
    end  # of if inside message
  end  # of _smtp_client_line  

end  # of Protos

