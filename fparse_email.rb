class FileParser
  
  # Just hand this data, line at a time, off to the _parse_email method
  # used by the protos parser.
  def fparse_email(data)
    pos = 0
    
    # Check our initalization condition
    unless @pstate
      @pstate = Struct.new(:buff, :maxlen, :terminator, :body, :fparser,
                           :base64, :file_data, :in_mime, :boundary).new
      @pstate.body = ''
      _prepare_to_copy(@pstate, 8194, "\n")
    end  # of unless @pstate

    # Grab lines and feed them into the generic email parser
    while pos < data.length
      pos, ret = _find_terminator(@pstate, data, pos)
      return true if ret == true  # more data to come, but not now

      # Whether this is false or a line, we don't care
      ret = @pstate.buff
      @pstate.buff = ''
      _email_body_line(ret, @state, @pstate, @sdir)
    end  # of while data
    true
  end  # of fparse_email


  # We're done reading the email message, raise necessary events
  def conclude_email
    # Raise the general email-generic event
    @event_collector.send(:email_message) do
      { :body => @pstate.body, :protocol => :content, :to => nil,
        :server_ip => str_ip(@state.app_state[:dst]),
        :client_ip => str_ip(@state.app_state[:src]),
        :server_port => @state.app_state[:dport],
        :client_port => @state.app_state[:sport],
        :from => nil, :dir => @dir, :size => @pstate.body.length
      }
    end  
  end  # of conclude_email

end  # of FileParser
