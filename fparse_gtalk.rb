# This is a transitory parser.  At the time of its writing, it detects
# known gmail web chat transmissions, which are delivered as files delivered
# asynchronusly over HTTP (ie, chunked encoding).  The format of these
# messages may change (currently it is \n-delimited JSON).

class FileParser
  def fparse_gtalk(data)
    pos = 0
    
    # Check our initalization condition
    unless @pstate
      @pstate = Struct.new(:buff, :maxlen, :terminator).new
      _prepare_to_copy(@pstate, 4098, "\n")
    end  # of unless @pstate
    
    # For now we're going to cheat and abuse the fact that gtalk appears
    # to use \n to delimit all commands.  If we were being proper, we'd
    # respect nested bracketing.
    while pos < data.length
      pos, ret = _find_terminator(@pstate, data, pos)
      return ret if ret == true or not ret

      # We have a line, let's set up the next state now
      @pstate.buff = ''

      # Check to see if this is a line we can parse
      next unless ret =~ /^[\[,]\[[0-9]{1,6},\[/

      # Get the command number (monotonically increasing)
      i = ret.index(',', 3)
      next unless i
      cmd = ret[2..i].to_i
      self_name = self_email = nil

      # Tokenize the attributes.  This doesn't work for all commands, but it
      # works for the one's we're interested in.
      e = ret.index(/[\[\]\n]/, i+2)
      next unless e
      tokens = ret[i+2...e].split('","')
      tokens[0][0,1]   = '' if tokens[0][0,1]   == '"'
      tokens[-1][-1,1] = '' if tokens[-1][-1,1] == '"'

      # Look for message types we recognize
      case tokens[0].downcase

        # User is logging on, we have to register this state as global since
        # subsequent communications need it but are in their own separate files
        when 'ud'
          next if tokens[1].empty? or not tokens[1].include?('.com')
          gtalks = (global_state[:gtalks] ||= [])
        
          # First delete all the old endpoints just in case (one hour)
          gtalks.reject! { |v| @state.last_seen - v[3] > 3600 }

          # Format of inserted gtalk state:
          # [ client_ip, email, name, last_time ]
          gtalk_state = gtalks.find { |x| x[0] == @state.app_state[:src] }
          if gtalk_state
            # raise name collision event?
            gtalk_state[3] = @state.last_seen
            gtalk_state[1] = tokens[1]
            gtalk_state[2] = tokens[2]
          else
            gtalks << [ @state.app_state[:src], tokens[1], tokens[2],
                        @state.last_seen ]
          end
          @event_collector.send(:gtalk_login) do
            { :server_ip => str_ip(@state.app_state[:dst]),
              :client_ip => str_ip(@state.app_state[:src]),
              :server_port => @state.app_state[:dport],
              :client_port => @state.app_state[:sport], :dir => @dir,
              :email => tokens[1], :name => tokens[2], :cmd => cmd }
          end

        # Just use this to preserve state
        when 'noop'
          gtalks = (global_state[:gtalks] ||= [])
          gtalk_state = gtalks.find { |x| x[0] == @state.app_state[:src] }
          gtalk_state[3] = @state.last_seen if gtalk_state

        # Message being sent by the local user
        when 'e'
          next if tokens[3].nil? or tokens[1].include?(',')
          gtalks = (global_state[:gtalks] ||= [])
          gtalk_state = gtalks.find { |x| x[0] == @state.app_state[:src] }
          if gtalk_state
            gtalk_state[3] = @state.last_seen
            self_email, self_name = gtalk_state[1], gtalk_state[2]
          end

          # Adjust the email address, it may have junk at the end
          if tokens[1][-3,3] != 'com'
            i = tokens[1].index('.com')
            tokens[1][i+4..-1] = '' if i
          end
          msg = tokens[3].gsub("\\\"", '"')

          # Raise the necessary events
          @event_collector.send(:gtalk_message) do
            { :server_ip => str_ip(@state.app_state[:dst]),
              :client_ip => str_ip(@state.app_state[:src]),
              :server_port => @state.app_state[:dport],
              :client_port => @state.app_state[:sport], :dir => @dir,
              :sender => self_email, :recipient => tokens[1], :msg => msg,
              :cmd => cmd, :chat_dir => :outgoing, :local_name => self_name }
          end
          @event_collector.send(:protos_chat_message) do
            { :server_ip => str_ip(@state.app_state[:dst]),
              :client_ip => str_ip(@state.app_state[:src]),
              :server_port => @state.app_state[:dport],
              :client_port => @state.app_state[:sport], :dir => @dir,
              :chat_dir => :outgoing, :sender => self_email, :content => msg,
              :recipient => tokens[1], :protocol => :gtalk }
          end

        # Message is being sent to the local user
        when 'm'
          next if tokens[4].nil? or tokens[3].downcase != 'active'
          gtalks = (global_state[:gtalks] ||= [])
          gtalk_state = gtalks.find { |x| x[0] == @state.app_state[:src] }
          if gtalk_state
            gtalk_state[3] = @state.last_seen
            self_email, self_name = gtalk_state[1], gtalk_state[2]
          end
          @event_collector.send(:gtalk_message) do
            msg = tokens[4].gsub("\\\"", '"')
            { :server_ip => str_ip(@state.app_state[:dst]),
              :client_ip => str_ip(@state.app_state[:src]),
              :server_port => @state.app_state[:dport],
              :client_port => @state.app_state[:sport], :dir => @dir,
              :recipient => self_email, :sender => tokens[1], :msg => msg,
              :cmd => cmd, :chat_dir => :incoming, :local_name => self_name }
          end
          @event_collector.send(:protos_chat_message) do
            { :server_ip => str_ip(@state.app_state[:dst]),
              :client_ip => str_ip(@state.app_state[:src]),
              :server_port => @state.app_state[:dport],
              :client_port => @state.app_state[:sport], :dir => @dir,
              :chat_dir => :incoming, :recipient => self_email, 
              :sender => tokens[1], :protocol => :gtalk, :content => msg }
          end

      end  # of case tokens[0]
    end  # of while data
    true
  end  # of fparse_gtalk()

  # Take a line and a current position and pop the next element, return
  # element (or nil) and new i.  Exit on nested brackets.
  def _gtalk_pop(ret, i)
    
  end  # of _gtalk_pop
end  # of class FileParser
