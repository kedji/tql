# This is a transitory parser.  At the time of its writing, it detects
# known facebook chat transmissions, which are delivered as files fetched
# synchronusly over HTTP (ie, not chunked-encoding).  The format of these
# messages may change, as well as the transmission mechanism.

class FileParser
  def fparse_facebook(data)
    pos = 0
    
    # Check our initalization condition
    unless @pstate
      @pstate = Struct.new(:state, :buff, :maxlen, :terminator).new
      _prepare_to_copy(@pstate, 80, '[')
      @pstate.state = :find_open_bracket
    end  # of unless @pstate
    
    while pos < data.length
      case @pstate.state
        
        # In this state we're looking for the initial open bracket.  If we
        # don't find it within 80 bytes, we're probably not going to find it
        # and we should give up.
        when :find_open_bracket
          pos, ret = _find_terminator(@pstate, data, pos)
          return true if ret == true   # more data to come, but not now
          return false unless ret      # We didn't find it within 80 bytes
          
          # We have our bracket, let's make sure this is a chat message
          return false unless ret =~ /"t":"msg",/
          _prepare_to_copy(@pstate, 4096, ']')
          @pstate.state = :find_close_bracket
          
        # In this state we look for the close bracket, where all the data
        # we need to display the text is between the two.  There is a known
        # false negative here where the user's message contains ']', but it
        # is ignored now for the sake of efficiency of parsing.
        when :find_close_bracket
          pos, ret = _find_terminator(@pstate, data, pos)
          return true if ret == true   # more data to come, but not now
          return false unless ret      # We didn't find it within 4kb
          
          # Verify this is a chat message type
          return false unless ret =~ /"type":"msg",/
          
          # Start identifying components.  Message first.
          return false unless (s = ret =~ /"text":/)
          return false unless (e = ret.index('","', s+7))
          msg = ret[s+8..e-1]

          # From and To ID's
          return false unless (s = ret =~ /"from":/)
          return false unless (e = ret.index(',', s+7))
          from_id = ret[s+7..e-1].to_i
          return false unless (s = ret =~ /"to":/)
          return false unless (e = ret.index(',', s+5))
          to_id = ret[s+5..e-1].to_i

          # From and To names
          return false unless (s = ret =~ /"from_name":/)
          return false unless (e = ret.index('","', s+13))
          from_name = ret[s+13..e-1]
          return false unless (s = ret =~ /"to_name":/)
          return false unless (e = ret.index('","', s+11))
          to_name = ret[s+11..e-1]
          
          # Finally, raise the event and exit
          @event_collector.send(:facebook_chat) do
            { :server_ip => str_ip(@state.app_state[:dst]),
              :client_ip => str_ip(@state.app_state[:src]),
              :server_port => @state.app_state[:dport],
              :client_port => @state.app_state[:sport], :dir => @dir,
              :msg => msg, :from_id => from_id, :to_id => to_id,
              :from_name => from_name, :to_name => to_name }
          end
          @event_collector.send(:protos_chat_message) do
            { :server_ip => str_ip(@state.app_state[:dst]),
              :client_ip => str_ip(@state.app_state[:src]),
              :server_port => @state.app_state[:dport],
              :client_port => @state.app_state[:sport], :dir => @dir,
              :chat_dir => nil, :recipient => to_name, 
              :sender => from_name, :protocol => :facebook, :content => msg }
          end
          return false
                  
      end  # of case state
    end  # of while data
    true
  end  # of fparse_facebook()
end  # of class FileParser