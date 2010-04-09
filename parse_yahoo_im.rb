class Protos

  def parse_yahoo_im(data, state, dir)
    return nil unless data
    req = state.app_state[:req_struct]
    res = state.app_state[:resp_struct]
    pos = 0
    
    # Hand off to the client or server parser as needed.
    dir = state.app_state[dir][:type]
    obj = (dir == :client ? req : res)

    # Check our initialization condition
    unless obj
      obj = Struct.new(
        :state, :buff, :maxlen, :terminator, :service, :version, :user
      ).new
      obj.state = :get_header
      _prepare_to_copy(obj, 20)
      state.app_state[:resp_struct] = obj if dir == :server
      state.app_state[:req_struct] = obj if dir == :client
    end

    while pos < data.length
      case obj.state

        # Find the channel header (always six bytes)
        when :get_header
          pos, ret = _copy_bytes(obj, data, pos)
          return true if ret == true

          # We have our header, let's dissect it
          raise "Yahoo IM traffic out of sync" unless ret[0,4] == 'YMSG'
          
          # Get the version, length, and service
          obj.version = _big_endian(ret[4,2]) unless obj.version
          len = _big_endian(ret[8,2])
          obj.service = _big_endian(ret[10,2])
          
          # Set up the next state
          if len > 0
            _prepare_to_copy(obj, len)
            obj.state = :get_content

            # Skip past states we don't care about
            unless [6, 85, 241].include?(obj.service)
              obj.state = :skip_content 
            end
          else
            _prepare_to_copy(obj, 20)
          end
          
        # Yahoo IM is pretty simple.  Each message is a header (which we
        # already have) and an optional content array.  Here we're just
        # getting, splitting and parsing that array.
        when :get_content
          pos, ret = _copy_bytes(obj, data, pos)
          return true if ret == true

          # Go ahead and set up the next state
          _prepare_to_copy(obj, 20)
          obj.state = :get_header

          # Get a content hash out of this silly flat array
          content, i = {}, nil
          ret.split("\xc0\x80").each do |elm|
            if i
              content[i], i = elm, nil
            else
              i = elm.to_i
            end
          end

          # Parse the service messages we care about
          case obj.service
            when 6   # message
              msg = content[14]
              next unless msg  # What are we doing if there's no message?
              recipient = content[5]
              sender = content[4] || content[1]
              chat_dir = (dir == :client ? :outgoing : :incoming)
              @event_collector.send(:yahoo_im_message) do
                { :server_ip => str_ip(state.app_state[:dst]),
                  :client_ip => str_ip(state.app_state[:src]),
                  :server_port => state.app_state[:dport],
                  :client_port => state.app_state[:sport], :dir => dir,
                  :sender => sender, :recipient => recipient, 
                  :chat_dir => chat_dir, :msg => msg }
              end
              @event_collector.send(:protos_chat_message) do
                { :server_ip => str_ip(state.app_state[:dst]),
                  :client_ip => str_ip(state.app_state[:src]),
                  :server_port => state.app_state[:dport],
                  :client_port => state.app_state[:sport], :dir => dir,
                  :sender => sender, :recipient => recipient, 
                  :chat_dir => chat_dir, :msg => msg,
                  :protocol => :yahoo_im }
              end
              
            when 85   # List (denotes sign on)
              username = content[3] || content[89]
              next unless username
              obj.user = username
              @event_collector.send(:yahoo_im_login) do
                realname = "#{content[216]} #{content[254]}"
                realname = nil unless realname.length > 1
                { :server_ip => str_ip(state.app_state[:dst]),
                  :client_ip => str_ip(state.app_state[:src]),
                  :server_port => state.app_state[:dport],
                  :client_port => state.app_state[:sport], :dir => dir,
                  :username => username, :name => realname }
              end
              
            when 241   # Buddy list?
              next unless content[65]
              next unless content[7]   # Have to have at least one friend
              
              # This is a little annoying; redundant array indices!
              @event_collector.send(:yahoo_im_friend_list) do
                friends, i = [], nil
                ret.split("\xc0\x80").each do |elm|
                  if i
                    friends << elm if i == 7
                    i = nil
                  else
                    i = elm.to_i
                  end
                end
                { :server_ip => str_ip(state.app_state[:dst]),
                  :client_ip => str_ip(state.app_state[:src]),
                  :server_port => state.app_state[:dport],
                  :client_port => state.app_state[:sport], :dir => dir,
                  :username => obj.user, :friends => friends }
              end
              
          end  # of case service
        
        # Just skip past the given number of bytes
        when :skip_content
          pos, ret = _skip_bytes(obj, data, pos)
          return true if ret
          _prepare_to_copy(obj, 20)
          obj.state = :get_header          
        
      end  # of case
    end  # of while data
    true
  end  # of parse_yahoo_im

end  # of class Protos
