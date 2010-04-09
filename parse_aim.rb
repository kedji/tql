class Protos

  # AIM connections are divided into two components - logon, and communication.
  # The communication component exchanges SNAC data.  That is to say, Channel
  # ID is set to 2 and usually contains an FNAC.  The logon component exchanges
  # New Connection data, ie, Channel ID is set to 1.  Parse the logon half.
  def parse_aim_logon(data, state, dir)
    return nil unless data
    req = state.app_state[:req_struct]
    res = state.app_state[:resp_struct]
    
    # Hand off to the client or server parser as needed.
    dir = state.app_state[dir][:type]
    return _parse_aim_traffic(data, state, res, req, dir) if dir == :server
    return _parse_aim_traffic(data, state, req, res, dir) if dir == :client
    raise "AIM traffic not client or server"
  end  # of parse_aim_logon

  # Parse AIM logon stream, server-to-client or client-to-server, keep state
  # in res.  'dir' is either :server or :client
  def _parse_aim_traffic(data, state, res, req, dir)
    pos = 0

    # Check our initialization condition
    unless res
    res = Struct.new(
        :state, :buff, :maxlen, :terminator, :channel, :seq_number, :family,
        :sub_family, :auth_cookie, :username, :flags, :client_version,
        :language, :country, :email
      ).new
      res.state = :find_channel
      _prepare_to_copy(res, 6)
      state.app_state[:resp_struct] = res if dir == :server
      state.app_state[:req_struct] = res if dir == :client
    end

    while pos < data.length
      case res.state

        # Find the channel header (always six bytes)
        when :find_channel
          pos, ret = _copy_bytes(res, data, pos)
          return true if ret == true

          # We have our header, let's dissect it
          raise "AIM traffic out of sync" unless ret[0] == 0x2A
          res.channel = ret[1]
          res.seq_number = _big_endian(ret[2,2])
          _prepare_to_copy(res, _big_endian(ret[4,2]))  # fine if it's 0
          res.state = :channel_contents

        # We've already parsed the channel header, now get its contents
        when :channel_contents
          pos, ret = _copy_bytes(res, data, pos)
          return true if ret == true
        
          # We have our blob of data.  Report it.
          @event_collector.send(:aim_raw_flap) do
            { :channel => res.channel,
              :seq => res.seq_number, :snac => ret, :dir => dir,
              :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport] }
          end

          # Now break it up depending on channel ID
          # Logon
          if res.channel == 1
            if ret.length >= 8
              tlvs = _aim_tlvs_split(res, ret, 4)  # first 4 bytes are version
              res.auth_cookie = (tlvs.find { |t,_| t == 6 } || []).last
              aim_cookies = (global_state[:aim_cookies] ||= {})
              login_info = aim_cookies.delete res.auth_cookie
              if login_info
                res.username       = login_info[:username]
                req.username       = login_info[:username] if req
                res.email          = login_info[:email]
                req.email          = login_info[:email]    if req
                res.client_version = login_info[:version]
                req.client_version = login_info[:version]  if req
                res.language       = login_info[:language]
                req.language       = login_info[:language] if req
                res.country        = login_info[:country]
                req.country        = login_info[:country]  if req
                @event_collector.send(:aim_login) do
                  { :seq => res.seq_number, :dir => dir,
                    :server_ip => str_ip(state.app_state[:dst]),
                    :client_ip => str_ip(state.app_state[:src]),
                    :server_port => state.app_state[:dport],
                    :client_port => state.app_state[:sport],
                    :username => res.username, :country => res.country,
                    :client_version => res.client_version, 
                    :email => res.email, :language => res.language
                  }
                end
              end  # of if login_info
            end  # of if proper login

          # Logoff
          elsif res.channel == 4
            # Do nothing right now

          # SNAC data
          else res.channel == 2
            _parse_aim_fnac(state, res, dir, req, ret) if ret.length >= 10

          end  # of channel type

          # Time to get the next FLAP
          res.state = :find_channel
          _prepare_to_copy(res, 6)

      end  # of case state
    end  # of while data
    true   
  end  # of _parse_aim_traffic

  # Take a blob containing TLVs (and optionally a position where to begin
  # parsing) and return a list of TLVs.  Format of returned TLV:
  # [ tlv_type, tlv_data]  (length can be inferred from tlv_data.length)
  def _aim_tlvs_split(res, blob, pos = 0)
    tlvs = []

    # loop while there's data to be read
    while blob.length - pos >= 4
      tlv_type = _big_endian(blob[pos,2])
      tlv_len  = _big_endian(blob[pos+2,2])
      pos += 4
      if blob.length - pos < tlv_len
        @event_collector.send(:aim_tlv_overflow) do
          { :channel => res.channel,
            :seq => res.seq_number, :snac => res.buff, :dir => dir,
            :server_ip => str_ip(state.app_state[:dst]),
            :client_ip => str_ip(state.app_state[:src]),
            :server_port => state.app_state[:dport],
            :client_port => state.app_state[:sport],
            :should_be => blob.length - pos, :length => tlv_len }
        end
        break
      end  # of if overflow

      # Add the TLV and increment position
      tlvs << [ tlv_type, blob[pos, tlv_len] ]
      pos += tlv_len
    end  # of while data
    tlvs
  end  # of _aim_tlvs_split
  
  # Grab SSI's, just like TLVs.  Return an array.  Format: [type, name]
  def _aim_ssis_split(res, blob, pos = 0)
    ssis = []
    while blob.length - pos > 4
      len = _big_endian(blob[pos, 2])
      name = blob[pos+2, len]
      pos = pos + len + 6
      type = _big_endian(blob[pos, 2])
      len = _big_endian(blob[pos+2, 2])
      pos = pos + len + 4
      ssis << [type, name] unless name.empty?
    end
    ssis
  end

  # Parse out an FNAC - some are TLVs, some aren't.  All have 10-byte headers
  def _parse_aim_fnac(state, res, dir, req, snac)
    # First get the header
    res.family = _big_endian(snac[0,2])
    res.sub_family = _big_endian(snac[2,2])
    res.flags = _big_endian(snac[4,2])
    #res.fnac_id = _big_endian(snac[6,4])

    # Now conditionally handle each FNAC that we understand.
    case [ res.family, res.sub_family ]

      # Signon/Logon  (a bit redundant, ain't it?)
      when [ 0x17, 0x2 ]
        tlvs = _aim_tlvs_split(res, snac, 10)

        # Get the username
        if (tlv = tlvs.find { |t,_| t == 0x1 })
          res.username = tlv.last
          req.username = tlv.last if req
        end

        # Get the version string
        if (tlv = tlvs.find { |t,_| t == 0x3 })
          res.client_version = tlv.last
          req.client_version = tlv.last if req
        end

        # Get the language
        if (tlv = tlvs.find { |t,_| t == 0xF })
          res.language = tlv.last
          req.language = tlv.last if req
        end

        # Get the country
        if (tlv = tlvs.find { |t,_| t == 0xE })
          res.country = tlv.last
          req.country = tlv.last if req
        end

      # Signon/Logon-Reply
      when [ 0x17, 0x3 ]
        tlvs = _aim_tlvs_split(res, snac, 10)

        # Get the username
        if (tlv = tlvs.find { |t,_| t == 0x1 })
          res.username = tlv.last
          req.username = tlv.last if req
        end

        # Get the auth_cookie
        if (tlv = tlvs.find { |t,_| t == 0x6 })
          res.auth_cookie = tlv.last
          req.auth_cookie = tlv.last if req
        end

        # Get the user's official email address
        if (tlv = tlvs.find { |t,_| t == 0x11 })
          res.email = tlv.last
          req.email = tlv.last if req
        end

        # Now add this object to our global state
        res.username ||= req.username if req   # just to be sure
        if res.auth_cookie and res.username
          aim_cookies = (global_state[:aim_cookies] ||= {})
          
          # First let's delete all the old cookies just in case they're cluttering
          aim_cookies.reject! { |_,v| state.last_seen - v[:time] > 3600 }
          
          # Now add our new cookie
          aim_cookies[res.auth_cookie] = { :username => res.username,
            :email => res.email, :language => res.language,
            :country => res.country, :version => res.client_version,
            :time => state.last_seen }
        end
      
      # AIM-SSI/List
      when [ 0x13, 0x6 ]
        ssis = _aim_ssis_split(res, snac, 13)
        ssis = ssis.select { |t,_| t == 0 }
        ssis = ssis.collect { |_,x| x.downcase.gsub(' ', '') }
        if ssis.length > 1
          @event_collector.send(:aim_buddy_list) do
            { :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport], :dir => dir,
              :username => res.username, :country => res.country,
              :client_version => res.client_version, 
              :email => res.email, :language => res.language,
              :seq => res.seq_number, :buddies => ssis
            }
          end
        end  # of if buddy list    

      # Messaging/outgoing
      when [ 0x4, 0x6 ]
        buddylen = snac[20]  # only one byte
        buddy = snac[21, buddylen]
        tlvs = _aim_tlvs_split(res, snac, 21+buddylen)
        msg = tlvs.find { |t,_| t == 0x2 }  # message block
        if msg
          msg = msg.last
          
          # cut out msg header (which has an encoded length)
          msg[0, _big_endian(msg[2,2]) + 12] = ''
          @event_collector.send(:aim_message) do
            { :seq => res.seq_number, 
              :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport], :dir => dir,
              :sender => res.username, :country => res.country,
              :client_version => res.client_version, :chat_dir => :outgoing,
              :email => res.email, :language => res.language,
              :recipient => buddy, :msg => _strip_html(msg)
            }
          end
          @event_collector.send(:protos_chat_message) do
            { :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport], :dir => dir,
              :chat_dir => :outgoing, :recipient => buddy, 
              :sender => res.username, :protocol => :aim,
              :content => _strip_html(msg) }
          end
        end  # of if msg
      
      # Messaging/incoming
      when [ 0x4, 0x7 ]
        buddylen = snac[20]  # only one byte
        buddy = snac[21, buddylen]
        tlvs = _aim_tlvs_split(res, snac, 25+buddylen)
        msg = tlvs.find { |t,_| t == 0x2 }  # message block
        if msg
          msg = msg.last
          
          # cut out msg header (which has an encoded length)
          msg[0, _big_endian(msg[2,2]) + 12] = ''
          @event_collector.send(:aim_message) do
            { :seq => res.seq_number, :chat_dir => :incoming,
              :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport], :dir => dir,
              :recipient => res.username, :country => res.country,
              :client_version => res.client_version, 
              :email => res.email, :language => res.language,
              :sender => buddy, :msg => _strip_html(msg)
            }
          end
          @event_collector.send(:protos_chat_message) do
            { :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport], :dir => dir,
              :chat_dir => :incoming, :recipient => res.username, 
              :sender => buddy, :protocol => :aim,
              :content => _strip_html(msg) }
          end
        end  # of if msg
      
    end  # of case family/subfamily
  end  # of _parse_aim_fnac
  
end  # of class Protos
