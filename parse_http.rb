class Protos

  # Parse HTTP reqeusts.  Return true for "keep feeding me data", or false for
  # "I'm done parsing this"
  def parse_http_client(data, state, dir)
    return nil unless data
    req = state.app_state[:req_struct]
    res = state.app_state[:resp_struct]
    pos = 0

    # State initialization
    unless req
      req = state.app_state[:req_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :kvps, :command, :resource,
        :version, :reused, :host, :fparser, :multipart, :multistate, :bcheck,
        :nfwd
      ).new
      req.state = :find_command
      _prepare_to_copy(req, 2070, "\n")
      req.reused = false
    end
    
    while pos < data.length
      case req.state
      
        # Find the entire command bar; eg "GET /file.php?a=5 HTTP/1.1"
        when :find_command
          # Search until we find a newline
          pos, ret = _find_terminator(req, data, pos)
          
          # Check our exit conditions
          raise "Not HTTP request or URL too long" unless ret
          return true if ret == true  # More data to come, but not now

          # Deconstruct into either 2 or 3 component pieces
          req.command, req.resource, req.version = ret.split
          req.version = "HTTP/0.9" unless req.version
          return false unless req.command
          if req.version.strip.length == 8 and req.version[0,5] == 'HTTP/'
            req.version = req.version[5,3]
          else
            req.version = "malformed(#{req.version.strip})"
          end

          # Report HTTP 0.9 requests and exit
          if req.version == '0.9'
            @event_collector.send(:http_request) do
              { :command => req.command, :version => req.version,
                :resource => req.resource, :reused_connection => req.reused,
                :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport],
                :dir => state.app_state[dir][:type] }
            end  # of sending event
            
            # Now let's prepare the octet stream parser to accept file
            file_endpoints = (global_state[:file_endpoints] ||= [])

            # First delete all the old endpoints just in case
            file_endpoints.reject! { |v| state.last_seen - v[3] > 3600 }

            # Now add the endpoint
            file_endpoints << [ state.app_state[:dst], state.app_state[:dport],
                                :http, state.last_seen, req.resource ]
            return false  # done parsing
          end  # of if HTTP 0.9
          
          # Set up the next state (all the attributes are the same, actually)
          req.kvps = {}
          req.state = :gather_kvps
          req.buff = ''
    
        # Get elements like Host and User-Agent, if they're supplied
        when :gather_kvps
          pos, ret = _find_terminator(req, data, pos)

          # Check our exit conditions
          raise "Not valid HTTP or KVP too long" unless ret
          return true if ret == true  # More data to come, but not now
          
          # Trim the \r and look for our state-change condition
          ret[-1,1] = '' if ret[-1,1] == "\r"
          cpos = ret.index(': ')
          if cpos
            skey = (ret[0,cpos].downcase.gsub('-','').to_sym rescue :invalid)
            req.kvps[skey] = ret[cpos+2..-1]
          end
          if ret.length < 2  # We're at the "\r\n\r\n" terminating the request
            req.host = req.kvps[:host]          
            @event_collector.send(:http_request) do
              { :command => req.command, :version => req.version,
                :resource => req.resource, :accept => req.kvps[:accept],
                :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport],
                :reused_connection => req.reused,
                :cookie => req.kvps[:cookie],
                :keepalive => req.kvps[:keepalive],
                :referer => req.kvps[:referer], :host => req.host,
                :user_agent => req.kvps[:useragent],
                :dir => state.app_state[dir][:type]
              }
            end  # of sending event
            
            # If there's a cookie, raise a similar event
            @event_collector.send(:http_cookie) do
              { :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport],
                :resource => req.resource, :command => 'GET',
                :cookie => req.kvps[:cookie], :host => req.kvps[:host],
                :dir => state.app_state[dir][:type]
              }
            end if req.kvps[:cookie]

            # Set up the next state
            if req.command.upcase == 'POST'
              if (len = req.kvps[:contentlength].to_i) > 0
                req.state = :post_contents
                _prepare_to_copy(req, len, @maxlen)
                
                # Is this a multipart message with boundaries?
                ct = (req.kvps[:contenttype] or '')
                if ct.include?('multipart') and ct.include?('boundary=')
                  req.multipart = ct[ct.index('boundary=')+9..-4].gsub('"','')
                  req.multistate = :headers
                  req.fparser = nil
                  req.bcheck = ''

                # This is a generic POST, still run it through the file parser
                else
                  req.fparser = FileParser.new(@event_collector, state, dir,
                                               :http_post, req.resource)
                end
              else
                req.state = :find_command
              end
            else
              req.reused = true
              req.state = :find_command
            end
          end  # of if request termination
          
          # Clear our searching data
          req.buff = ''
          
        # Grab the stuff after the key value pairs (post contents?)
        when :post_contents
          spos = pos

          # This copy is limited to @maxlen (max file size)
          pos, ret = _copy_bytes(req, data, pos)

          # Handle multipart or classic POSTs separately
          if req.multipart
            _parse_multipart_post(req, data, spos, pos, state, dir)
          else
            req.fparser.parse(data[spos...pos])
          end
          return true if ret == true
          req.fparser.conclude unless req.multipart  # We're done

          # We have our POST content.  Raise an event.
          @event_collector.send(:http_post) do
            { :content => req.buff, :version => req.version,
              :resource => req.resource, :accept => req.kvps[:accept],
              :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport],
              :reused_connection => req.reused,
              :cookie => req.kvps[:cookie],
              :keepalive => req.kvps[:keepalive],
              :referer => req.kvps[:referer], :host => req.host,
              :user_agent => req.kvps[:useragent],
              :dir => state.app_state[dir][:type]
            }
          end  # of send event
          
          # If there's a cookie, raise a similar event
          @event_collector.send(:http_cookie) do
            { :server_ip => str_ip(state.app_state[:dst]),
              :client_ip => str_ip(state.app_state[:src]),
              :server_port => state.app_state[:dport],
              :client_port => state.app_state[:sport],
              :resource => req.resource, :command => 'POST',
              :cookie => req.kvps[:cookie], :host => req.kvps[:host],
              :dir => state.app_state[dir][:type]
            }
          end if req.kvps[:cookie]

          # Set up next state
          req.state = :find_command
          _prepare_to_copy(req, 2070, "\n")

      end  # of case(req.state)
    end  # of while pos < data.length
    return true
  end

  # Parse HTTP responses.
  def parse_http_server(data, state, dir)
    return nil unless data
    req = state.app_state[:req_struct]
    res = state.app_state[:resp_struct]
    pos = 0
    
    # State initialization
    unless res
      res = state.app_state[:resp_struct] = Struct.new(
        :state, :buff, :maxlen, :terminator, :kvps, :response, :code,
        :version, :reused, :contentbytes, :content, :chunked
      ).new
      res.state = :find_command
      _prepare_to_copy(res, 1044, "\n")
      res.kvps = {}
      res.reused = false
      res.chunked = false
    end
    
    while pos < data.length
      case res.state
      
        # Find the entire command bar; eg "GET /file.php?a=5 HTTP/1.1"
        when :find_command

          # Search until we find a newline
          pos, ret = _find_terminator(res, data, pos)
          
          # Check our exit conditions
          raise "Not HTTP response <<#{ret}>>" unless ret
          return true if ret == true  # More data to come, but not now

          # Deconstruct into either 2 or 3 component pieces
          res.version, res.code, res.response = ret.split
          raise "Invalid response code <<#{ret.strip}>>" unless res.response
          res.response.strip!
          if res.version.strip.length == 8 and res.version[0,5] == 'HTTP/'
            res.version = res.version[5,3]
          else
            res.version = "malformed(#{res.version.strip})"
          end
          
          # Set up the next state (all the attributes are the same, actually)
          res.state = :gather_kvps
          res.buff = ''
    
        # Get elements like Server and LastModified, if they're supplied
        when :gather_kvps
          pos, ret = _find_terminator(res, data, pos)

          # Check our exit conditions
          raise "Not valid HTTP or KVP too long" unless ret
          return true if ret == true  # More data to come, but not now
          
          # Trim the \r and look for our state-change condition
          ret[-1,1] = '' if ret[-1,1] == "\r"
          cpos = ret.index(': ')
          if cpos
            skey = (ret[0,cpos].downcase.gsub('-','').to_sym rescue :invalid)
            res.kvps[skey] = ret[cpos+2..-1]
          end
          if ret.length < 2  # We're at the "\r\n\r\n" terminating the kvps          
            @event_collector.send(:http_response_header) do
              { :response => res.response, :version => res.version, 
                :code => res.code, :host => (req.host if req rescue nil),
                :resource => (req.resource if req rescue nil),
                :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport],
                :dir => state.app_state[dir][:type],
                :chunked => res.chunked,
                :content_length => res.kvps[:contentlength],
                :content_type => res.kvps[:contenttype],
                :server => res.kvps[:server], :cookie => res.kvps[:setcookie]
              }
            end  # of sending event
            
            # If there's a cookie, raise a similar event
            @event_collector.send(:http_cookie_set) do
              { :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport],
                :dir => state.app_state[dir][:type],
                :resource => (req ? req.resource : nil),
                :host => (req ? req.kvps[:host] : nil),
                :cookie => res.kvps[:setcookie]
              }
            end if res.kvps[:setcookie]

            # Set up the next state
            if res.kvps[:contentlength]
              res.contentbytes = res.kvps[:contentlength].to_i
              res.state = :get_content
              fname = (req.resource rescue nil)
              res.content = FileParser.new(@event_collector, state, dir,
                                           :http, fname)
            elsif res.kvps[:transferencoding] == 'chunked'
              res.state = :find_chunk_length
            else
              res.kvps = {}
              res.state = :find_command
            end
          end  # of if-kvps termination

          # Clear our searching data
          res.buff = ''
          
        # We're in the middle of getting a file.  Grab it!
        when :get_content
          # Is there more data after this ?
          if data.length - pos < res.contentbytes
            res.content.parse(data[pos..-1])
            res.contentbytes -= data.length - pos
            return true
            
          # There's no more data, we're done grabbing the file.
          else
            res.content.parse(data[pos, res.contentbytes])
            pos += res.contentbytes
            res.contentbytes = 0
            res.content.conclude
            @event_collector.send(:http_response) do
              { :response => res.response, :version => res.version, 
                :code => res.code, :host => (req.host if req rescue nil),
                :resource => (req.resource if req rescue nil),
                :server_ip => str_ip(state.app_state[:dst]),
                :client_ip => str_ip(state.app_state[:src]),
                :server_port => state.app_state[:dport],
                :client_port => state.app_state[:sport],
                :content_length => res.kvps[:contentlength],
                :content_type => res.kvps[:contenttype],
                :server => res.kvps[:server], :content => res.content.buff,
                :complete => res.content.complete?,
                :cookie => res.kvps[:setcookie], :chunked => res.chunked,
                :dir => state.app_state[dir][:type],
              }
            end  # of sending event
            
            # Determine our destination based on whether or not we're chunked
            res.buff = ''
            if res.chunked
              res.state = :skip_two_bytes
              _prepare_to_copy(res, 2)
            else
              res.kvps = {}
              res.state = :find_command
            end
          end  # of if-end-of-content
          
        # This is a bit annoying.  Content after regular "content-length"
        # response is just followed by the next response.  Following "chunked"
        # content, however, there's a "\r\n" delimiter before the next chunk
        # length.  Also, there's a double "\r\n" after the last chunk (the
        # one of size zero), so sometimes we need to skip two bytes and THEN
        # change state.
        when :skip_two_bytes
          pos, ret = _copy_bytes(res, data, pos)
          return true if ret == true
          
          # We're either looking for a new response header or a new chunked
          # transfer length.
          _prepare_to_copy(res, 1044, "\n")
          if res.chunked
            res.state = :find_chunk_length
          else
            res.state = :find_command
          end
          
        # If this is a chunked encoding transfer, it will begin with
        # a hex value signifying length (or 0 to exit).  Share's content-
        # grabbing state with "content-length" encoding.
        when :find_chunk_length
          # Search until we find a newline
          pos, ret = _find_terminator(res, data, pos)
          
          # Check our exit conditions
          raise "HTTP response chunk length not found" unless ret
          return true if ret == true  # More data to come, but not now
          
          # We have the length in hex, decode it and transfer state
          res.contentbytes = ret.to_i(16)
          res.buff = ''
          res.content = FileParser.new(@event_collector, state, dir, :http,
                                       'chunked')
          res.chunked = true
          res.state = :get_content
          
          # A chunk size of zero means skip two bytes, then look for a new
          # response header.
          if res.contentbytes < 1
            res.chunked = false
            res.maxlen = 2
            res.state = :skip_two_bytes
          end
          
      end  # of case state
    end  # of while pos < data.length
    true
  end
  
  # Multipart POST messages may contain files we'd like to take a look at
  def _parse_multipart_post(req, data, pos, epos, state, dir)
    while pos < epos
      case req.multistate
        
        # Looking for headers that preceed the data
        when :headers
          i = data.index("\n", pos)
          if i and i < epos
            req.bcheck << data[pos...i]
            pos = i + 1
            
            # Exit condition - \r\n\r\n
            if req.bcheck.length < 2
              req.multistate = :body_check
              req.nfwd = false
              req.fparser = FileParser.new(@event_collector, state, dir,
                                           :http_post, 'multipart')
                                           
            # boundary found, not really a big deal right now
            #elsif req.bcheck.include?(req.multipart)
            end  # of if exit condition or boundary
            req.bcheck = ''
          else
            req.bcheck << data[pos...epos]
            return nil
          end  # of if newline found
          
        # Getting the body, always checking for the boundary and newlines.
        when :body_check
        
          # If our buffered data is less than the boundary, buffer more data.
          rem = req.multipart.length - req.bcheck.length
          
          # Check for a newline before buffering
          i = data.index("\r\n", pos)
          i += 1 if i
          
          # Okay, we found a newline before the buffer could possibly be the
          # boundary, so this data is good to send along.
          if i and i < epos and i - pos < rem
            req.bcheck << data[pos...(i-1)]
            
            # We might have to prepend a newline - any chunck except the first
            req.bcheck = "\r\n#{req.bcheck}" if req.nfwd
            req.nfwd = true
            
            # Hand the data off to the parser
            req.fparser.parse(req.bcheck)  # clearly this isn't the boundary
            req.bcheck = ''
            pos = i + 1
          
          # No newline, buffer what we can
          else
            if pos + rem < epos  # We have all the data we need, let's get it
              req.bcheck << data[pos,rem]
              pos += rem
              
              # Did we find the boundary?
              if req.bcheck.include?(req.multipart[0..-3])
                if req.fparser.pos <= 4
                  req.fparser.cancel
                else
                  req.fparser.conclude
                end
                req.bcheck = ''
                req.multistate = :headers
                
              # Nope, this data is part of the content. Send it to the parser
              # and change to the state where we just look for a newline.
              else
                # We might have to prepend a newline
                req.bcheck = "\r\n#{req.bcheck}" if req.nfwd
                req.nfwd = true
                req.fparser.parse(req.bcheck)
                req.bcheck = ''
                req.multistate = :body_nocheck                
              end  # of if-boundary-found
              
            # Nope, we don't have all the data we need.  Buffer and exit
            else
              req.bcheck << data[pos...epos]
              return nil
            end  # of if-we-have-all-the-data-we-need
          end  # of if-newline-before-buffer's-end
          
        # slightly faster state for handing data to the file parser.  Only
        # looks for newlines, otherwise forwards all data.
        when :body_nocheck
          i = data.index("\r\n", pos)
          i += 1 if i
          
          # We found a newline in our data
          if i and i < epos
            req.nfwd = true
            req.fparser.parse(data[pos...(i-1)])
            pos = i + 1
            req.multistate = :body_check
          
          # We didn't find a newline - send all this data along
          else
            req.fparser.parse(data[pos...epos])
            return nil
          end  # of if-newline-found
                      
      end  # of case multistate
    end  # of while data
  end  # end of _parse_multipart_post

end  # of class Protos
