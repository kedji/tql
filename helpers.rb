module ParserHelpers

  # String version of an IP address
  def str_ip(num)
    "#{num >> 24}.#{(num >> 16) & 0xFF}.#{(num >> 8) & 0xFF}.#{num & 0xFF}"
  end

  # Search for a terminating character, storing in 'buff' until we find it.
  # Do not store the 'terminator' character inside buff.  If the char hasn't
  # been found in 'maxlen' bytes, return false.  If still searching, return
  # true.  If found, return contents of buff.
  def _find_terminator(obj, data, pos)
    buff, maxlen, term = obj.buff, obj.maxlen, obj.terminator
    loop do
      return pos, false if buff.length >= maxlen
      return pos, true if pos >= data.length
      (pos+=1 ; return pos, buff) if data[pos,1] == term
      buff << data[pos,1]
      pos += 1
    end
  end  # of _find_terminator

  # Copy exactly 'maxlen' bytes into 'buff'.  True means keep parsing, buff
  # means done.  If obj.terminator is present (an integer), only that many
  # bytes will be stored inside buff, although all other functioning will
  # continue as normal.
  def _copy_bytes(obj, data, pos)
    buff, maxlen = obj.buff, obj.maxlen
    maxcopy = obj.terminator.class == Fixnum ? obj.terminator : 2147483647

    # We don't have all our data.  Copy what we've got and return
    remlen = data.length - pos
    if maxlen > remlen
      # Figure out exactly how many bytes to copy into our buffer
      if buff.length < maxcopy
        if buff.length + remlen <= maxcopy
          buff << data[pos..-1]
        else
          buff << data[pos,(maxcopy-buff.length)]
        end
      end

      # Update our counters regardless of how much we buffered
      pos += remlen
      obj.maxlen -= remlen
      return pos, true

    else  # We have all our data, return what we've got
      if buff.length < maxcopy
        if buff.length + maxlen <= maxcopy
          buff << data[pos, maxlen]
        else
          buff << data[pos, maxcopy-buff.length]
        end
      end
      pos += maxlen
      obj.maxlen = 0
      return pos, buff
    end
  end  # of _copy_bytes
  
  # Skip past the given number of bytes, return false when complete, true
  # if more data remains.  Semantics are the same as _copy_bytes() except
  # nothing gets copied.
  def _skip_bytes(obj, data, pos)
    bytes = obj.maxlen
    rem = data.length - pos
    if bytes > rem  # We don't have all our data
      obj.maxlen -= rem
      return pos+rem, true
    end
    obj.maxlen = 0
    pos += bytes
    return pos, false
  end

  # Prepare 'obj' to start filling buff with either _copy_bytes or
  # _find_terminator.
  def _prepare_to_copy(obj, maxlen, terminator = nil)
    obj.buff = ''
    obj.maxlen = maxlen
    obj.terminator = terminator
  end

  # Convert a big-endian string to an int
  def _big_endian(str)
    num = 0
    str.each_byte { |x| num = (num << 8) | x }
    num
  end

  # Convert a big-endian string into a hex string
  def _hex_value(str)
    hex = ''
    str.each_byte { |x| hex << x.to_s(16) }
    hex
  end

  # Generic email parsing routine.  Used by SMTP, POP3, IMAP.  Supports MIME.
  # Feed lines from the email body into this method, one at a time.  Obj
  # must be a res or req object that contains the following attributes:
  # in_mime, body, base64, file_data, fparser, boundary
  def _email_body_line(line, state, obj, dir)
  
    # Are we inside MIME?
    if obj.in_mime
      case obj.in_mime  # mini-state for MIME
            
        # Looking for chunk-specific headers (Content-Transfer-Encoding)
        when :headers
          
          # If they've specified a new MIME boundary, get it (and realize
          # this precludes this MIME section from containing a file)
          if line =~ /oundary=/
            obj.boundary = $'.strip.gsub('"', '')
            i = (obj.boundary =~ /[0-9]/)
            obj.boundary = obj.boundary[0,i] if i
            obj.in_mime = :body
          end
            
          # Get the encoding type if present
          if line =~ /^Content-Transfer-Encoding: /
            obj.base64 = true if $'.strip.downcase == 'base64'
            obj.file_data = true
          end

          # A blank line is our exit condition
          if line.length < 2 
            obj.in_mime = :body
            prot = :email_mime
            prot = :email_mime_64 if obj.base64
            if obj.file_data
              obj.fparser=FileParser.new(@event_collector, state, dir, prot)
              obj.file_data = false
            end
          end
            
        # Just looking for the boundary now
        when :body
          if obj.boundary and line.include?(obj.boundary)
          
            # Were we parsing this file already?
            if obj.fparser
              if obj.base64
                obj.fparser.abort     # We should have seen \r\n first
              else
                obj.fparser.conclude  # All done, exit cleanly
              end
              obj.fparser = nil
            end  # of if we were parsing this
            
            # Read the MIME headers before we start getting the body
            obj.in_mime = :headers
            obj.base64 = false
              
          # We have not found the boundary - keep handing this to our
          # file parser (if we have one)
          else
            if obj.fparser
              if obj.base64
                if line.length < 2
                  obj.fparser.conclude
                else
                  obj.fparser.parse_64(line)
                end
              else
                line << "\n"
                obj.fparser.parse(line)
              end
            end  # of if fparser
              
          end  # of if we found the boundary
      
      end  # of case in_mime state
        
    # We're not inside MIME (yet)
    else
      # Is this a MIME header?
      if line =~ /^MIME-Version: 1\./
        obj.in_mime = :headers
          
      end  # of is this a mime header
    end  # of if-in-MIME
      
    # Add this line to the message body
    #####  Add some sort of length cap?  That'd be a good idea.
    obj.body << line
    obj.body << "\n"
  end  # of _email_body_line
  
  # Take a string and cut out its HTML
  def _strip_html(str)
    txt = str + '>'  # make ourselves a copy for safety
    
    # Strip out tags first
    # Strip out the tags first
    loop do
      break unless (s = txt.index('<'))
      break unless (e = txt.index('>', s))
      txt[s..e] = ''
    end
    
    # Do some conversions
    txt.gsub!('>', '')
    txt.gsub!('&amp;', '&')
    txt.gsub!('&lt;',  '<')
    txt.gsub!('&gt;',  '>')
    txt.gsub!("\x00",  ' ')
    txt.gsub!("\n",    ' ')
    txt.gsub!("\r",    ' ')
    txt.gsub!("\t",    ' ')
    txt
  end  # of _strip_html  

end  # of ParserHelpers
