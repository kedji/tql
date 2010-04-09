# Event receiver; also parses the TQL statements to build the actual rules.

module EventReceiver

  # Handles incoming events, parsing TQL statements, executing TQL statements,
  # maintains "accept whitelist" for events, etc.
  class Events

    def initialize(debug = false)
      @debug = debug         # True/false flag - do we print debugging info?
      @accept = {}           # Master table for receiving events
      @pkt_count = 0         # Count of all packets processed
      @bytes = 0             # Count of how much traffic has been processed
      @last_pkt = nil        # Last (or current) packet processed
      @global_state = {}     # State shared between all parsers
      @stream_capture = nil  # this gets set to an array when needed
      
      # User variable defaults - these can be modified with TQL statements
      #debug - implicit
      @max_file_length       = 0x10000     # 64k / 1MB
      @full_event_display    = false 
      @parse_file_contents   = true
      @syn_timeout_delay     = 60
      @stream_timeout_delay  = 1800
    end
    attr_reader :bytes, :pkt_count, :debug, :max_file_length, :global_state
    attr_reader :syn_timeout_delay, :full_event_display, :parse_file_contents
    attr_reader :stream_timeout_delay
    attr_reader :stream_capture, :last_pkt
    attr_writer :bytes, :pkt_count, :max_file_length, :last_pkt

    # Hand TQL statements here as a string.  This does NOT destroy the
    # existing accept table, it appends to it.
    def parse_tql(script)
      lines = tokenize(script)

      # We can identify each command by the first word.
      lines.each do |cmd|
        next if cmd.first[0,1] == '#' or cmd.first[0,2] == '--'
        if cmd.first.upcase == 'SELECT'
          cmd = parse_select(cmd)
          debug_select(cmd) if @debug
          add_select(cmd)
        elsif cmd.first.upcase == 'STREAM'
          cmds = parse_stream(cmd)
          cmds.each do |cmd|
            debug_stream(cmd) if @debug
            add_stream(cmd)
          end
        elsif cmd.first.upcase == 'SET'
          debug = @debug
          cmd = parse_and_add_set(cmd)
          debug_set(cmd) if debug
        else
          raise "Unrecognized TQL command, '#{cmd.first.upcase}'"
        end
      end
    end  # of parse_tql

    # This method is responsible for breaking up the TQL statements into
    # atomic components - tokens.  Single-quoted strings are treated as
    # atomic themselves.
    def tokenize(script)
      script = script.dup
      quoted_strings = []

      # First things first, make sure there are no null bytes.
      raise "TQL contains null byte(s)" if script.include? "\0"
      
      # Filter out comment lines
      script = script.split("\n")
      script.reject! { |x| y = x.strip ; y[0,1] == '#' or y[0,2] == '--' }
      script = script.join("\n")
      
      # Convert all single-quoted strings to null chars for placeholding
      loop do
        s = script.index("'")
        break unless s
        e = script.index("'", s+1)
        raise "unmatched single quote" unless e
        quoted_strings << script[s+1...e]
        script[s..e] = " \0 "
      end

      # It would be nice if commas were their own tokens, so let's force that.
      script = script.gsub(',', ' , ').upcase
      
      # Split all statements by ';', then into individual tokens
      lines = script.split(';').collect {|x| x.split }.reject {|x| x.empty? }

      # No go back and replace null bytes with their full strings
      lines.each do |line|
        line.each do |word|
          word.replace(quoted_strings.shift) if word == "\0"
          raise "quoted string parsing underflow" unless word
        end
      end
      raise "quoted string parsing remainder" unless quoted_strings.empty?
      lines
    end  # of tokenize

    # Disect a SELECT statement that's already been tokenized for us.
    def parse_select(cmd)
      # First let's break the statement into its various sub-lists.  Start
      # with FROM
      from_list = cmd.index('FROM')
      raise "Statement missing FROM clause." unless from_list
      select_list = cmd[1...from_list].reject { |x| x == ',' }
      select_list = select_list.collect { |x| x.downcase }
      
      # Now do INTO (skipping WHERE for now)
      into_list = cmd.index('INTO')
      raise "Statement missing INTO clause." unless into_list
      from_list = cmd[from_list+1...into_list]
      into_list = cmd[into_list+1..-1]
      unless into_list.length.between?(1,2)
        raise "Bad number of terms in INTO clause"
      end

      # Now do WHERE (which is conditional and will be part of FROM)
      where_list = nil
      if from_list.include? 'WHERE'
        where_pos = from_list.index 'WHERE'
        where_list = from_list[where_pos+1..-1]
        unless where_list.length == 1
          raise "Bad number of terms in WHERE clause (#{where_list.length})"
        end
        from_list = from_list[0...where_pos]
        where_list = where_list.first
      end
      if from_list.length != 1
        raise "Bad number of terms in FROM clause (#{from_list.length})"
      end
      from_list = from_list.first.downcase

      # Return the hash with the attributes we've just parsed out
      { :select => select_list, :from => from_list, :where => where_list,
        :into => into_list }
    end  # of parse_select

    # Print some debugging information based on the parsed SELECT statement.
    def debug_select(hash)
      $stderr.puts '--- DEBUG ---'
      $stderr.puts "SELECT(#{hash[:select].join(', ')})"
      $stderr.puts "  FROM(#{hash[:from]})"
      $stderr.puts "  WHERE('#{hash[:where]}')" if hash[:where]
      into_list = hash[:into].dup
      into_list.push "'#{into_list.pop}'" if into_list.length > 1
      $stderr.puts "  INTO(#{into_list.join(' ')})"
      $stderr.puts ""
    end  # of debug_select

    # Take a parsed SELECT statement and create entries, "rules", in our
    # accept hash.
    def add_select(cmd)
      attrs = cmd[:select].collect { |x| x.to_sym }
      handler = get_handler(cmd[:into])        
      @accept[cmd[:from].to_sym] ||= []
      @accept[cmd[:from].to_sym] << [ attrs, cmd[:where], handler ]
    end

    # Parse out a STREAM command
    def parse_stream(cmd)      
      # Find the INTO (skipping WHERE for now)
      into_list = cmd.index('INTO')
      raise "Statement missing INTO clause." unless into_list
      from_list = cmd[1...into_list]
      into_list = cmd[into_list+1..-1]
      unless into_list.length.between?(1,2)
        raise "Bad number of terms in INTO clause" 
      end

      # Now do WHERE (which is conditional and will be part of FROM)
      where_list = nil
      if from_list.include? 'WHERE'
        where_pos = from_list.index 'WHERE'
        where_list = from_list[where_pos+1..-1]
        unless where_list.length == 1
          raise "Bad number of terms in WHERE clause (#{where_list.length})"
        end
        from_list = from_list[0...where_pos]
        where_list = where_list.first
      end  # of if WHERE
      
      # Now parse out the STREAM parameters - the interesting part
      if from_list.length < 2 or from_list.length > 3
        raise "Bad number of terms in STREAM clause (#{from_list.length})"
      end
      direction = nil
      if from_list.length == 3
        if from_list[1] == '>' or from_list[1] == '<'
          direction = from_list[1]
        else 
          raise "Invalid direction specification in STREAM statement"
        end
      end  # of if direction
      left_ip,  left_port  = parse_endpoint(from_list.first)
      right_ip, right_port = parse_endpoint(from_list.last)
      
      # Compute our final return array
      ret = []
      if direction == nil or direction == '>'
        ret << { :left_ip => left_ip, :left_port => left_port,
                 :right_ip => right_ip, :right_port => right_port,
                 :where => where_list, :into => into_list }
      end
      if direction == nil or direction == '<'
        ret << { :left_ip => right_ip, :left_port => right_port,
                 :right_ip => left_ip, :right_port => left_port,
                 :where => where_list, :into => into_list }
      end
      return ret
    end  # of parse_stream
    
    # Print some debugging information based on the parsed STREAM statement.
    def debug_stream(hash)
      $stderr.puts '--- DEBUG ---'
      li, ri = (str_ip(hash[:left_ip])||'*'), (str_ip(hash[:right_ip])||'*')
      lp, rp = (hash[:left_port] || '*'), (hash[:right_port] || '*')
      $stderr.puts "STREAM(#{li}:#{lp} > #{ri}:#{rp})"
      psuedo_e = "_stream_capture_#{(@stream_capture || []).length}".to_sym
      $stderr.puts "  INTO EVENT(#{psuedo_e})"
      $stderr.puts ""      
    end  # of debug_stream

    # Take a parsed STREAM statement and create entries in both the
    # stream_capture array and accept hash.  Every stream adds an implicit
    # SELECT statement for actually processing the stream data.
    def add_stream(cmd)
      @stream_capture ||= []
      
      # Generate a psuedo event name, add the stream capture information
      psuedo_event = "_stream_capture_#{@stream_capture.length}".to_sym
      @stream_capture << [ cmd[:left_ip], cmd[:left_port], cmd[:right_ip],
                           cmd[:right_port], psuedo_event ]
                           
      # Now construct an implicit SELECT statement for this psuedo event
      query = { :select => [:content], :from => psuedo_event,
                :where => cmd[:where], :into => cmd[:into] }
      debug_select(query) if @debug
      add_select(query)
    end  # of add_stream

    # Take a TQL SET statement, parse it, and set the appropriate variable
    def parse_and_add_set(cmd)
      # First strip out the superfluous equal's sign if present
      cmd.delete '='
      raise "Invalid format for SET statement." unless cmd.length == 3
      ret = nil
     
      # Get the variable name
      case cmd[1].downcase
        when 'debug'
          ret = @debug = to_bool(cmd[2])
        when 'max_file_length'
          ret = @max_file_length = cmd[2].to_i
        when 'full_event_display'
          ret = @full_event_display = to_bool(cmd[2])
        when 'parse_file_contents'
          ret = @parse_file_contents = to_bool(cmd[2])
        when 'syn_timeout_delay'
          ret = @syn_timeout_delay = cmd[2].to_i
        when 'stream_timeout_delay'
          ret = @stream_timeout_delay = cmd[2].to_i
        else
          raise "Invalid user variable: #{cmd[1]}"
      end
      return cmd[1], ret
    end  # of parse_and_add_set

    # Print some debugging information based on the parsed STREAM statement.
    def debug_set(cmd)
      $stderr.puts '--- DEBUG ---'
      $stderr.puts "SET #{cmd[0].downcase} = #{cmd[1].to_s.upcase}"
      $stderr.puts ''
    end

    # Small helper function that takes a string or numeric value and
    # returns an intuitive true or false.
    def to_bool(str)
      str = str.to_s.downcase
      return true if str == 'yes' or str == 'true' or str == 'on'
      return true if str.to_i > 0
      return false
    end

    # Small helper function that takes an enpoint (IP address and port) and
    # returns the two in numeric format (or corresponding nil's).  Accepts:
    #   1.2.3.4:56      1.2.3.4:*     1.2.3.4:      1.2.3.4
    #   *:*             :*            *:            :56
    # Raises exceptions on invalid strings.
    def parse_endpoint(ep_str)
      ep = ep_str.gsub('*', '').split(":")
      ep[0] ||= ''
      raise "Incomprehensible IP:Port endpoint (#{ep})" if ep.length > 2
      
      # Let's parse the IP address if it's present
      ip = ep.first.split('.')
      if ip.empty?
        ip = nil
      else
        raise "Invalid IP address '#{ep.first}'" unless ip.length == 4
        ip = ip.inject(0) do |val, x|
          x = x.to_i
          raise "Invalid IP address '#{ep.first}'" unless x.between?(0, 255)
          (val << 8) + x
        end
      end  # of ip.empty?
      
      # Now parse the port if it's present
      port = ep[1].to_i
      port = nil if port == 0
      
      return [ip, port]
    end  # of parse_endpoint

    # String version of an IP address
    def str_ip(num)
      return nil unless num
      "#{num >> 24}.#{(num >> 16) & 0xFF}.#{(num >> 8) & 0xFF}.#{num & 0xFF}"
    end
    

    # Convert the INTO clause into a Proc object
    def get_handler(into)
      if into.first == 'RUBY'
        raise "RUBY destination must have code snippit" unless into.length==2
        return lambda { |e,_| event = e; eval into.last }
      elsif into.first == 'METHOD'
        raise "METHOD keyword must provide method name" unless into.length==2
        return lambda { |e,_| method(into.last.downcase).call(e) }
      elsif into.first == 'STDOUT'
        return lambda { |e,_| stdout(e) }
      elsif into.first == 'STDERR'
        return lambda { |e,_| stderr(e) }
      elsif into.first == 'FILE'
        raise "FILE keyword must provide file name" unless into.length==2
        return lambda do |p,f|
          e = event = f
          fname = eval(into.last)
          file_out(p, fname)
        end
      elsif into.first == 'LOG'
        raise "LOG keyword must provide file name" unless into.length==2
        return lambda do |p,f|
          e = event = f
          fname = eval(into.last)
          file_out(p, fname, true)
        end
      elsif into.first == 'FSTREAM'
        raise "FSTREAM keyword must provide file name" unless into.length==2
        return lambda do |p,f|
          e = event = f
          fname = eval(into.last)
          file_out(p, fname, false)
        end
      end
      raise "unknown hander: '#{into.first}'"
    end

    # Standard handlers, stdout and stderr
    def stdout(event) ; $stdout.puts event ; $stdout.flush ; end
    def stderr(event) ; $stderr.puts event ; $stdout.flush ; end
    
    # Write the event's single element into the file (or log).  If log is nil,
    # this is a direct FILE out.  If log is false, this is exactly the same
    # except the file is opened for append-writes.  If log is true, append
    # writes are used, plus attributes are formatted differently
    def file_out(e, fname, log = nil)
      attrs = e.attrs.dup
      
      # Make sure we only have one attribute, not counting time
      time = attrs.delete :time
      event = attrs.delete :event_name
      pkt = attrs.delete :pkt
      unless log or attrs.length == 1
        raise "File output can only write one selected attribute"
      end
      
      # Construct our output value
      value = attrs.find { true }.last.to_s
      if attrs.length == 1
        value = time.strftime "<%Y-%m-%d %H:%M:%S> #{value}" if time and log
        value << "\n" if log
      else
        value = e.to_s
      end
      
      # Open the file (possibly for append) and write out the content.
      File.open(fname.to_s, (log.nil? ? 'w' : 'a')) { |f| f.print(value) }
      nil
    end

    # Collector function, take in events if they're in our accept hash.
    # If they are, for each handler stanza, compile a relevant list of
    # parameters, evaluate the WHERE clause (if given), and assuming it
    # returns true, call the handler passing the event as a parameter.
    def send(event_name, &blk)
      # First grab the hash (if necessary)
      ret = @accept[event_name.to_sym]
      return nil unless ret
      attrs = blk.call
      return false unless attrs   # Returning false omits the event (for perf)
      raise "Bad type - attributes must be a hash" unless attrs.class <= Hash
      attrs[:event_name] = event_name
      attrs[:pkt] = @pkt_count
      attrs[:time] = @last_pkt.time
      
      # Now prune the hash and call our handlers for each event
      ret.each do |alist, where, handler|
        full = Event.new(attrs)
        params = {}

        # Apply WHERE filter in this context BEFORE filtering
        if where
          e = event = full
          return nil unless eval(where)
        end

        # Build the list of "arguments" based on the SELECT statement
        if alist.length == 1 and alist.first == :*
          params = attrs
        else
          params[:event_name] = attrs[:event_name]  # always implicitly included
          alist.each { |k| params[k] = attrs[k] }
        end

        # Pass off to the approprate handler
        e = Event.new(params)
        handler.call(e, full)
      end  # each handler (ret)
    end  # of send()

  end  # of Events class

  # Simple class that makes it easy for TQL writers to access returned
  # attributes.
  class Event
    MAX_ATTR_NAME = 20
    MAX_ATTR_VALUE = 57

    def initialize(attrs = {})  
      @attrs = attrs
    end
    
    # Access members of our hash.  Simple
    def method_missing(cmd, *args)
      if cmd.to_s[-1,1] == '='
        @attrs[cmd.to_s[0...-1].to_sym] = args.first
      else
        @attrs[cmd.to_sym]
      end
    end
    attr_writer :attrs
    attr_reader :attrs
    
    # Is the char printable?
    def _printable?(chr)
      chr.between? 31, 126
    end

    # Printable enumeration of attributes
    def to_s
      ret = "--- #{@attrs[:event_name]} ---\n"
      attrs = @attrs.collect { |k,v| [k.to_s, v] }
      attrs.reject! { |k,_| k == 'event_name' }
      attrs.sort.each do |k,v|
        # Adjust the length of the attribute name
        line = "#{k[0,MAX_ATTR_NAME-2]}:#{' '*MAX_ATTR_NAME}"[0,MAX_ATTR_NAME] 
        
        # Beautify the attribute
        v = v.join(', ') if v.class <= Array
        v = v.to_s
        unless @full_event_display
          v = v[0,MAX_ATTR_VALUE] if v.length > MAX_ATTR_VALUE
        end
        i = 0
        while i < v.length do
          v[i,1] = "\\x#{'%02x' % v[i]}" unless _printable?(v[i])
          i += 1
        end
        unless @full_event_display
          v = v[0,MAX_ATTR_VALUE] if v.length > MAX_ATTR_VALUE
        end
        ret << "  #{line}#{v}\n"
      end
      ret << "\n"
    end  # of to_s
  end  # of class Event

end  # of EventReceiver module


if $0 == __FILE__
  e = EventReceiver::Events.new
  e.parse_tql(
  "SELECT * FROM tables WHERE 'e.bob' INTO stdout;
   SELECT BILL, bob, sam from tcp_replay INTO stdout;; ;; ;
  ")
  e.send(:tables) do
    { :bob => 5, :yo => 'mama' }
  end
end
