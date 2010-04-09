class Protos

  # This method parses unidentified TCP streams to see if useful information
  # can be gleaned.  This can be turned off using the variable ???????.
  def parse_octet_stream(data, state, dir)
    dir = state.app_state[dir][:type]
    req = state.app_state[:req_struct_o]
    res = state.app_state[:resp_struct_o]
    obj = dir == :client ? req : res
    return _octet_stream_conclude(state, dir, obj) unless data
    pos = 0

    # Check our initialization state
    unless obj
      # "index" in this context refers to number of bytes ALREADY handled
      # by previous invocations of the parser.  pos+index -> position within
      # the stream.
      obj = state.app_state[dir == :client ? :req_struct_o : :resp_struct_o] =
            Struct.new(:state, :buff, :maxlen, :terminator, :index,
                       :magic, :fparser).new
      obj.index = 0
      obj.state = :heuristics
      _prepare_to_copy(obj, 16)

      # Do a check to see if this is a raw file transfer we should be
      # expecting.
      file_endpoints = global_state[:file_endpoints]
      if file_endpoints
        fep = file_endpoints.find do |ep|
          ep[0] == state.app_state[:dst] and
          ep[1] == state.app_state[:dport]
        end
        
        # We found an endpoint, this is a raw file transfer
        if fep
          file_endpoints.delete fep
          obj.state = :raw_transfer
          obj.fparser = FileParser.new(@event_collector, state, dir, fep[2],
                                       fep[4])
        end
      end  # of if file_endpoints
    end  # of unless obj

    while pos < data.length
      case obj.state

        # We know this is a file transfer, let's just run it right through
        # the file content parser
        when :raw_transfer
          obj.fparser.parse(data)
          pos = data.length
        
        # In this state we just spin forever because we haven't found anything.
        when :skip
          pos = data.length

        # In this state we're looking for key elements to identify this kind
        # of traffic.  Keep in mind it may be a raw file transfer.
        when :heuristics
          pos, ret = _copy_bytes(obj, data, pos)
          unless ret == true
            obj.magic = ret[0,16]

            # Can we match this to anything?
#$stderr.puts "Applying heuristics to unknown octet stream"

          end
          obj.state = :skip

      end  # of case
    end  # of while data

    # Deliver a chunk of data as an event, and advance our internal index
    @event_collector.send(:octet_stream_chunk) do
      { :data => data, :dir => dir, 
        :client_ip => str_ip(state.app_state[:src]),
        :server_ip => str_ip(state.app_state[:dst]),
        :server_port => state.app_state[:dport],
        :client_port => state.app_state[:sport],
        :index => obj.index, :magic => obj.magic }
    end unless file_endpoints
    obj.index += data.length

  end  # of parse_octet_stream

  # We've been signaled that this stream is over.  Wrap up if necessary.
  def _octet_stream_conclude(state, dir, obj)
    obj.fparser.conclude if obj.fparser
  end  # of _octet_stream_conclude

end  # of class Protos
