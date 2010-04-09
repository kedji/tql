# Since DHCP is UDP-based, we can presume that all of the data is contained
# within the 'data' variable.

class Protos

  def parse_dhcp_client(data, state, dir)
    return nil unless data
    return false unless data.length > 241
    return false unless _big_endian(data[0xEC, 4]) == 0x63825363

    # Initialize reporting variables
    host = nil
    requested = 0

    # Now read in all the options
    _dhcp_options(data) do |typ,val|
      case typ
        when 12
          host = val
        when 50
          requested = _big_endian(val)
      end  # of case
    end  # of _dhcp_options

    # Do our reporting
    @event_collector.send(:dhcp_request) do
      # Get the src & dst address/port fist
      src, dst, sport, dport = state.src, state.dst, state.sport, state.dport
      src, dst, sport, dport = dst, src, dport, sport unless dir == :up

      # Event details themselves
      { :requested => str_ip(requested), :host => host, :dir => :client,
        :client_port => sport, :server_ip => str_ip(dst),
        :server_port => dport, :client_ip => str_ip(src) }
    end  # of event
    true
  end  # of parse_dhcp_server

  def parse_dhcp_server(data, state, dir)
    return nil unless data
    return false unless data.length > 241
    return false unless _big_endian(data[0xEC, 4]) == 0x63825363

    # Initialize reporting variables
    server = lease = router = subnet = 0
    domain = nil

    # Now read in all the options
    _dhcp_options(data) do |typ,val|
      case typ
        when 1
          subnet = _big_endian(val)
        when 3
          router = _big_endian(val)
        when 15
          domain = val
        when 51
          lease = _big_endian(val)
        when 54
          server = _big_endian(val)
      end  # of case
    end  # of _dhcp_options

    # Do our reporting
    @event_collector.send(:dhcp_offer) do
      # Get the src & dst address/port fist
      src, dst, sport, dport = state.src, state.dst, state.sport, state.dport
      src, dst, sport, dport = dst, src, dport, sport unless dir == :down

      # Event details themselves
      { :server => str_ip(server), :lease => lease, :router => str_ip(router),
        :subnet => str_ip(subnet), :domain => domain, :dir => :server,
        :client_port => sport, :server_ip => str_ip(dst),
        :server_port => dport, :client_ip => str_ip(src) }
    end  # of event
    true
  end  # of parse_dhcp_server

  # Loop through the options provided in this packet.  Opts start at 0xF0.
  # Each one is a TLV so it's easy to parse; yield each type, value
  def _dhcp_options(data)
    pos = 0xF0
    loop do
      break if data.length <= pos + 3
      typ = data[pos]
      len = data[pos+1]
      break if data.length <= pos + 2 + len or typ == 0
      yield [ typ, data[pos+2, len] ]
      pos += 2 + len
    end
  end  # of _dhcp_options

end  # of class Protos
