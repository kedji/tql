require 'helpers.rb'

# Class which identifies and parses application-layer traffic.
class Protos
  include ParserHelpers
  MAGIC_BYTES = 8

  def initialize(event_collector)
    @event_collector = event_collector
    @maxlen = @event_collector.max_file_length
    init_heuristics
  end
  
  # Entry-point method where all delivered traffic initially comes in.  The
  # fact that this method is being called implies that state.app_state has
  # been created, has not been destroyed (happens when a parser decides to
  # stop processing the stream), and that the 3-way handshake has been seen.
  # Return true on success, otherwise kill app_state and return false.
  def parse(data, state, dir)
    pstate = state.app_state[dir]
    return nil unless pstate

    # Do some initialization on this stream if new
    init_parse(state, dir) unless pstate[:magic]

    # Grab the magic first few bytes if we don't have them yet
    if pstate[:magic].length < MAGIC_BYTES
      heuristics(data, state, dir)

      # If both up and down states have been deleted, delete app_state
      state.app_state=nil unless state.app_state[:up] or state.app_state[:down]
#puts "!!! state reset" unless state.app_state

      # Return false if we're not going to parse, true if we're out of bytes
      return false unless state.app_state and state.app_state[dir]
      return true if data.length == 0
    end

    # Now hand this off to our parser
    begin
      ret = pstate[:parser].call(data, state, dir)
    rescue RuntimeError
      @event_collector.send(:protos_parser_exception) do
        parser = pstate[:parser].to_s
        pos = parser.index('parse')
        parser = parser[pos...parser.index('>', pos)]
        { :dir => state.app_state[dir][:type], :parser => parser,
          :server_ip => str_ip(state.app_state[:dst]),
          :client_ip => str_ip(state.app_state[:src]),
          :server_port => state.app_state[:dport],
          :client_port => state.app_state[:sport], :reason => $! }
      end
      ret = nil
    end
    
    # The parser returned a value indicating that it wished to stop parsing,
    # or it raised an exception
    unless ret
      @event_collector.send(:protos_parser_aborting) do
        parser = pstate[:parser].to_s
        pos = parser.index('parse')
        parser = parser[pos...parser.index('>', pos)]
        { :dir => state.app_state[dir][:type], :parser => parser,
          :server_ip => str_ip(state.app_state[:dst]),
          :client_ip => str_ip(state.app_state[:src]),
          :server_port => state.app_state[:dport],
          :client_port => state.app_state[:sport] }
      end if state.layer_4 == :tcp
      state.app_state[dir] = nil
      state.app_state=nil unless state.app_state[:up] or state.app_state[:down]
      return false
    end
    
    # Finally, update the state statistics
    if dir == :up
      state.bytes_up += data.length
    else
      state.bytes_down += data.length
    end
    true
  end  # of parse()

  # The stream has ended for reasons other than content of the protocol
  # eg, FIN, RST, or we've fallen out of sync.
  # Send nil as data to the parser to signal the stream's conclusion.
  def conclude(state, dir)
    pstate = (state.app_state ? state.app_state[dir] : nil)
    pstate[:parser].call(nil, state, dir) if pstate and pstate[:parser]
    nil
  end

  # Initialize a new data stream
  def init_parse(state, dir)
    if dir == :up
      state.app_state[dir][:type] = state.syn_seen == :src ? :client : :server
    else
      state.app_state[dir][:type] = state.syn_seen == :src ? :server : :client
    end
    state.app_state[:dport] = state.syn_seen == :src ? state.dport : state.sport
    state.app_state[:sport] = state.syn_seen == :src ? state.sport : state.dport
    state.app_state[:src] = state.syn_seen == :src ? state.src : state.dst
    state.app_state[:dst] = state.syn_seen == :src ? state.dst : state.src
    state.app_state[:name] = state.last_seen.strftime("%Y-%m-%d_%H-%M-%S_")
    state.app_state[dir][:magic] = ''
  end

  # Grab the first few "magic" bytes of a connection and use them to
  # attempt to heuristically identify the protocol.  If some magic bytes are
  # taken from data, then use .replace() to remove them from the string.  If
  # all magic bytes have been read, prepend them to data using .replace().
  def heuristics(data, state, dir)
    pstate = state.app_state[dir]
    magic = pstate[:magic]
    rem = MAGIC_BYTES - magic.length

    # Grab the remaining bytes from data
    magic << data[0, rem]
    data[0, rem] = ''

    # Do we have all the bytes we need?
    if magic.length == MAGIC_BYTES
      # First back-fill the data so the protocol parser can see the first
      # bytes of the connection as well.
      data.replace "#{magic}#{data}"

      # Now let's do some scanning...
      [ true, false ].each do |pc|  # do we consider the port?
        @proto_magic.each do |port, exp, parser|
          if !exp or magic =~ exp
            # Check the port on the first pass
            if pc
              next unless state.app_state[:dport] == port
            elsif not exp
              next
            end
            
            # Alert that we've identified the stream!
            @event_collector.send(:protos_magic_found) do
              if state.layer_4 == :tcp
                { :protocol => parser,
                  :client_ip => str_ip(state.app_state[:src]),
                  :server_ip => str_ip(state.app_state[:dst]),
                  :client_port => state.app_state[:sport],
                  :server_port => state.app_state[:dport],
                  :dir => state.app_state[dir][:type], :default_port => pc
                }
              end
            end

            # Now point this stream at a parsing method
            begin
              pstate[:parser] = method "parse_#{parser}"
            rescue
              @event_collector.send(:protos_parser_dne) do
                { :magic => magic, :client_ip => str_ip(state.app_state[:src]),
                  :server_ip => str_ip(state.app_state[:dst]),
                  :client_port => state.app_state[:sport],
                  :server_port => state.app_state[:dport],
                  :parser => "parse_#{parser}",
                  :dir => state.app_state[dir][:type] }
              end
              pstate[:parser] = false
            end
            break
          end  # of if regex match
        end  # of proto_magic.each
        break unless pstate[:parser] == nil
      end  # of consider port?

      # If we don't have a parser for this magic number, step into the
      # parse_octet_stream state.
      if pstate[:parser].nil?
        @event_collector.send(:protos_magic_not_found) do
          { :magic => magic, :client_ip => str_ip(state.app_state[:src]),
            :server_ip => str_ip(state.app_state[:dst]),
            :client_port => state.app_state[:sport],
            :server_port => state.app_state[:dport],
            :dir => state.app_state[dir][:type],
            :tcp => state.pkt.tcp?, :udp => state.pkt.udp? }
        end
        pstate[:parser] = method "parse_octet_stream"
      end
      state.app_state[dir] = nil unless pstate[:parser]
            
    end  # of if magic bytes read
    nil
  end  # of heuristics()

  # Read in our heuristics definitions.  Here's the format (and the process
  # of identification):  proto_magic consists of arrays that contain default
  # port number, heuristic regex, and protocol name.  The protocol
  # identification process makes two passes through proto_magic for each
  # stream.  In the first pass, a match is returned if port and regex
  # content match.  In the second pass, only the regex match matters.  This
  # helps defend against protocol collisions (FTP, SMTP and POP3 for instance)
  # in the majority of cases since services generally run on known ports.
  # Putting nil in place of a regex will cause strict port matching (matching
  # on port only, not content) - use this sparingly!
  def init_heuristics()
   @proto_magic = [
    [   80, /^GET \//,                                        'http_client' ],
    [   80, /^HEAD \//,                                       'http_client' ],
    [   80, /^POST \//,                                       'http_client' ],
    [   80, /^HTTP\/1\./,                                     'http_server' ],
    [  443, /^#{"\x80"}.#{"\x01\x03"}.\0/m,                   'tls'         ],
    [  443, /^#{"\\x16\x03"}....\0\0/m,                       'tls'         ],
    [  139, /^#{"\xff"}SMB/,                                  'smb'         ],
    [ 5190, /^\*#{"\x01"}....\0\0/m,                          'aim_logon'   ],
    [ 5190, /^\*#{"\x02"}/,                                   'aim_logon'   ],
    [ 5050, /^YMSG/,                                          'yahoo_im'    ],
    [ 6667, /^NICK /,                                         'irc_traffic' ],
    [ 6667, /^NOTICE A/,                                      'irc_traffic' ],
    [   21, /^220[- ]/,                                       'ftp_server'  ],
    [   21, /^USER /,                                         'ftp_client'  ],
    [   25, /^2[52]0[ -]/,                                    'smtp_server' ],
    [   25, /^5[0-9][0-9][ -]/,                               'smtp_server' ],
    [   25, /^354 Star/,                                      'smtp_server' ],
    [   25, /^[Rr][Ss][Ee][Tt]#{"\r\n"}/,                     'smtp_client' ],
    [   25, /^[EHeh][EHeh][Ll][Oo] /,                         'smtp_client' ],
    [  110, /^[+]OK /,                                        'pop3_server' ],
    [  110, /^APOP /,                                         'pop3_client' ],
    [  110, /^AUTH #{"\r\n"}/,                                'pop3_client' ],
    [  110, /^USER /,                                         'pop3_client' ],
    [  143, /^[*] OK /,                                       'imap_server' ],
    [  143, /^1 C/,                                           'imap_server' ],
    [  143, /^[A-Za-z0-9]{4} [A-Za-z]/,                       'imap_client' ],
    [ 6881, /^.BitTorr/m,                                     'bittorrent'  ],
    [   22, /^SSH-/,                                          'ssh'         ],
    [   53, /^..[\0#{"\x01"}].#{"\x00\x01"}\0\0/m,            'dns_client'  ],
    [   53, /^..[#{"\x80"}#{"\x81"}#{"\x85"}].\0#{"\x01"}\0/m,'dns_server'  ],
    [   68, /^#{"\x01\x01\x06\x00"}/,                         'dhcp_client' ],
    [   67, /^#{"\x02\x01\x06\x00"}/,                         'dhcp_server' ],
    [  138, nil,                                              'netbios'     ],
    [ 5901, /^RFB [0-9]{3}\./,                                'vnc'         ],
    [ 3389, /^.\0\0..[#{"\xe0"}#{"\xd0"}]\0\0/,               'rdp'         ],
    [ 1863, /^\\login2\\/,                                    'msim_client' ],
    [ 1863, /^\\lc\\/,                                        'msim_server' ],
   ]
  end  # of init_heuristics

  # Return our global state hash
  def global_state
    @event_collector.global_state
  end

end  # of class Protos


#########  Parsers  #########
require 'file_content.rb'
require 'parse_octet_stream.rb'
require 'parse_http.rb'
require 'parse_aim.rb'
require 'parse_irc.rb'
require 'parse_bittorrent.rb'
require 'parse_smtp.rb'
require 'parse_pop3.rb'
require 'parse_imap.rb'
require 'parse_ssh.rb'
require 'parse_dns.rb'
require 'parse_ftp.rb'
require 'parse_dhcp.rb'
require 'parse_yahoo_im.rb'
require 'parse_netbios.rb'
require 'parse_vnc.rb'
require 'parse_rdp.rb'
