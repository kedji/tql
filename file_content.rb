# This is the super-application layer that handles file content.  It handles
# file data much in the same way that stream.rb handles TCP/UDP and
# application-layer data.

require 'helpers.rb'

class FileParser
  include ParserHelpers

  # Class constants
  MIME_CHARS =
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
  MAGIC_BYTES = 16
  FILE_MAGIC = [
    [ /^<[Hh][Tt][Mm][Ll]/,                         'html'        ],
    [ /^<![-D]/,                                    'html'        ],
    [ /^GIF8/,                                      'gif'         ],
    [ /^#{"\\xff\xd8\xff"}/,                        'jpeg'        ],
    [ /^BM/,                                        'bitmap'      ],
    [ /^for \(;;\)/,                                'facebook'    ],
    [ /^[0-9]{2,4}\n\[\[/,                          'gtalk'       ],
    [ /^#![\/ ]/,                                   'script'      ],
    [ /^#{"\x1f\x8b"}/,                             'gzip'        ],
    [ /^PK/,                                        'pkzip'       ],
    [ /^BZ/,                                        'bzip'        ],
    [ /^MZ/,                                        'pe'          ],
    [ /^.PNG#{"\\x0d\x0a"}/,                        'png'         ],
    [ /^I I/,                                       'tiff'        ],
    [ /^Rar!/,                                      'rar'         ],
    [ /^ID3[#{"\x02"}#{"\x03"}]/,                   'mp3'         ],
    [ /^#{"\xff"}[#{"\xf2"}-#{"\xff"}]/,            'mp3'         ],
    [ /^RIFF/,                                      'avi'         ],
    [ /^\0\0#{"\x01\xba"}/,                         'mpeg'        ],
    [ /^#{"\xa6\xd9\x00\xaa"}\0/,                   'asf'         ],
    [ /^0&#{"\xb2\x75"}/,                           'wmv'         ],
    [ /^....moov/,                                  'mov'         ],
    [ /^....mdat/,                                  'mov'         ],
    [ /^%PDF/,                                      'pdf'         ],
    [ /^DomainKey-S/,                               'email'       ],
    [ /^To: /,                                      'email'       ],
    [ /^From: /,                                    'email'       ],
    [ /^Date: /,                                    'email'       ],
    [ /^Received: /,                                'email'       ],
    [ /^Return-Path:/,                              'email'       ],
    [ /^Message-ID: /,                              'email'       ],
    [ /^#{"\xd4\xc3\xb2\xa1"}/,                     'pcap'        ],
    [ /^#{"\xa1\xb2\xc3\xd4"}/,                     'pcap'        ],
    [ /^[CF][WL][SV]/,                              'flash'       ],
    [ /^<\?[Xx][Mm][Ll]/,                           'xml'         ],
    [ /^[12]#{"\xBE"}/,                             'wri'         ],
    [ /^\{\\rtf/,                                   'rtf'         ],
    [ /^#{"\xD0\xCF\x11\xe0"}/,                     'ms_compound' ],
    [ /^#{"\xef\xbb\xbf"}/,                         'unicode'     ],
]

  def initialize(event_collector, state, dir, proto, name = nil)
    @event_collector = event_collector
    @state = state                          # state object of container stream
    @sdir = dir                             # :up or :down
    @dir = (state.app_state[dir][:type] rescue :unknown)
    @proto = proto                          # protocol transferring the file
    @name = name                            # hint at file name
    
    # Parsing data
    @pos = 0                                       # where within the file
    @buff = ''                                     # buffer the file
    @maxlen = @event_collector.max_file_length     # max bytes to buffer
    @eject = !@event_collector.parse_file_contents # skip file parsing?
    @mime_block = ''                               # chunk of four bytes
    @finished = nil                                # used for idempotency
    @magic = nil                                   # stores file type if known
    @parser = nil                                  # pointer to parsing method
    @pstate = nil                                  # state for parsing method
    @conclude = nil                                # pointer to parser conclude
  end
  attr_reader :pos, :buff, :maxlen, :magic
  attr_writer :maxlen
  
  # Return our global state hash
  def global_state  
    @event_collector.global_state
  end

  # Virtual accessor - tells if we have the whole file
  def complete?
    buff.length < @maxlen
  end
  
  # Handle a chunk of data associated with this file stream
  def parse(data, pos = 0)
    return nil if @eject

    # Check to see if we need to apply some heuristics
    if @buff.length < MAGIC_BYTES
      rem = MAGIC_BYTES - @buff.length
      @buff << data[0, rem]
      pos += rem
      data[0, rem] = ''

      # Apply heuristics if we have enough data
      if @buff.length == MAGIC_BYTES
        FILE_MAGIC.each do |exp, parser|
          if @buff =~ exp
            begin
              @magic = parser
              @parser = method("fparse_#{parser}")
              @conclude = method("conclude_#{parser}") rescue nil
              @parser.call(@buff)
            rescue NameError
              @parser = nil
              @event_collector.send(:file_parser_dne) do
                { :format => @magic, :parser => "fparse_#{parser}",
                  :client_ip => str_ip(@state.app_state[:src]),
                  :server_ip => str_ip(@state.app_state[:dst]),
                  :client_port => @state.app_state[:sport],
                  :server_port => @state.app_state[:dport],
                  :dir => @dir, :protocol => @proto
                }
              end
            end
          end  # of if buff =~ exp
        end  # of each file_magic
      end  # of if sufficient buffer for heuristics

      return nil if data.empty?
    end  # of if-need-heuristics-data

    # Just buffer the data and hand off to the file parser
    if @parser
      @parser = nil unless @parser.call(data)
    end
    @buff << data unless @buff.length > @maxlen
    @pos += data.length
  end  # of parse()
  
  # Handle a chunk of data associated with this file stream, but the stream
  # is being delivered Base64 encoded.  Decode it before handing it directly
  # to parse
  def parse_64(edata)
    return nil if @eject
    to_parse = ''
    
    # Check every single F'ing character.  God, MIME is slow.
    edata.each_byte do |i| i = i.chr
      if MIME_CHARS.include?(i)
        @mime_block << i
        if @mime_block.length == 4
          to_parse << de_mime(@mime_block)
          @mime_block = ''
        end
      end
    end  # of each_byte

    # Hand the decoded data to the parser
    parse(to_parse) unless to_parse.empty?
  end  # of parse_64
  
  # Take four MIME chars and produce three (at most) decoded bytes
  def de_mime(quad)
    num = 0
    sub = 3
    quad.each_byte do |x|
      if x.between?(0x41, 0x5a)     ; x -= 0x41
      elsif x.between?(0x61, 0x7a)  ; x -= 0x47
      elsif x.between?(0x30, 0x39)  ; x += 0x4
      elsif x == 0x2b               ; x = 0x3e
      elsif x == 0x2f               ; x = 0x3f
      else
        x = 0
        sub -= 1
      end
      num = (num << 6) + x
    end  # of each byte
    ret = (num >> 16).chr + ((num >> 8) & 0xFF).chr + (num & 0xFF).chr
    ret[0,sub]
  end
  
  # The file has finished being transferred, that's all the data
  def conclude(finished = true)
    return nil if @finished or @pos < 1
    @conclude.call if @conclude    # call the parser's conclude method
    @event_collector.send(:file_transfer) do
      { :server_ip => str_ip(@state.app_state[:dst]),
        :client_ip => str_ip(@state.app_state[:src]),
        :server_port => @state.app_state[:dport],
        :client_port => @state.app_state[:sport], :size => @buff.length,
        :complete => (complete? & finished), :dir => @dir, :protocol => @proto,
        :content => @buff, :name => @name,
        :format => @magic
      }
    end  # of sending event
    @finished = true
  end  # of conclude
  
  # The file isn't done being sent, but that's all the data we have.
  def abort ; conclude(false) ; end
  
  # This turned out not to be a file.  Believe me, this can happen
  def cancel ; @finished = true ; @buff = '' ; end
  
end  # of FileParser


#########  Parsers  #########
require 'fparse_email.rb'
require 'fparse_gzip.rb'
require 'fparse_facebook.rb'
require 'fparse_gtalk.rb'
