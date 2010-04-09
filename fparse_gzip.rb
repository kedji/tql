require 'zlib'
require 'stringio'

class FileParser
  
  # Don't do anything except make sure we haven't yet read too much data.  If
  # we have, return false to save (a small amount of) processing power.
  def fparse_gzip(data)
    @buff.length <= @maxlen
  end

  # We can gunzip this now all in one chunk (if the file is completely buffered)
  def conclude_gzip
    return nil unless @buff.length > 10 and @buff.length <= @maxlen
    io_data = StringIO.new(@buff)
    unzipped = nil
    begin
      # Get the gzipped data
      z_stream = Zlib::GzipReader.new(io_data)
      unzipped = z_stream.read
      z_stream.close
    rescue
      return nil
    end

    # Run this new file through the file parser now
    fparser = FileParser.new(@event_collector, @state, @sdir, :gzip,
      (@name ? "#{@name}.gunzipped" : nil))
    fparser.maxlen = unzipped.length  # Not buffering, we have the whole thing
    fparser.parse(unzipped)
    fparser.conclude
  end  # of conclude_gzip

end  # of FileParser
