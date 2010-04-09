#!/usr/bin/env ruby

# Simple tool designed to perform regression testing on TQL.  Assumes the
# presence of a regression directory containing captures (and baselines).

REGRESS_DIR = File.join(File.split(__FILE__).first, 'regress')
baseline = false
failures = completed = 0

# Are we conducting a baseline?
(baseline = true ; ARGV.shift) if ARGV[0] == '-b'

# Print some help?
if ARGV[0] == '-?' or ARGV[0] == '--help'
  puts "\n*** TQL Baseline/Regression Tool ***"
  puts "\nUsage: #{$0} [-b] [files...]"
  puts "Path:  #{REGRESS_DIR}"
  Kernel.exit
end

# Get a list of files?  If no arguments given, regress all of them.
captures = ARGV.dup
if captures.empty?
  captures = Dir.glob(File.join(REGRESS_DIR, '*')).sort.reject do |x|
    x[-9,9] == '.baseline' || x.include?('regress.tql')
  end.collect { |x| File.split(x).last }
end

pkts = kb = ms = 0

# Now do a regression (or baselining) on all the files
captures.each do |cap|
  cfile = File.join(REGRESS_DIR, cap)
  bfile = cfile + ".baseline"
  
  # Raise an exception if a capture is missing or a baseline is missing
  raise "Capture missing: #{cap}" unless File.exist?(cfile)
  raise "Baseline missing for: #{cap}" unless baseline or File.exist?(bfile)

  # Run TQL on this capture or file
  $stdout.flush
  modifier = nil
  modifier = ' -c ' unless cfile[-5,5] == '.pcap'
  color = "\033[0m\033[36m"
  color = "\033[0m\033[34m" if modifier
  print "#{color}" + "#{cap}:#{' '*50}"[0,46]
  cmd = File.join(File.split(__FILE__).first, 'tql')
  cmd << (modifier || ' -p ')
  cmd << cfile
  cmd << " -t #{File.join(REGRESS_DIR, 'regress.tql')}"
  output = `#{cmd} 2>&1`

  # Isolate the performance line and parse it
  pos = output.rindex("\n", -3) || 0
  perf = output[pos..-1]
  output[pos...-1] = ''
  perf = perf.gsub('(', '').gsub('[', '').split.collect { |x| x.to_f }
  perf.reject! { |x| x == 0 }
  
  # Update our totals [ packets, time, p/s, k/s ]
  if perf.length == 4
    kb = kb + (perf[3] * perf[1] / 1000)
    pkts += perf[0].to_i
    ms += perf[1]
  end
  
  # Compare or save this output
  if baseline
    if output =~ /^\t/
      puts "\033[0m\033[37m[ \033[0m\033[41m" +
           "EXCEPTION\033[0m\033[37m ]\033[0m"
      failures += 1
    elsif output != (File.read(bfile) rescue nil)
      File.open(bfile, 'w') { |b| b.write(output) }
      msg = "BASELINED (#{output.length} bytes)"
      puts "\033[0m\033[37m[ \033[0m\033[35m#{msg} \033[0m\033[37m]\033[0m"
      completed += 1
    else
      puts "\033[0m\033[37m[ \033[0m\033[32mUP TO DATE \033[0m\033[37m]\033[0m"
    end
  else
    cmp = File.read(bfile)
    if output =~ /^\t/
      puts "\033[0m\033[37m[ \033[0m\033[41m" +
           "EXCEPTION\033[0m\033[37m ]\033[0m"
      failures += 1
    elsif cmp == output
      completed += 1
      #puts "#{modifier ? 'Content' : 'Capture'} passed"
      puts "\033[0m\033[37m[ \033[0m\033[32mPASSED \033[0m\033[37m]\033[0m"
    else
      failures += 1
      File.open(File.join('/', 'tmp', "#{cap}.stage"), 'w') do |f|
        f.write(output)
      end
      puts "\033[0m\033[37m[ \033[0m\033[31mMISMATCH \033[0m\033[37m]\033[0m"
    end
  end  # of if baseline
end  # of each capture

if baseline
  print "\n\033[0m\033[32m"
  if failures > 0
    print "\033[0m\033[31m#{failures} " +
          "file(s) failed, "
  end
  puts "#{completed} file(s) successfully baselined\033[0m"
else
  print "\033[0m\033[31m" if failures > 0 
  print "\033[0m\033[32m" if failures == 0 
  ms = ms / 1000
  puts "\nTotal: #{pkts} packets in #{(ms*10000).to_i.to_f/10}ms " +
       "(#{(pkts.to_f/ms).to_i} pkts/sec) [#{(kb/ms).to_i}kb/s]"
  puts "#{completed} passed, #{failures} failed."
  print "\033[0m  \n"
end
