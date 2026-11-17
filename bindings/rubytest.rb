#!/usr/bin/ruby

require RbConfig::CONFIG['vendorarchdir'] + '/mscrubylogparser'

#puts MscRubyLogParser::LOG_TYPE_APACHE
#puts MscRubyLogParser::LOG_TYPE_NGINX
#puts MscRubyLogParser::LOGMSG_UNKNOWN
#puts MscRubyLogParser::LOGMSG_WARNING
#puts MscRubyLogParser::LOGMSG_ACCDENIED
#puts MscRubyLogParser::LOGMSG_REQBODY
#puts MscRubyLogParser::LOGMSG_ERROR
#puts MscRubyLogParser::LOGMSG_AUDITLOG

puts MscRubyLogParser::LIBRARY_VERSION
puts MscRubyLogParser::MODULE_VERSION

if ARGV.length < 2
    puts "Argument missing"
    exit
end

if ARGV[1] == "apache"
    logtype = MscRubyLogParser::LOG_TYPE_APACHE
elsif ARGV[1] == "nginx"
    logtype = MscRubyLogParser::LOG_TYPE_NGINX
else
    puts "Unknown logtype"
    exit
end

File.readlines(ARGV[0]).each do |line|
   result = MscRubyLogParser.parse(line, line.bytesize, logtype)
   puts result
   result = nil
end

