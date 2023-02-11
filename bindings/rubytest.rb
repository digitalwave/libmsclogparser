#!/usr/bin/ruby

require RbConfig::CONFIG['vendorarchdir'] + '/mscrubylogparser'

#puts LOG_TYPE_APACHE
#puts LOG_TYPE_NGINX
#puts LOGMSG_UNKNOWN
#puts LOGMSG_WARNING
#puts LOGMSG_ACCDENIED
#puts LOGMSG_REQBODY
#puts LOGMSG_ERROR
#puts LOGMSG_AUDITLOG

puts LIBRARY_VERSION
puts MODULE_VERSION

if ARGV.length < 2
    puts "Argument missing"
    exit
end

if ARGV[1] == "apache"
    logtype = LOG_TYPE_APACHE
elsif ARGV[1] == "nginx"
    logtype = LOG_TYPE_NGINX
else
    puts "Unknown logtype"
    exit
end

File.readlines(ARGV[0]).each do |line|
   result = parse(line, line.length, logtype)
   puts result
   result = nil
end

