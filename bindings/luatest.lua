#!/usr/bin/lua

function dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s ..k..' = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

function file_exists(file)
  local f = io.open(file, "r")
  if f then f:close() end
  return f ~= nil
end

function lines_from(file)
  if not file_exists(file) then return {} end
  local lines = {}
  for line in io.lines(file) do 
    lines[#lines + 1] = line
  end
  return lines
end

p = require("msclualogparser")

--print(p.LOG_TYPE_APACHE)
--print(p.LOG_TYPE_NGINX)

--print(p.LOGMSG_UNKNOWN)
--print(p.LOGMSG_WARNING)
--print(p.LOGMSG_ACCDENIED)
--print(p.LOGMSG_REQBODY)
--print(p.LOGMSG_ERROR)
--print(p.LOGMSG_AUDITLOG)

print(p.LIBRARY_VERSION)
print(p.MODULE_VERSION)

if (arg[2] == nil)
then
    print("Argument missing")
    return 1
end

local logtype = -1

if (arg[2] == "apache")
then
    logtype = p.LOG_TYPE_APACHE
elseif (arg[2] == "nginx")
then
    logtype = p.LOG_TYPE_NGINX
else
    print("Invalid logtype")
    return 1
end

for k,v in pairs(lines_from(arg[1])) do
  l = string.len(v)
  r = p.parse(v, l, logtype)
  print(dump(r))
  r = nil
end

