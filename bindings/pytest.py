#!/usr/bin/python3

import sys
import mscpylogparser
import json

"""print("Versions:")
print(mscpylogparser.LIBRARY_VERSION)
print(mscpylogparser.MODULE_VERSION)

print("Logtypes:")
print("Apache: ", mscpylogparser.LOG_TYPE_APACHE)
print("Nginx: ", mscpylogparser.LOG_TYPE_NGINX)

print("Logmsgtypes:")
print("LOGMSG_UNKNOWN:", mscpylogparser.LOGMSG_UNKNOWN);
print("LOGMSG_WARNING:", mscpylogparser.LOGMSG_WARNING)
print("LOGMSG_ACCDENIED:", mscpylogparser.LOGMSG_ACCDENIED)
print("LOGMSG_REQBODY:", mscpylogparser.LOGMSG_REQBODY)
print("LOGMSG_ERROR:", mscpylogparser.LOGMSG_ERROR)
print("LOGMSG_AUDITLOG:", mscpylogparser.LOGMSG_AUDITLOG)
"""
if len(sys.argv) < 3:
    print("Argument missing")
    sys.exit(1)

if sys.argv[2] == "apache":
    lt = mscpylogparser.LOG_TYPE_APACHE
elif sys.argv[2] == "nginx":
    lt = mscpylogparser.LOG_TYPE_NGINX
else:
    print("Invalid logtype")
    sys.exit(2)

try:
    with open(sys.argv[1], "r") as fp:
        lines = fp.readlines()
except:
    print("Can't open file.")
    sys.exit(3)

li = 1
for l in lines:
    r = mscpylogparser.parse(l, len(l), lt)
    #if r['is_broken'] == 1:
    #    print(l)
    if True:
        print(json.dumps(r))
    li += 1
    del(r)

