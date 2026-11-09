#!/usr/bin/python3

# Reference leak check for the Python binding.
#
# Parses the same lines many times and checks that the number of memory
# blocks allocated by the interpreter does not grow with the number of
# parse() calls. A leaked reference (eg. a list or a string which was
# never released) shows up as a linear growth.
#
# Usage: pyleaktest.py [logfile apache|nginx]
# Without arguments it uses the built-in sample lines.
#
# Note: parse() writes a '\0' to line[len], so the lines are passed
# without the trailing newline and with their length in bytes.

import sys
import gc
import mscpylogparser

SAMPLES = [
    (mscpylogparser.LOG_TYPE_NGINX,
     '2026/10/21 16:30:51 [info] 1234#1234: *45 ModSecurity: Warning. Matched "Operator `Within\' with parameter `.bak/ .sql/\' against variable `TX:EXTENSION\' (Value: `.sql/\' ) [file "/usr/share/modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1036"] [id "920440"] [rev ""] [msg "URL file extension is restricted by policy"] [data ".sql"] [severity "2"] [ver "OWASP_CRS/3.3.10"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [hostname "www.example.com"] [uri "/dump.sql"] [unique_id "179259305124.380942"] [ref "o4,4o5,3v5,8o281,5t:urlDecodeUni,t:lowercase"], client: 192.0.2.10, server: www.example.com, request: "GET /dump.sql HTTP/1.1", host: "www.example.com"'),
    (mscpylogparser.LOG_TYPE_APACHE,
     '[Wed Oct 21 16:30:51.123456 2026] [security2:error] [pid 1234:tid 5678] [client 192.0.2.10:54321] [client 192.0.2.10] ModSecurity: Warning. Matched phrase "nikto" at REQUEST_HEADERS:User-Agent. [file "/usr/share/modsecurity-crs/rules/REQUEST-913-SCANNER-DETECTION.conf"] [line "56"] [id "913100"] [msg "Found User-Agent associated with security scanner"] [data "Matched Data: nikto found within REQUEST_HEADERS:User-Agent: mozilla/5.00 (nikto/2.1.6)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.10"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-reputation-scanner"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [hostname "www.example.com"] [uri "/"] [unique_id "ZTNmYzE3ZWQtNjQ"]'),
    # broken entries: the parser reports errors for them
    (mscpylogparser.LOG_TYPE_NGINX,
     '2026/10/21 16:30:51 [info] 1234#1234: *45 ModSecurity: Warning. [file "/x.conf"] [line "1"] [id "1"] [tag "a"] [tag "b" [hostname "www.example.com"] [uri "/"'),
    (mscpylogparser.LOG_TYPE_APACHE,
     '[Wed Oct 21 16:30:51.123456 2026] [security2:error] [pid 1234:tid 5678] [client 192.0.2.10:54321] [client 192.0.2.10] ModSecurity: Warning. [id "1"] [tag "a"] [unknown "x"] [uri'),
]

ROUNDS = 6
CALLS_PER_ROUND = 20000


def load_lines():
    if len(sys.argv) < 3:
        return SAMPLES
    if sys.argv[2] == "apache":
        lt = mscpylogparser.LOG_TYPE_APACHE
    elif sys.argv[2] == "nginx":
        lt = mscpylogparser.LOG_TYPE_NGINX
    else:
        print("Invalid logtype")
        sys.exit(2)
    with open(sys.argv[1], "r", errors="replace") as fp:
        lines = [(lt, l.rstrip("\n")) for l in fp.readlines()[:CALLS_PER_ROUND]]
    if not lines:
        print("FAIL: %s has no lines" % sys.argv[1])
        sys.exit(2)
    return lines


def one_round(lines):
    calls = 0
    tags = 0
    errors = 0
    while calls < CALLS_PER_ROUND:
        for lt, l in lines:
            r = mscpylogparser.parse(l, len(l.encode()), lt)
            tags += len(r['log_rule_tags'])
            errors += len(r['log_entry_errors'])
            calls += 1
    return calls, tags, errors


# sys.getallocatedblocks() counts pymalloc blocks only, it is always 0 eg. with
# PYTHONMALLOC=malloc, and a constant zero would look like a pass
if sys.getallocatedblocks() == 0:
    print("SKIP: cannot measure, sys.getallocatedblocks() is 0 (PYTHONMALLOC=malloc?)")
    sys.exit(77)

lines = load_lines()
blocks = []
for i in range(ROUNDS):
    calls, tags, errors = one_round(lines)
    gc.collect()
    blocks.append(sys.getallocatedblocks())
    print("round %d: %d calls, %d tags, %d errors, allocated blocks: %d" % (i + 1, calls, tags, errors, blocks[-1]))

# the first round warms up the interpreter (caches, interned strings)
growth = blocks[-1] - blocks[1]
calls = (ROUNDS - 2) * CALLS_PER_ROUND
print("growth after warm-up: %d blocks in %d calls (%.3f blocks/call)" % (growth, calls, float(growth) / calls))

if tags == 0 or errors == 0:
    print("FAIL: the input does not exercise tags and errors")
    sys.exit(1)

if growth > calls / 100:
    print("FAIL: memory grows with the number of parse() calls - reference leak")
    sys.exit(1)

print("OK")
