/*
This file is part of the libmsclogparser project.

log_server: the nginx "server:" field, the server_name of the block that
served the request. Table driven, one row per line shape.

nginx appends its context to the ModSecurity message
(ngx_http_log_error_handler(), src/http/ngx_http_request.c):
  , client: ADDR, server: NAME[, request: "LINE"][, ...][, host: "HOST"][, referrer: "REF"]
The quoted values are not escaped, so a fake ", client: X, server: Y" can
come both before (matched value, [uri]) and after (request line, host,
referrer) the real one. The rule: exactly one ", client: ADDR, server: "
in the line -> its NAME; otherwise an empty string and exactly one error
message (ambiguous or truncated line). Parsing continues either way.

Build and run: make check (or tests/run-tests.sh).
*/

#include "../src/msclogparser.c"
#include "test_util.h"

// the nginx error log line is cut at NGX_MAX_ERROR_STR (2048) bytes with the LF
#define NGX_MAX_LINE 2047

#define ERR_AMBIGUOUS "log_server: ambiguous 'server:' context, value not used"
#define ERR_TRUNCATED "log_server: line truncated, value not used"

#define REAL ", client: 192.0.2.10, server: www.example.test, request: \"GET /?q=1 HTTP/1.1\""
#define FAKE ", client: 192.0.2.66, server: evil.example.test, request: "

typedef struct {
    const char *name;
    // the nginx line is built from these (NULL: default), see build_line()
    const char *value;          // matched value, default "1"
    size_t      value_pad;      // number of 'A's appended to the value
    const char *hostname;       // [hostname], default "www.example.test"
    const char *uri;            // [uri], default "/"
    const char *suffix;         // the nginx context after the ModSecurity part
    const char *raw;            // a complete line instead of the above
    loglinetype type;
    const char *cut_before;     // cut the line before the first occurrence of this
    size_t      cut_len;        // cut the line at this length (0: no cut)
    const char *not_in_line;    // the built line must not contain this
    // expected
    const char *server;
    const char *hostname_exp;   // NULL: not checked
    const char *client_exp;     // NULL: not checked
    int         modsecline;     // -1: not checked
    int         broken;         // -1: not checked
    const char *error;          // NULL: no error expected, else the one error message
} server_case;

static const server_case cases[] = {
    { .name = "normal line",
      .suffix = REAL ", host: \"www.example.test\"",
      .server = "www.example.test", .hostname_exp = "www.example.test",
      .client_exp = "192.0.2.10", .modsecline = 1, .broken = 0 },
    // log_hostname is unchanged: still the name the client sent
    { .name = "unknown host is served by the default block",
      .hostname = "asdf.invalid",
      .suffix = ", client: 192.0.2.10, server: _, request: \"GET / HTTP/1.1\", host: \"asdf.invalid\"",
      .server = "_", .hostname_exp = "asdf.invalid", .modsecline = -1, .broken = -1 },
    // HTTP/1.0 without Host: the connector puts server_name into [hostname]
    { .name = "no host header",
      .hostname = "_",
      .suffix = ", client: 192.0.2.10, server: _, request: \"GET / HTTP/1.0\"",
      .server = "_", .hostname_exp = "_", .modsecline = -1, .broken = -1 },
    { .name = "empty server_name",
      .suffix = ", client: 192.0.2.10, server: , request: \"GET / HTTP/1.1\", host: \"a.example.test\"",
      .server = "", .modsecline = -1, .broken = -1 },
    { .name = "no request field, nothing after server",
      .suffix = ", client: 192.0.2.10, server: _",
      .server = "_", .modsecline = -1, .broken = -1 },
    // parse() removes the line ending, the CR of a CRLF too
    { .name = "no request field, LF line ending",
      .suffix = ", client: 192.0.2.10, server: _\n",
      .server = "_", .modsecline = -1, .broken = -1 },
    { .name = "no request field, CRLF line ending",
      .suffix = ", client: 192.0.2.10, server: _\r\n",
      .server = "_", .modsecline = -1, .broken = -1 },
    { .name = "no request field, host after server",
      .suffix = ", client: 192.0.2.10, server: _, host: \"a.example.test\"",
      .server = "_", .modsecline = -1, .broken = -1 },
    // a full fake ", client: X, server: Y": never the fake, empty, not an error
    { .name = "fake client+server in the matched value",
      .value = "1" FAKE "\"x", .suffix = REAL,
      .server = "", .modsecline = -1, .broken = -1,
      .error = ERR_AMBIGUOUS },
    { .name = "fake client+server in the uri",
      .uri = "/a\"]" FAKE "\"x", .suffix = REAL,
      .server = "", .modsecline = -1, .broken = -1,
      .error = ERR_AMBIGUOUS },
    { .name = "fake client+server in the request line",
      .suffix = ", client: 192.0.2.10, server: www.example.test, request: \"GET /?q=1" FAKE "\"x HTTP/1.1\"",
      .server = "", .modsecline = -1, .broken = -1,
      .error = ERR_AMBIGUOUS },
    { .name = "fake client+server in the referrer",
      .suffix = REAL ", referrer: \"x" FAKE "\"y\"",
      .server = "", .modsecline = -1, .broken = -1,
      .error = ERR_AMBIGUOUS },
    { .name = "fake client+server in the host",
      .suffix = REAL ", host: \"x" FAKE "\"y\"",
      .server = "", .modsecline = -1, .broken = -1,
      .error = ERR_AMBIGUOUS },
    // only ", server: .." without a ", client: ADDR" before it: not a candidate
    { .name = "server fragment in the matched value",
      .value = "1, server: evil.example.test, request: \"x", .suffix = REAL,
      .server = "www.example.test", .modsecline = -1, .broken = -1 },
    { .name = "server fragment in the referrer",
      .suffix = REAL ", referrer: \"x, server: evil.example.test, request: \"y\"",
      .server = "www.example.test", .modsecline = -1, .broken = -1 },
    { .name = "truncated line without server",
      .suffix = REAL, .cut_before = ", server: ",
      .server = "", .modsecline = -1, .broken = -1 },
    // a line at NGX_MAX_ERROR_STR may have lost the real context but kept a fake
    { .name = "line cut by nginx is not trusted",
      .suffix = FAKE "\"" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" REAL, .cut_len = NGX_MAX_LINE,
      .not_in_line = ", client: 192.0.2.10",
      .server = "", .modsecline = -1, .broken = -1,
      .error = ERR_TRUNCATED },
    { .name = "line shorter than the nginx cap is used",
      .value = "", .value_pad = 100, .suffix = REAL,
      .server = "www.example.test", .modsecline = -1, .broken = -1 },
    { .name = "apache line has no server",
      .raw = "[Thu Feb 15 13:07:04.494742 2024] [security2:error] [pid 1720626:tid 140234] "
             "[client 192.0.2.9:38148] ModSecurity: Warning. Operator GE matched 5 at "
             "TX:inbound_anomaly_score. [file \"/etc/crs/rules/RESPONSE-980.conf\"] [line \"92\"] "
             "[id \"980130\"] [msg \"Inbound Anomaly Score Exceeded (Total Score: 5)\"] "
             "[hostname \"www.example.test\"] [uri \"/xmlrpc.php\"] [unique_id \"Zc3-aHFzNBf8HIsK4ZQ\"]"
             ", client: 192.0.2.9, server: www.example.test",
      .type = LOG_TYPE_APACHE,
      .server = "", .modsecline = 1, .broken = -1 },
    { .name = "not a modsecurity line",
      .raw = "2026/10/20 12:00:00 [error] 59513#59513: *1 open() failed (2: No such file), "
             "client: 192.0.2.10, server: www.example.test, request: \"GET / HTTP/1.1\"",
      .server = "", .modsecline = 0, .broken = -1 },
};

// the line of a case, malloc()-ed, with room for the '\0' parse() writes
static char * build_line(const server_case *c) {
    const char *value = c->value ? c->value : "1";
    const char *hostname = c->hostname ? c->hostname : "www.example.test";
    const char *uri = c->uri ? c->uri : "/";
    size_t size = 1024 + c->value_pad + strlen(value) + strlen(hostname) + strlen(uri)
                + (c->suffix ? strlen(c->suffix) : 0) + (c->raw ? strlen(c->raw) : 0);
    char *line = malloc(size);
    if (c->raw != NULL) {
        snprintf(line, size, "%s", c->raw);
    }
    else {
        char *pad = malloc(c->value_pad + 1);
        memset(pad, 'A', c->value_pad);
        pad[c->value_pad] = '\0';
        snprintf(line, size,
            "2026/10/20 12:00:00 [error] 59513#59513: *1 ModSecurity: Warning. Matched "
            "\"Operator `Rx' with parameter `x' against variable `ARGS:q' (Value: `%s%s' ) "
            "[file \"/etc/crs/rules/REQUEST-942.conf\"] [line \"10\"] [id \"942100\"] "
            "[msg \"SQL Injection\"] [severity \"2\"] [tag \"attack-sqli\"] "
            "[hostname \"%s\"] [uri \"%s\"] [unique_id \"168142074224.426959\"] [ref \"o0,5v10,5\"]%s",
            value, pad, hostname, uri, c->suffix ? c->suffix : "");
        free(pad);
    }
    if (c->cut_before != NULL) {
        char *p = strstr(line, c->cut_before);
        if (p != NULL) *p = '\0';
    }
    if (c->cut_len > 0 && strlen(line) > c->cut_len) {
        line[c->cut_len] = '\0';
    }
    return line;
}

int main(void) {
    size_t n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        const server_case *c = &cases[i];
        char *line = build_line(c);
        loglinetype type = c->raw != NULL ? c->type : LOG_TYPE_NGINX;
        if (c->cut_len > 0) {
            CHECK(strlen(line) == c->cut_len, "%s: line length %zu", c->name, strlen(line));
        }
        else if (c->raw == NULL) {
            CHECK(strlen(line) < NGX_MAX_LINE, "%s: line length %zu", c->name, strlen(line));
        }
        if (c->not_in_line != NULL) {
            CHECK(strstr(line, c->not_in_line) == NULL, "%s: line contains '%s'", c->name, c->not_in_line);
        }

        logdata l;
        memset(&l, '\0', sizeof(l));
        parse(line, strlen(line), type, &l);

        CHECK(l.log_server != NULL && strcmp(l.log_server, c->server) == 0, "%s: log_server '%s'", c->name, l.log_server);
        CHECK(l.log_server == NULL || strstr(l.log_server, "evil") == NULL, "%s: log_server is the fake", c->name);
        CHECK(l.log_entry_errors_cnt == (c->error != NULL ? 1 : 0), "%s: errors_cnt %d", c->name, l.log_entry_errors_cnt);
        if (c->error != NULL) {
            CHECK(has_error(&l, c->error), "%s: missing error '%s'", c->name, c->error);
            // the rest of the line is still parsed
            CHECK(l.log_rule_id != NULL && strcmp(l.log_rule_id, "942100") == 0, "%s: log_rule_id", c->name);
            CHECK(l.log_uri != NULL && l.log_uri[0] != '\0', "%s: log_uri", c->name);
        }
        if (c->hostname_exp != NULL) {
            CHECK(strcmp(l.log_hostname, c->hostname_exp) == 0, "%s: log_hostname '%s'", c->name, l.log_hostname);
        }
        if (c->client_exp != NULL) {
            CHECK(strcmp(l.log_client, c->client_exp) == 0, "%s: log_client '%s'", c->name, l.log_client);
        }
        if (c->modsecline >= 0) {
            CHECK(l.entry_is_modsecline == c->modsecline, "%s: entry_is_modsecline %d", c->name, l.entry_is_modsecline);
        }
        if (c->broken >= 0) {
            CHECK(l.entry_is_broken == c->broken, "%s: entry_is_broken %d", c->name, l.entry_is_broken);
        }
        free(line);
    }
    printf("test_log_server: %zu cases\n", n);
    return test_result("test_log_server");
}
