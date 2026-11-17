/*
This file is part of the libmsclogparser project.

log_client and log_server: the nginx "client:" and "server:" fields, the
address of the peer and the server_name of the block that served the
request. Table driven, one row per line shape.

nginx appends its context to the ModSecurity message
(ngx_http_log_error_handler(), src/http/ngx_http_request.c):
  , client: ADDR, server: NAME[, request: "LINE"][, ...][, host: "HOST"][, referrer: "REF"]
The quoted values are not escaped, so a fake ", client: X, server: Y" can
come both before (matched value, [uri]) and after (request line, host,
referrer) the real one. The rule: exactly one ", client: ADDR, server: "
in the line -> its ADDR and NAME; otherwise empty strings and exactly one
error message (ambiguous or truncated line). Parsing continues either way.

test_fake_fields_in_context(): the ModSecurity fields ([file], [id],
[hostname], [unique_id], ...) are searched only before the context (nginx)
or before ", referer: " (Apache), so fake fields in the request line, the
host or the referrer can't replace the real ones.

Build and run: make check (or tests/run-tests.sh).
*/

#include "../src/msclogparser.c"
#include "test_util.h"

// the nginx error log line is cut at NGX_MAX_ERROR_STR (2048) bytes with the LF
#define NGX_MAX_LINE 2047

#define ERR_AMBIGUOUS "client, server: ambiguous context, values not used"
#define ERR_TRUNCATED "client, server: line truncated, values not used"

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
      .server = "", .client_exp = "", .modsecline = -1, .broken = -1,
      .error = ERR_AMBIGUOUS },
    { .name = "fake client+server in the uri",
      .uri = "/a\"]" FAKE "\"x", .suffix = REAL,
      .server = "", .client_exp = "", .modsecline = -1, .broken = -1,
      .error = ERR_AMBIGUOUS },
    { .name = "fake client+server in the request line",
      .suffix = ", client: 192.0.2.10, server: www.example.test, request: \"GET /?q=1" FAKE "\"x HTTP/1.1\"",
      .server = "", .client_exp = "", .modsecline = -1, .broken = -1,
      .error = ERR_AMBIGUOUS },
    { .name = "fake client+server in the referrer",
      .suffix = REAL ", referrer: \"x" FAKE "\"y\"",
      .server = "", .client_exp = "", .modsecline = -1, .broken = -1,
      .error = ERR_AMBIGUOUS },
    { .name = "fake client+server in the host",
      .suffix = REAL ", host: \"x" FAKE "\"y\"",
      .server = "", .client_exp = "", .modsecline = -1, .broken = -1,
      .error = ERR_AMBIGUOUS },
    // only ", server: .." without a ", client: ADDR" before it: not a candidate
    { .name = "server fragment in the matched value",
      .value = "1, server: evil.example.test, request: \"x", .suffix = REAL,
      .server = "www.example.test", .client_exp = "192.0.2.10", .modsecline = -1, .broken = -1 },
    // only ", client: .." without a ", server: " after it: not a candidate
    { .name = "client fragment in the matched value",
      .value = "1, client: 192.0.2.66, x", .suffix = REAL,
      .server = "www.example.test", .client_exp = "192.0.2.10", .modsecline = -1, .broken = -1 },
    { .name = "client fragment in the uri",
      .uri = "/a, client: 192.0.2.66, x", .suffix = REAL,
      .server = "www.example.test", .client_exp = "192.0.2.10", .modsecline = -1, .broken = -1 },
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
      .server = "", .client_exp = "", .modsecline = -1, .broken = -1,
      .error = ERR_TRUNCATED },
    { .name = "line shorter than the nginx cap is used",
      .value = "", .value_pad = 100, .suffix = REAL,
      .server = "www.example.test", .client_exp = "192.0.2.10", .modsecline = -1, .broken = -1 },
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

// the line of a case, malloc()-ed
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

#define NGX_REAL_TAIL "[hostname \"www.example.test\"] [uri \"/\"] [unique_id \"168142074224.426959\"] [ref \"o0,5v10,5\"]"
#define NGX_FAKE_TAIL "\"] [file \"/evil.conf\"] [line \"1\"] [id \"1\"] [msg \"evil\"] [hostname \"evil.example.test\"] [uri \"/evil\"] [unique_id \"EVIL\"] [ref \"\"]"
#define AP_LINE "[Thu Feb 15 13:07:04.494742 2024] [security2:error] [pid 1:tid 2] [client 192.0.2.10:1234] ModSecurity: Warning. Pattern match \"x\" at ARGS:q. " \
    "[file \"/etc/crs/rules/REQUEST-942.conf\"] [line \"10\"] [id \"942100\"] [msg \"SQL Injection\"] [severity \"CRITICAL\"] [tag \"attack-sqli\"] " \
    "[hostname \"www.example.test\"] [uri \"/\"] [unique_id \"Zc3-aHFzNBf8HIsK4ZQ\"]"
#define AP_FAKE_TAIL "x\"] [file \"/evil.conf\"] [line \"1\"] [id \"1\"] [msg \"evil\"] [tag \"evil\"] [hostname \"evil.example.test\"] [uri \"/evil\"] [unique_id \"EVIL\"]"

typedef struct {
    const char *name;
    loglinetype type;
    const char *value;          // nginx: matched value
    const char *hostname;       // nginx: [hostname]
    const char *suffix;         // nginx: the context; Apache: appended to AP_LINE
    // expected
    const char *hostname_exp;
    const char *unique_id_exp;
    const char *server_exp;     // nginx only, NULL: log_server and log_client aren't checked
    int         ambiguous;      // more than one possible end: no field is used
} fake_fields_case;

#define ERR_AMBIGUOUS_PART "Ambiguous end of the ModSecurity part, the fields aren't used!"
#define NGX_WHILE " while sending to client"
// libmodsecurity3 doesn't escape '"' in the variable name of the match message
#define NGX_FAKE_IN_MSG "1' ) [file \"/evil.conf\"] [line \"1\"] [id \"1\"] [msg \"evil\"] [severity \"2\"] " \
    "[hostname \"evil.example.test\"] [uri \"/evil\"] [unique_id \"EVIL\"] [ref \"y\"], client: 192.0.2.66, server: evil.example.test"

static const fake_fields_case fake_cases[] = {
    { "nginx, fake fields in the referrer", LOG_TYPE_NGINX, "1", "www.example.test",
      REAL ", host: \"www.example.test\", referrer: \"x" NGX_FAKE_TAIL "\"",
      "www.example.test", "168142074224.426959", "www.example.test" },
    { "nginx, fake fields in the request line", LOG_TYPE_NGINX, "1", "www.example.test",
      ", client: 192.0.2.10, server: www.example.test, request: \"GET /?q=" NGX_FAKE_TAIL " HTTP/1.1\", host: \"www.example.test\"",
      "www.example.test", "168142074224.426959", "www.example.test" },
    { "nginx, fake fields in the host", LOG_TYPE_NGINX, "1", "www.example.test",
      REAL ", host: \"x" NGX_FAKE_TAIL "\"",
      "www.example.test", "168142074224.426959", "www.example.test" },
    // a fake context after fake fields: two possible ends, no field is used
    { "nginx, fake fields and context in the referrer", LOG_TYPE_NGINX, "1", "www.example.test",
      REAL ", referrer: \"x" NGX_FAKE_TAIL ", client: 192.0.2.66, server: evil.example.test, referrer: \"z\"",
      "", "", "", 1 },
    // the same in the message (libmodsecurity3 doesn't escape the '"' there)
    { "nginx, fake fields and context in the matched value", LOG_TYPE_NGINX, NGX_FAKE_IN_MSG, "www.example.test",
      REAL, "", "", "", 1 },
    { "nginx, fake last field and context in the matched value", LOG_TYPE_NGINX,
      "1 [ref \"y\"], client: 192.0.2.66, server: evil.example.test", "www.example.test",
      REAL, "", "", "", 1 },
    // [uri] is searched after [hostname], not from the beginning of the line
    { "nginx, fake [uri] in the matched value", LOG_TYPE_NGINX, "a [uri \"/evil\"]", "www.example.test",
      REAL, "www.example.test", "168142074224.426959", "www.example.test" },
    // nginx writes ' while ACTION' before the context in some phases
    { "nginx, while ACTION before the context", LOG_TYPE_NGINX, "1", "www.example.test",
      NGX_WHILE REAL ", host: \"www.example.test\"",
      "www.example.test", "168142074224.426959", "www.example.test" },
    { "nginx, while ACTION, fake fields in the referrer", LOG_TYPE_NGINX, "1", "www.example.test",
      NGX_WHILE REAL ", referrer: \"x" NGX_FAKE_TAIL "\"",
      "www.example.test", "168142074224.426959", "www.example.test" },
    // a fake context in the message (no '"' needed) doesn't end the ModSecurity part
    { "nginx, fake context in the matched value", LOG_TYPE_NGINX,
      "1, client: 192.0.2.66, server: evil.example.test", "www.example.test",
      REAL ", referrer: \"x" NGX_FAKE_TAIL "\"",
      "www.example.test", "168142074224.426959", "" },
    // no context at all (eg. nginx cut the line before it): a fake marker in the
    // message doesn't hide the fields
    { "nginx, no context, fake context in the matched value", LOG_TYPE_NGINX,
      "1, client: 192.0.2.66, server: evil.example.test", "www.example.test", "",
      "www.example.test", "168142074224.426959", NULL },
    // an empty [hostname] is taken from the host: of the context, not from a fake one
    { "nginx, empty hostname, fake host in the referrer", LOG_TYPE_NGINX, "1", "",
      REAL ", host: \"real.example.test\", referrer: \"x\", host: \"evil.example.test\" [hostname \"evil\"]\"",
      "real.example.test", "168142074224.426959", "www.example.test" },
    { "apache, fake fields in the referer", LOG_TYPE_APACHE, NULL, NULL,
      ", referer: " AP_FAKE_TAIL,
      "www.example.test", "Zc3-aHFzNBf8HIsK4ZQ", NULL },
    { "apache, fake fields and referer in the referer", LOG_TYPE_APACHE, NULL, NULL,
      ", referer: " AP_FAKE_TAIL ", referer: x",
      "", "", NULL, 1 },
    { "apache, no referer", LOG_TYPE_APACHE, NULL, NULL, "",
      "www.example.test", "Zc3-aHFzNBf8HIsK4ZQ", NULL },
};

static void test_fake_fields_in_context(void) {
    for (size_t i = 0; i < sizeof(fake_cases) / sizeof(fake_cases[0]); i++) {
        const fake_fields_case *c = &fake_cases[i];
        char line[4096];
        if (c->type == LOG_TYPE_NGINX) {
            snprintf(line, sizeof(line),
                "2026/10/20 12:00:00 [error] 59513#59513: *1 ModSecurity: Warning. Matched "
                "\"Operator `Rx' with parameter `x' against variable `ARGS:q' (Value: `%s' ) "
                "[file \"/etc/crs/rules/REQUEST-942.conf\"] [line \"10\"] [id \"942100\"] "
                "[msg \"SQL Injection\"] [severity \"2\"] [tag \"attack-sqli\"] "
                "[hostname \"%s\"] [uri \"/\"] [unique_id \"168142074224.426959\"] [ref \"o0,5v10,5\"]%s",
                c->value, c->hostname, c->suffix);
        }
        else {
            snprintf(line, sizeof(line), "%s%s", AP_LINE, c->suffix);
        }

        logdata l;
        memset(&l, '\0', sizeof(l));
        parse(line, strlen(line), c->type, &l);

        // without a context the line is broken ("Can't find client field!")
        int broken = c->ambiguous || (c->server_exp == NULL && c->type == LOG_TYPE_NGINX);
        CHECK(l.entry_is_modsecline == 1 && l.entry_is_broken == broken,
              "%s: modsecline %d broken %d", c->name, l.entry_is_modsecline, l.entry_is_broken);
        CHECK(has_error(&l, ERR_AMBIGUOUS_PART) == c->ambiguous, "%s: ambiguous error %d", c->name,
              has_error(&l, ERR_AMBIGUOUS_PART));
        if (c->ambiguous) {
            // no field is used, neither the real nor the fake one
            CHECK(l.log_rule_file[0] == '\0' && l.log_rule_id[0] == '\0' && l.log_rule_msg[0] == '\0'
                  && l.log_rule_tags_cnt == 0 && l.log_hostname[0] == '\0' && l.log_uri[0] == '\0'
                  && l.log_unique_id[0] == '\0', "%s: a field is used: file '%s' id '%s' unique_id '%s'", c->name,
                  l.log_rule_file, l.log_rule_id, l.log_unique_id);
            if (c->type == LOG_TYPE_NGINX) {
                CHECK(l.log_client[0] == '\0' && l.log_server[0] == '\0', "%s: client '%s' server '%s'", c->name,
                      l.log_client, l.log_server);
            }
            continue;
        }
        CHECK(l.log_entry_raw_length == strlen(line), "%s: length %zu", c->name, l.log_entry_raw_length);
        CHECK(strcmp(l.log_rule_file, "/etc/crs/rules/REQUEST-942.conf") == 0, "%s: file '%s'", c->name, l.log_rule_file);
        CHECK(strcmp(l.log_rule_line, "10") == 0, "%s: line '%s'", c->name, l.log_rule_line);
        CHECK(strcmp(l.log_rule_id, "942100") == 0, "%s: id '%s'", c->name, l.log_rule_id);
        CHECK(strcmp(l.log_rule_msg, "SQL Injection") == 0, "%s: msg '%s'", c->name, l.log_rule_msg);
        CHECK(l.log_rule_tags_cnt == 1 && strcmp(l.log_rule_tags, "attack-sqli") == 0, "%s: tags %zu '%s'", c->name,
              l.log_rule_tags_cnt, l.log_rule_tags);
        CHECK(strcmp(l.log_hostname, c->hostname_exp) == 0, "%s: hostname '%s'", c->name, l.log_hostname);
        CHECK(strcmp(l.log_uri, "/") == 0, "%s: uri '%s'", c->name, l.log_uri);
        CHECK(strcmp(l.log_unique_id, c->unique_id_exp) == 0, "%s: unique_id '%s'", c->name, l.log_unique_id);
        if (c->type == LOG_TYPE_NGINX && c->server_exp == NULL) {
            CHECK(l.log_client[0] == '\0' && l.log_server[0] == '\0', "%s: client '%s' server '%s' without a context",
                  c->name, l.log_client, l.log_server);
        }
        if (c->type == LOG_TYPE_NGINX && c->server_exp != NULL) {
            CHECK(strcmp(l.log_server, c->server_exp) == 0, "%s: server '%s'", c->name, l.log_server);
            CHECK(strcmp(l.log_client, "192.0.2.66") != 0, "%s: client is the fake", c->name);
        }
        else if (c->type == LOG_TYPE_APACHE) {
            CHECK(strcmp(l.log_client, "192.0.2.10:1234") == 0, "%s: client '%s'", c->name, l.log_client);
        }
    }
}

int main(void) {
    test_fake_fields_in_context();
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
        CHECK(l.log_client == NULL || strcmp(l.log_client, "192.0.2.66") != 0, "%s: log_client is the fake", c->name);
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
