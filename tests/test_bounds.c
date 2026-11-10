/*
This file is part of the libmsclogparser project.

Bounds tests: oversized fields must be truncated (and the line marked
as broken), never written past the stack buffers or the pools.

Build and run: make check (or tests/run-tests.sh). The same checks
run with tiny buffers too, see tests/test_bounds_tiny.c.
*/

#include <stdarg.h>
#include <stdint.h>

#include "../src/msclogparser.c"
#include "test_util.h"

#define AP_HEAD "[Thu Feb 15 13:07:04.494742 2024] [security2:error] [pid 1:tid 2] [client 192.0.2.10:1234] ModSecurity: "
#define AP_TAIL " [hostname \"www.example.test\"] [uri \"/index.php\"] [unique_id \"Zc3-aHFzNBf8HIsK4ZQ\"]"
#define AP_NOSPACE "[Thu Feb 15 13:07:04.494742 2024] [security2:error] [pid 1:tid 2] [client 192.0.2.10:1234] ModSecurity:"
#define NGX_NOSPACE "2022/12/20 17:04:13 [info] 1#1: *1 ModSecurity:"
#define NGX_HEAD "2022/12/20 17:04:13 [info] 1#1: *1 ModSecurity: "
#define NGX_TAIL " [hostname \"192.0.2.1\"] [uri \"/index.php\"] [unique_id \"168142074224.426959\"], client: 192.0.2.10, server: www.example.test, request: \"GET / HTTP/1.1\", host: \"www.example.test\""
#define FIELDS " [file \"/etc/crs/rules/REQUEST-942.conf\"] [line \"92\"] [id \"942100\"] [msg \"SQL Injection Attack\"] [severity \"CRITICAL\"]"

// with tiny (overridden) buffers the pools are full early, the values
// and the error messages are checked only with the default sizes
#define DEFAULT_SIZES (sizeof(((logdata *)0)->datapool.pool) >= 8192 && MSCLOG_TBUFF_SIZE >= 4096)
#define CHECKV(cond, ...) do { if (DEFAULT_SIZES) CHECK(cond, __VA_ARGS__); } while (0)

// repeat ch n times
static char * rep(char ch, size_t n) {
    char *s = malloc(n + 1);
    memset(s, ch, n);
    s[n] = '\0';
    return s;
}

// concatenate the strings, the list ends with NULL
static char * cat(const char *first, ...) {
    va_list ap;
    size_t len = 0;
    const char *s;
    va_start(ap, first);
    for (s = first; s != NULL; s = va_arg(ap, const char *)) len += strlen(s);
    va_end(ap);
    char *r = malloc(len + 1), *p = r;
    va_start(ap, first);
    for (s = first; s != NULL; s = va_arg(ap, const char *)) { size_t l = strlen(s); memcpy(p, s, l); p += l; }
    va_end(ap);
    *p = '\0';
    return r;
}

// every field must be a string inside the data pool, or an empty string
static void check_invariants(const char *name, logdata *l) {
    const size_t poolsize = sizeof(l->datapool.pool);
    const char *pool = l->datapool.pool;
    CHECK(l->datapool.offset <= poolsize, "%s: datapool offset %zu", name, l->datapool.offset);
    CHECK(l->lineerrpool.offset <= poolsize, "%s: lineerrpool offset %zu", name, l->lineerrpool.offset);
    for (int f = 0; f <= LOGFIELD_LOG_UNIQUE_ID; f++) {
        if (f == LOGFIELD_LOG_DATE_TIMESTAMP) continue;
        const char *p = l->fields[f];
        CHECK(p != NULL, "%s: field %d is NULL", name, f);
        if (p == NULL) continue;
        if (p >= pool && p < pool + poolsize) {
            CHECK(memchr(p, '\0', pool + poolsize - p) != NULL, "%s: field %d is not terminated in the pool", name, f);
        }
        else {
            CHECKV(p[0] == '\0', "%s: field %d is outside of the pool", name, f);
        }
    }
    // the tags are read as a sequence from the pool
    const char *t = l->log_rule_tags;
    for (size_t i = 0; i < l->log_rule_tags_cnt; i++) {
        CHECK(t >= pool && t < pool + poolsize, "%s: tag %zu is outside of the pool", name, i);
        if (!(t >= pool && t < pool + poolsize)) break;
        const char *e = memchr(t, '\0', pool + poolsize - t);
        CHECK(e != NULL, "%s: tag %zu is not terminated in the pool", name, i);
        if (e == NULL) break;
        t = e + 1;
    }
}

// the error messages and their positions can be read back from the error
// pool, and the positions are aligned for size_t
static void check_errors(const char *name, logdata *l) {
    const char *pool = l->lineerrpool.pool;
    const char *end = pool + sizeof(l->lineerrpool.pool);
    l->lineerrpool.currptr = l->lineerrpool.pool;
    for (int c = 0; c < l->log_entry_errors_cnt; c++) {
        msclogerr err;
        read_msclog_err(&l->lineerrpool, &err);
        CHECK(err.errmsg >= pool && err.errmsg < end, "%s: error %d is outside of the pool", name, c);
        CHECK((const char *)(err.endpos + 1) <= end, "%s: error %d positions are outside of the pool", name, c);
        CHECK((uintptr_t)err.startpos % _Alignof(size_t) == 0 && (uintptr_t)err.endpos % _Alignof(size_t) == 0,
              "%s: error %d positions are not aligned", name, c);
        if ((const char *)(err.endpos + 1) > end) break;
        CHECK(*err.startpos <= l->log_entry_raw_length && *err.endpos <= l->log_entry_raw_length,
              "%s: error %d positions %zu, %zu", name, c, *err.startpos, *err.endpos);
    }
}

static void parse_line(const char *name, const char *src, loglinetype lt, logdata *l) {
    // exact size copy, parse() writes the terminating '\0'
    size_t len = strlen(src);
    char *line = malloc(len + 1);
    memcpy(line, src, len + 1);
    memset(l, '\0', sizeof(logdata));
    parse(line, len, lt, l);
    check_invariants(name, l);
    check_errors(name, l);
    free(line);
}

static void test_regular_lines(void) {
    logdata l;
    char *s;

    s = cat(AP_HEAD, "Warning. Matched \"Operator `Rx' with parameter `x' against variable `ARGS:q' (Value: `1 or 1=1' )",
            FIELDS, " [tag \"application-multi\"] [tag \"attack-sqli\"]", AP_TAIL, NULL);
    parse_line("apache regular", s, LOG_TYPE_APACHE, &l);
    CHECKV(l.entry_is_modsecline == 1 && l.entry_is_broken == 0, "apache regular: modsec=%d broken=%d", l.entry_is_modsecline, l.entry_is_broken);
    CHECKV(strcmp(l.log_client, "192.0.2.10:1234") == 0, "apache regular: client '%s'", l.log_client);
    CHECKV(strcmp(l.log_rule_id, "942100") == 0, "apache regular: id '%s'", l.log_rule_id);
    CHECKV(strcmp(l.log_rule_msg, "SQL Injection Attack") == 0, "apache regular: msg '%s'", l.log_rule_msg);
    CHECKV(l.log_rule_tags_cnt == 2, "apache regular: tags %zu", l.log_rule_tags_cnt);
    CHECKV(strcmp(l.log_uri, "/index.php") == 0, "apache regular: uri '%s'", l.log_uri);
    CHECKV(strcmp(l.log_unique_id, "Zc3-aHFzNBf8HIsK4ZQ") == 0, "apache regular: unique_id '%s'", l.log_unique_id);
    free(s);

    s = cat(NGX_HEAD, "Warning. Matched \"Operator `Rx' with parameter `x' against variable `ARGS:q' (Value: `1' )",
            FIELDS, NGX_TAIL, NULL);
    parse_line("nginx regular", s, LOG_TYPE_NGINX, &l);
    CHECKV(l.entry_is_modsecline == 1 && l.entry_is_broken == 0, "nginx regular: modsec=%d broken=%d", l.entry_is_modsecline, l.entry_is_broken);
    CHECKV(strcmp(l.log_client, "192.0.2.10") == 0, "nginx regular: client '%s'", l.log_client);
    CHECKV(strcmp(l.log_modsec_target_value, "1") == 0, "nginx regular: value '%s'", l.log_modsec_target_value);
    CHECKV(strcmp(l.log_rule_id, "942100") == 0, "nginx regular: id '%s'", l.log_rule_id);
    free(s);
}

static void test_long_message(void) {
    logdata l;
    // the ModSecurity message (before ' [file ') is longer than MSCLOG_TBUFF_SIZE
    size_t sizes[] = { 4100, 5000, 7000, 20000 };
    for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
        char *v = rep('A', sizes[i]);
        char *s = cat(AP_HEAD, "Warning. Matched \"Operator `Rx' with parameter `x' against variable `ARGS:q' (Value: `", v, "' )",
                      FIELDS, AP_TAIL, NULL);
        parse_line("long message", s, LOG_TYPE_APACHE, &l);
        CHECK(l.entry_is_broken == 1, "long message %zu: not broken", sizes[i]);
        CHECK(strlen(l.log_modsec_msg) < MSCLOG_TBUFF_SIZE, "long message %zu: msg length %zu", sizes[i], strlen(l.log_modsec_msg));
        CHECK(l.log_modsec_msg_length == strlen(l.log_modsec_msg), "long message %zu: msg_length %zu", sizes[i], l.log_modsec_msg_length);
        CHECKV(has_error(&l, "ModSecurity message is truncated!"), "long message %zu: no error", sizes[i]);
        free(s);
        s = cat(NGX_HEAD, "Warning. Matched \"Operator `Rx' with parameter `x' against variable `ARGS:q' (Value: `", v, "' )",
                FIELDS, NGX_TAIL, NULL);
        parse_line("long message nginx", s, LOG_TYPE_NGINX, &l);
        CHECK(l.entry_is_broken == 1, "long message nginx %zu: not broken", sizes[i]);
        CHECK(strlen(l.log_modsec_msg) < MSCLOG_TBUFF_SIZE, "long message nginx %zu: msg length %zu", sizes[i], strlen(l.log_modsec_msg));
        free(s);
        free(v);
    }
}

static void test_many_tags(void) {
    logdata l;
    // 400 tags, 40 bytes each: more than the data pool
    char *tags = malloc(2000 * 64), *p = tags;
    for (int i = 0; i < 400; i++) {
        p += snprintf(p, tags + 2000 * 64 - p, " [tag \"t%03dxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"]", i);
    }
    char *s = cat(AP_HEAD, "Warning. Pattern match \"x\" at ARGS:q.", FIELDS, tags, AP_TAIL, NULL);
    parse_line("many tags", s, LOG_TYPE_APACHE, &l);
    CHECK(l.entry_is_broken == 1, "many tags: not broken");
    CHECK(l.log_rule_tags_cnt < 400, "many tags: tag count %zu", l.log_rule_tags_cnt);
    free(s);

    // tags of every length: some of them fill the pool exactly
    for (int v = 1; v <= 48; v++) {
        char *tv = rep('t', v);
        p = tags;
        for (int i = 0; i < 2000; i++) {
            p += snprintf(p, tags + 2000 * 64 - p, " [tag \"%s\"]", tv);
        }
        s = cat(AP_HEAD, "Warning. Pattern match \"x\" at ARGS:q.", FIELDS, tags, AP_TAIL, NULL);
        parse_line("many tags, exact fit", s, LOG_TYPE_APACHE, &l);
        free(s);
        free(tv);
    }
    free(tags);
}

static void test_long_client(void) {
    logdata l;
    char *c = rep('9', 200);
    char *s = cat("[Thu Feb 15 13:07:04.494742 2024] [security2:error] [pid 1:tid 2] [client 192.0.2.", c, "] ModSecurity: ",
                  "Warning. Pattern match \"x\" at ARGS:q.", FIELDS, AP_TAIL, NULL);
    parse_line("long client", s, LOG_TYPE_APACHE, &l);
    CHECK(strlen(l.log_client) < 50, "long client: client length %zu", strlen(l.log_client));
    CHECKV(has_error(&l, "[client] field is truncated!"), "long client: no error");
    free(s);
    // nginx: the address is used up to 255 bytes, a longer one is dropped
    s = cat(NGX_HEAD, "Warning. Matched \"Operator `Rx' with parameter `x' against variable `ARGS:q' (Value: `1' )",
            FIELDS, " [hostname \"192.0.2.1\"] [uri \"/\"] [unique_id \"1\"], client: 192.0.2.", c, ", server: www.example.test", NULL);
    parse_line("long client nginx", s, LOG_TYPE_NGINX, &l);
    CHECKV(strlen(l.log_client) == 208 && strncmp(l.log_client, "192.0.2.999", 11) == 0, "long client nginx: client length %zu", strlen(l.log_client));
    CHECKV(strcmp(l.log_server, "www.example.test") == 0, "long client nginx: server '%s'", l.log_server);
    free(s);
    free(c);
    c = rep('9', 300);
    s = cat(NGX_HEAD, "Warning. Matched \"Operator `Rx' with parameter `x' against variable `ARGS:q' (Value: `1' )",
            FIELDS, " [hostname \"192.0.2.1\"] [uri \"/\"] [unique_id \"1\"], client: 192.0.2.", c, ", server: www.example.test", NULL);
    parse_line("too long client nginx", s, LOG_TYPE_NGINX, &l);
    CHECK(strcmp(l.log_client, "") == 0, "too long client nginx: client length %zu", strlen(l.log_client));
    CHECKV(strcmp(l.log_server, "www.example.test") == 0, "too long client nginx: server '%s'", l.log_server);
    free(s);
    free(c);
}

static void test_long_rule_error(void) {
    logdata l;
    char *v = rep('E', 6000);
    char *s = cat(AP_HEAD, "Rule 7f0 - Execution error - PCRE limits exceeded (-8): ", v,
                  " [id \"942100\"] [file \"/etc/crs/rules/REQUEST-942.conf\"] [line \"92\"] ", v, AP_TAIL, NULL);
    parse_line("long rule error", s, LOG_TYPE_APACHE, &l);
    CHECK(strlen(l.log_modsec_msg) < MSCLOG_TBUFF_SIZE, "long rule error: msg length %zu", strlen(l.log_modsec_msg));
    CHECK(l.entry_is_broken == 1, "long rule error: not broken");
    free(s);

    // short message, long process error after [line]
    s = cat(AP_HEAD, "Rule 7f0 - Execution error - PCRE limits exceeded (-8): x",
            " [id \"942100\"] [file \"/etc/crs/rules/REQUEST-942.conf\"] [line \"92\"] ", v, AP_TAIL, NULL);
    parse_line("long process error", s, LOG_TYPE_APACHE, &l);
    CHECK(strlen(l.log_modsec_process_error) < MSCLOG_TBUFF_SIZE, "long process error: length %zu", strlen(l.log_modsec_process_error));
    CHECK(l.entry_is_broken == 1, "long process error: not broken");
    free(s);

    // long Request body and Audit log messages
    s = cat(AP_HEAD, "Request body (Content-Length) is larger than the configured limit ", v, AP_TAIL, NULL);
    parse_line("long request body", s, LOG_TYPE_APACHE, &l);
    CHECK(strlen(l.log_modsec_msg) < MSCLOG_TBUFF_SIZE, "long request body: msg length %zu", strlen(l.log_modsec_msg));
    free(s);
    s = cat(AP_HEAD, "Audit log: Failed to lock global mutex ", v, AP_TAIL, NULL);
    parse_line("long audit log", s, LOG_TYPE_APACHE, &l);
    CHECK(strlen(l.log_modsec_msg) < MSCLOG_TBUFF_SIZE, "long audit log: msg length %zu", strlen(l.log_modsec_msg));
    free(s);
    free(v);
}

static void test_short_values(void) {
    logdata l;
    char *s;

    // empty [uri] value right before [unique_id]
    s = cat(AP_HEAD, "Warning. Pattern match \"x\" at ARGS:q.", FIELDS,
            " [hostname \"www.example.test\"] [uri \"[unique_id \"Zc3\"]", NULL);
    parse_line("empty uri", s, LOG_TYPE_APACHE, &l);
    CHECKV(l.log_uri[0] == '\0', "empty uri: uri '%s'", l.log_uri);
    CHECKV(has_error(&l, "[uri] field is truncated!"), "empty uri: no error");
    free(s);

    // '" against "' at the end of the message, the target is shorter than " required."
    s = cat(AP_HEAD, "Warning. Match of \"rx x\" against \"b.", FIELDS, AP_TAIL, NULL);
    parse_line("short against", s, LOG_TYPE_APACHE, &l);
    CHECKV(l.log_modsec_target_name[0] == '\0', "short against: target '%s'", l.log_modsec_target_name);
    free(s);

    // '"' right after "Warning. "
    s = cat(AP_HEAD, "Warning. \"x\" at ARGS:q.", FIELDS, AP_TAIL, NULL);
    parse_line("quote after warning", s, LOG_TYPE_APACHE, &l);
    CHECKV(l.log_modsec_reason[0] == '\0', "quote after warning: reason '%s'", l.log_modsec_reason);
    CHECKV(strcmp(l.log_modsec_operand, "x") == 0, "quote after warning: operand '%s'", l.log_modsec_operand);
    free(s);

    // message is "Warning.." only
    s = cat(AP_HEAD, "Warning..", FIELDS, AP_TAIL, NULL);
    parse_line("warning dot", s, LOG_TYPE_APACHE, &l);
    CHECKV(l.log_modsec_reason[0] == '\0', "warning dot: reason '%s'", l.log_modsec_reason);
    free(s);

    // too short Nginx messages
    s = cat(NGX_HEAD, "Warning.", FIELDS, NGX_TAIL, NULL);
    parse_line("short nginx warning", s, LOG_TYPE_NGINX, &l);
    CHECKV(has_error(&l, "Warning message is too short to parse!"), "short nginx warning: no error");
    free(s);
    s = cat(NGX_HEAD, "Access Matched", FIELDS, NGX_TAIL, NULL);
    parse_line("short nginx access", s, LOG_TYPE_NGINX, &l);
    CHECKV(has_error(&l, "Warning message is too short to parse!"), "short nginx access: no error");
    free(s);

    // the message doesn't end with '.', the target ends at the first ". "
    s = cat(AP_HEAD, "Warning. CC# match \"x\" at ARGS:q. [offset \"1\"]", FIELDS, AP_TAIL, NULL);
    parse_line("target before dot", s, LOG_TYPE_APACHE, &l);
    CHECKV(strcmp(l.log_modsec_target_name, "ARGS:q") == 0, "target before dot: target '%s'", l.log_modsec_target_name);
    free(s);

    // empty field values
    s = cat(AP_HEAD, "Warning. Pattern match \"x\" at ARGS:q. [file \"\"] [line \"\"] [id \"\"] [msg \"\"] [tag \"\"]", AP_TAIL, NULL);
    parse_line("empty values", s, LOG_TYPE_APACHE, &l);
    CHECKV(l.log_rule_id[0] == '\0', "empty values: id '%s'", l.log_rule_id);
    free(s);

    // the line ends inside a field name
    s = cat(AP_HEAD, "Warning. Pattern match \"x\" at ARGS:q. [file \"/x.conf\"] [li", NULL);
    parse_line("cut field name", s, LOG_TYPE_APACHE, &l);
    free(s);
}

static void test_truncated_tail(void) {
    logdata l;
    char *s, *v = rep('h', MSCLOG_TLEN_SIZE + 500), *ok = rep('h', MSCLOG_TLEN_SIZE);
    const char *msg = "Warning. Pattern match \"x\" at ARGS:q.";
    const char *ap_start = " [hostname \"www.example.test\"] [uri \"/\"] [unique_id \"Zc3\"]";

    // longer than the buffer: the value is cut and the caller is told
    s = cat(AP_HEAD, msg, FIELDS, " [hostname \"", v, "\"] [uri \"/\"] [unique_id \"Zc3\"]", NULL);
    parse_line("long hostname", s, LOG_TYPE_APACHE, &l);
    CHECKV(has_error(&l, "[hostname] field is truncated!"), "long hostname: no error");
    CHECKV(strlen(l.log_hostname) == MSCLOG_TLEN_SIZE, "long hostname: length %zu", strlen(l.log_hostname));
    free(s);
    s = cat(AP_HEAD, msg, FIELDS, " [hostname \"www.example.test\"] [uri \"/\"] [unique_id \"", v, "\"]", NULL);
    parse_line("long unique_id", s, LOG_TYPE_APACHE, &l);
    CHECKV(has_error(&l, "[unique_id] field is truncated!"), "long unique_id: no error");
    free(s);
    s = cat(AP_HEAD, msg, FIELDS, " [hostname \"www.example.test\"] [uri \"/", v, "\"] [unique_id \"Zc3\"]", NULL);
    parse_line("long uri", s, LOG_TYPE_APACHE, &l);
    CHECKV(has_error(&l, "[uri] field is truncated!"), "long uri: no error");
    CHECKV(strlen(l.log_uri) == MSCLOG_TLEN_SIZE, "long uri: length %zu", strlen(l.log_uri));
    free(s);
    s = cat(NGX_HEAD, "Warning. Matched \"Operator `Rx' with parameter `x' against variable `ARGS:q' (Value: `1' )", FIELDS,
            " [hostname \"\"] [uri \"/\"] [unique_id \"1\"], client: 192.0.2.10, server: www.example.test, request: \"GET / HTTP/1.1\", host: \"", v, "\"", NULL);
    parse_line("long host", s, LOG_TYPE_NGINX, &l);
    CHECKV(has_error(&l, "[host] field is truncated!"), "long host: no error");
    free(s);

    // exactly as long as the buffer: complete, no error
    // (the uri is copied together with its closing '"] ', so it is 3 shorter)
    char *ok3 = rep('u', MSCLOG_TLEN_SIZE - 3);
    s = cat(AP_HEAD, msg, FIELDS, " [hostname \"", ok, "\"] [uri \"", ok3, "\"] [unique_id \"", ok, "\"]", NULL);
    parse_line("exact fit tail", s, LOG_TYPE_APACHE, &l);
    CHECKV(l.entry_is_broken == 0 && l.log_entry_errors_cnt == 0, "exact fit tail: broken=%d errors=%d", l.entry_is_broken, l.log_entry_errors_cnt);
    free(s);

    // Request body and Audit log: longer than MSCLOG_TBUFF_SIZE
    free(v);
    v = rep('E', 6000);
    s = cat(AP_HEAD, "Request body (Content-Length) is larger than the configured limit ", v, ap_start, NULL);
    parse_line("long request body", s, LOG_TYPE_APACHE, &l);
    CHECKV(has_error(&l, "ModSecurity message is truncated!"), "long request body: no error");
    free(s);
    s = cat(AP_HEAD, "Audit log: Failed to lock global mutex ", v, ap_start, NULL);
    parse_line("long audit log", s, LOG_TYPE_APACHE, &l);
    CHECKV(has_error(&l, "ModSecurity message is truncated!"), "long audit log: no error");
    free(s);

    // short ones are complete
    s = cat(AP_HEAD, "Audit log: Failed to lock global mutex", ap_start, NULL);
    parse_line("short audit log", s, LOG_TYPE_APACHE, &l);
    CHECKV(l.entry_is_broken == 0, "short audit log: broken");
    free(s);
    free(v);
    free(ok);
    free(ok3);
}

// partial matches of a field name must not be searched again and again:
// a line of this length took tens of seconds with the quadratic search
static void test_partial_field_runs(void) {
    logdata l;
    size_t n = 320000;   // ' [l' * n = 960 KB
    char *run = malloc(n * 3 + 1), *p = run;
    for (size_t i = 0; i < n; i++) { memcpy(p, " [l", 3); p += 3; }
    *p = '\0';

    char *s = cat(AP_HEAD, "Warning. x [file \"/x\"]", run, AP_TAIL, NULL);
    clock_t start = clock();
    parse_line("partial field run", s, LOG_TYPE_APACHE, &l);
    double secs = (double)(clock() - start) / CLOCKS_PER_SEC;
    CHECK(secs < 3.0, "partial field run: %.2f s", secs);
    CHECKV(l.entry_is_modsecline == 1, "partial field run: not a modsecurity line");
    CHECKV(strcmp(l.log_unique_id, "Zc3-aHFzNBf8HIsK4ZQ") == 0, "partial field run: unique_id '%s'", l.log_unique_id);
    free(s);
    free(run);
}

#define CHECK_SAME(name, got, want) CHECKV(strcmp(got, want) == 0, "%s: changed to '%s'", name, got)

// is every byte sequence of the string a complete UTF-8 character?
static int is_utf8(const char *str) {
    const unsigned char *s = (const unsigned char *)str;
    while (*s != '\0') {
        int more = (*s < 0x80) ? 0 : ((*s & 0xE0) == 0xC0) ? 1 : ((*s & 0xF0) == 0xE0) ? 2 : ((*s & 0xF8) == 0xF0) ? 3 : -1;
        if (more < 0) return 0;
        s++;
        for (; more > 0; more--, s++) {
            if ((*s & 0xC0) != 0x80) return 0;
        }
    }
    return 1;
}

static void check_utf8(const char *name, const char *src, loglinetype lt, logdata *l) {
    parse_line(name, src, lt, l);
    for (int f = 0; f <= LOGFIELD_LOG_SERVER; f++) {
        if (f == LOGFIELD_LOG_DATE_TIMESTAMP || f == LOGFIELD_LOG_RULE_TAGS) continue;
        CHECK(is_utf8(l->fields[f]), "%s: field %d is cut in a character", name, f);
    }
    const char *t = l->log_rule_tags;
    for (size_t i = 0; i < l->log_rule_tags_cnt; i++) {
        CHECK(is_utf8(t), "%s: tag %zu is cut in a character", name, i);
        t += strlen(t) + 1;
    }
}

// n bytes of padding, then the character until the value is over the limit
static char * utf8_value(size_t pad, const char *ch, size_t limit) {
    size_t width = strlen(ch), count = limit / width + 4;
    char *v = malloc(pad + count * width + 1);
    memset(v, 'x', pad);
    for (size_t i = 0; i < count; i++) memcpy(v + pad + i * width, ch, width);
    v[pad + count * width] = '\0';
    return v;
}

// a limit must not cut a multibyte character, that makes the field invalid
static void test_cut_utf8(void) {
    static const char * const chars[] = { "\xc3\xa9", "\xe2\x82\xac", "\xf0\x9f\x98\x80" };
    static const struct { const char *name; size_t limit; int field; } fields[] = {
        { "file", 256, LOGFIELD_LOG_RULE_FILE }, { "msg", 512, LOGFIELD_LOG_RULE_MSG },
        { "data", 1024, LOGFIELD_LOG_RULE_DATA }, { "tag", 50, LOGFIELD_LOG_RULE_TAGS }
    };
    logdata l;

    for (size_t c = 0; c < sizeof(chars) / sizeof(chars[0]); c++) {
        // a fixed offset of the parser falls in the character
        char *h = cat(AP_HEAD, "Warning.", chars[c], " rest of it", FIELDS, AP_TAIL, NULL);
        check_utf8("offset", h, LOG_TYPE_APACHE, &l);
        CHECK_SAME("offset", l.log_modsec_reason, " rest of it");
        free(h);
        h = cat(AP_HEAD, "Warning.", chars[c], " x at ARGS:a.", FIELDS, AP_TAIL, NULL);
        check_utf8("at offset", h, LOG_TYPE_APACHE, &l);
        CHECK_SAME("at offset", l.log_modsec_reason, " x");
        free(h);
        h = cat(AP_HEAD, "Warning.", chars[c], " x \"q\" at ARGS:a.", FIELDS, AP_TAIL, NULL);
        check_utf8("quote start", h, LOG_TYPE_APACHE, &l);
        CHECK_SAME("quote start", l.log_modsec_reason, " x");
        free(h);
        // the target is cut 11 bytes before the end of the message
        h = cat(AP_HEAD, "Warning. Pattern match \"a\" against \"abc", chars[c], "zzzzzzzzz.", FIELDS, AP_TAIL, NULL);
        check_utf8("against tail", h, LOG_TYPE_APACHE, &l);
        CHECK_SAME("against tail", l.log_modsec_target_name, "abc");
        free(h);
        // a tail slice ends one byte before the quote, or before the end of the message
        h = cat(AP_HEAD, "Warning. x", chars[c], "\"q\" at ARGS:a.", FIELDS, AP_TAIL, NULL);
        check_utf8("quote offset", h, LOG_TYPE_APACHE, &l);
        CHECK_SAME("quote offset", l.log_modsec_reason, "x");
        free(h);
        h = cat(NGX_HEAD, "Warning. x", chars[c], FIELDS, NGX_TAIL, NULL);
        check_utf8("nginx tail slice", h, LOG_TYPE_NGINX, &l);
        CHECK_SAME("nginx tail slice", l.log_modsec_reason, "x");
        free(h);
        // the fixed offsets at the start of the other messages
        h = cat(NGX_NOSPACE, chars[c], " Warning. x.", FIELDS, NGX_TAIL, NULL);
        check_utf8("message start", h, LOG_TYPE_NGINX, &l);
        CHECK_SAME("message start", l.log_modsec_msg, " Warning. x.");
        free(h);
        h = cat(AP_HEAD, "Rule 7f12340000 [id \"1\"][file \"/x\"][line \"1\"]", " ", chars[c], "- Execution error ", AP_TAIL, NULL);
        check_utf8("rule error start", h, LOG_TYPE_APACHE, &l);
        CHECK_SAME("rule error start", l.log_modsec_process_error, "- Execution error");
        free(h);
        h = cat(AP_NOSPACE, chars[c], " Rule 7f [id \"1\"][file \"/x\"][line \"1\"] - x ", AP_TAIL, NULL);
        check_utf8("rule message start", h, LOG_TYPE_APACHE, &l);
        CHECK_SAME("rule message start", l.log_modsec_msg, " Rule 7f");
        free(h);
        h = cat(AP_NOSPACE, chars[c], " Request body: x", AP_TAIL, NULL);
        check_utf8("request body start", h, LOG_TYPE_APACHE, &l);
        CHECK_SAME("request body start", l.log_modsec_msg, " Request body: x");
        free(h);
        h = cat(AP_NOSPACE, chars[c], " Audit log: x", AP_TAIL, NULL);
        check_utf8("audit log start", h, LOG_TYPE_APACHE, &l);
        CHECK_SAME("audit log start", l.log_modsec_msg, " Audit log: x");
        free(h);
        // ... and the fixed offset before the tail
        h = cat(AP_HEAD, "Audit log: x. ", chars[c], "[hostname \"h\"] [uri \"/\"] [unique_id \"u\"]", NULL);
        check_utf8("audit log end", h, LOG_TYPE_APACHE, &l);
        CHECK_SAME("audit log end", l.log_modsec_msg, "Audit log: x. ");
        free(h);
        h = cat(AP_HEAD, "Request body: x. ", chars[c], "[hostname \"h\"] [uri \"/\"] [unique_id \"u\"]", NULL);
        check_utf8("request body end", h, LOG_TYPE_APACHE, &l);
        CHECK_SAME("request body end", l.log_modsec_msg, "Request body: x. ");
        free(h);
        h = cat(AP_HEAD, "Rule 7f12340000 ", chars[c], "[id \"1\"][file \"/x\"][line \"1\"] - x ", AP_TAIL, NULL);
        check_utf8("rule message end", h, LOG_TYPE_APACHE, &l);
        CHECK_SAME("rule message end", l.log_modsec_msg, "Rule 7f12340000 ");
        free(h);
        h = cat(NGX_HEAD, "Access ", chars[c], "denied with code 403 (phase 2). Matched x", FIELDS, NGX_TAIL, NULL);
        check_utf8("nginx access offset", h, LOG_TYPE_NGINX, &l);
        CHECK_SAME("nginx access offset", l.log_modsec_reason, "denied with code 403 (phase 2). Matched ");
        free(h);

        for (size_t pad = 0; pad < 4; pad++) {
            for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++) {
                char *v = utf8_value(pad, chars[c], fields[f].limit);
                // only a line with a [file] field reaches the copy of the other fields
                const char *file = strcmp(fields[f].name, "file") != 0 ? " [file \"/x\"]" : "";
                char *s = cat(AP_HEAD, "Warning. x.", file, " [", fields[f].name, " \"", v, "\"]", AP_TAIL, NULL);
                check_utf8(fields[f].name, s, LOG_TYPE_APACHE, &l);
                const char *got = fields[f].field == LOGFIELD_LOG_RULE_TAGS ? l.log_rule_tags : l.fields[fields[f].field];
                CHECKV(got[0] != '\0', "%s: the value is not stored", fields[f].name);
                free(s);
                free(v);
            }
            char *v = utf8_value(pad, chars[c], 4096);
            char *s = cat(AP_HEAD, "Warning. x", v, ".", FIELDS, AP_TAIL, NULL);
            check_utf8("message", s, LOG_TYPE_APACHE, &l);
            free(s);
            s = cat(AP_HEAD, "Rule 7f12340000 [id \"1\"][file \"/x\"][line \"1\"] - ", v, " ", AP_TAIL, NULL);
            check_utf8("rule error", s, LOG_TYPE_APACHE, &l);
            CHECKV(l.log_modsec_process_error[0] != '\0', "rule error: the value is not stored");
            free(s);
            free(v);

            v = utf8_value(pad, chars[c], 2048);
            s = cat(AP_HEAD, "Warning. x.", FIELDS, " [hostname \"h\"] [uri \"", v, "\"] [unique_id \"u\"]", NULL);
            check_utf8("uri", s, LOG_TYPE_APACHE, &l);
            free(s);
            s = cat(AP_HEAD, "Warning. x.", FIELDS, " [hostname \"", v, "\"] [uri \"/\"] [unique_id \"u\"]", NULL);
            check_utf8("hostname", s, LOG_TYPE_APACHE, &l);
            free(s);
            s = cat(NGX_HEAD, "Warning. x.", FIELDS, " [hostname \"\"] [uri \"/\"] [unique_id \"u\"], client: 192.0.2.10, server: s, request: \"GET / HTTP/1.1\", host: \"", v, "\"", NULL);
            check_utf8("nginx host", s, LOG_TYPE_NGINX, &l);
            CHECKV(l.log_hostname[0] != '\0', "nginx host: the value is not stored");
            free(s);
            s = cat(AP_HEAD, "Warning. x.", FIELDS, " [hostname \"h\"] [uri \"/\"] [unique_id \"", v, "\"]", NULL);
            check_utf8("unique_id", s, LOG_TYPE_APACHE, &l);
            free(s);
            free(v);

            v = utf8_value(pad, chars[c], 49);
            s = cat("[Thu Feb 15 13:07:04.494742 2024] [security2:error] [pid 1:tid 2] [client ", v, "] ModSecurity: Warning. x.", FIELDS, AP_TAIL, NULL);
            check_utf8("client", s, LOG_TYPE_APACHE, &l);
            free(s);
            free(v);
        }
    }
}

// a value that ends in the closing delimiter after the cut character is dropped
// is still a cut value
static void test_cut_before_delimiter(void) {
    logdata l;
    char *x = rep('x', 509);
    char *s = cat(AP_HEAD, "Warning. x. [file \"/x\"] [msg \"", x, "\"]\xe2\x82\xac\"]", AP_TAIL, NULL);
    char *want = cat(x, "\"]", NULL);
    parse_line("cut before delimiter", s, LOG_TYPE_APACHE, &l);
    CHECKV(strcmp(l.log_rule_msg, want) == 0, "cut before delimiter: msg '%s'", l.log_rule_msg);
    CHECKV(has_error(&l, "Field [msg] is truncated!"), "cut before delimiter: no error");
    free(s);
    free(want);
    free(x);

    x = rep('x', 2045);
    s = cat(AP_HEAD, "Warning. x.", FIELDS, " [hostname \"h\"] [uri \"", x, "\"]\xe2\x82\xac\"] [unique_id \"u\"]", NULL);
    want = cat(x, "\"]", NULL);
    parse_line("cut uri before delimiter", s, LOG_TYPE_APACHE, &l);
    CHECKV(strcmp(l.log_uri, want) == 0, "cut uri before delimiter: uri '%s'", l.log_uri);
    CHECKV(has_error(&l, "[uri] field is truncated!"), "cut uri before delimiter: no error");
    free(s);
    free(want);
    free(x);
}

// a value that was not cut stays byte-identical, also when it isn't valid UTF-8
static void test_uncut_invalid_bytes(void) {
    static const char * const values[] = { "\xa9" "x caf\xe9", "\xe9", "\xa9", "\xc3", "caf\xe2\x82" };
    logdata l;

    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        const char *v = values[i];
        char *s = cat(AP_HEAD, "Warning. x.", FIELDS, " [hostname \"h\"] [uri \"/caf", v, "\"] [unique_id \"u\"]", NULL);
        char *uri = cat("/caf", v, NULL);
        parse_line("uncut uri end", s, LOG_TYPE_APACHE, &l);
        CHECK_SAME("uncut uri end", l.log_uri, uri);
        free(uri);
        free(s);

        s = cat(AP_HEAD, "Warning. x.", FIELDS, " [hostname \"h\"] [uri \"", v, "\"] [unique_id \"u\"]", NULL);
        parse_line("uncut uri", s, LOG_TYPE_APACHE, &l);
        CHECK_SAME("uncut uri", l.log_uri, v);
        free(s);

        s = cat(AP_HEAD, "Warning. x. [file \"/x\"] [data \"", v, "\"]", AP_TAIL, NULL);
        parse_line("uncut data", s, LOG_TYPE_APACHE, &l);
        CHECK_SAME("uncut data", l.log_rule_data, v);
        free(s);

        // message slices: at the fixed offset and to the end of the message
        char *msg = cat("Warning. ", v, ".", NULL);
        s = cat(AP_HEAD, msg, FIELDS, AP_TAIL, NULL);
        parse_line("uncut slice", s, LOG_TYPE_APACHE, &l);
        CHECK_SAME("uncut slice", l.log_modsec_reason, v);
        free(s);
        s = cat(NGX_HEAD, msg, FIELDS, NGX_TAIL, NULL);
        parse_line("uncut nginx slice", s, LOG_TYPE_NGINX, &l);
        CHECK_SAME("uncut nginx slice", l.log_modsec_reason, v);
        free(s);
        free(msg);

        // up to the fixed " at " offset
        s = cat(AP_HEAD, "Warning. ", v, " at ARGS:", v, ".", FIELDS, AP_TAIL, NULL);
        parse_line("uncut at slice", s, LOG_TYPE_APACHE, &l);
        CHECK_SAME("uncut at slice", l.log_modsec_reason, v);
        CHECK_SAME("uncut at slice target", l.log_modsec_target_name + strlen("ARGS:"), v);
        free(s);

        s = cat(NGX_HEAD, "Warning. Matched \"Operator `Rx' with parameter `x' against variable `ARGS:q' (Value: `", v, "' )", FIELDS, NGX_TAIL, NULL);
        parse_line("uncut target value", s, LOG_TYPE_NGINX, &l);
        CHECK_SAME("uncut target value", l.log_modsec_target_value, v);
        free(s);
    }

    // the limit of copy_str_from_line() stops at the closing '"]', the value isn't cut
    for (size_t len = 1022; len <= 1024; len++) {
        char *v = rep('x', len);
        v[len - 1] = '\xe9';
        char *s = cat(AP_HEAD, "Warning. x. [file \"/x\"] [data \"", v, "\"]", AP_TAIL, NULL);
        parse_line("uncut data at limit", s, LOG_TYPE_APACHE, &l);
        CHECK_SAME("uncut data at limit", l.log_rule_data, v);
        free(s);
        free(v);
    }

    // the [uri] buffer is full before the closing '"]', the value isn't cut
    char *v = rep('x', 2048);
    v[2047] = '\xe9';
    char *s = cat(AP_HEAD, "Warning. x.", FIELDS, " [hostname \"h\"] [uri \"", v, "\"] [unique_id \"u\"]", NULL);
    parse_line("uncut uri at limit", s, LOG_TYPE_APACHE, &l);
    CHECK_SAME("uncut uri at limit", l.log_uri, v);
    free(s);
    free(v);
}

int main(void) {
    test_regular_lines();
    test_long_message();
    test_many_tags();
    test_long_client();
    test_long_rule_error();
    test_short_values();
    test_truncated_tail();
    test_partial_field_runs();
    test_cut_utf8();
    test_cut_before_delimiter();
    test_uncut_invalid_bytes();

    return test_result(DEFAULT_SIZES ? "test_bounds" : "test_bounds (tiny buffers)");
}
