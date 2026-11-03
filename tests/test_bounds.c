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
    s = cat(NGX_HEAD, "Warning. Matched \"Operator `Rx' with parameter `x' against variable `ARGS:q' (Value: `1' )",
            FIELDS, " [hostname \"192.0.2.1\"] [uri \"/\"] [unique_id \"1\"], client: 192.0.2.", c, ", server: www.example.test", NULL);
    parse_line("long client nginx", s, LOG_TYPE_NGINX, &l);
    CHECK(strlen(l.log_client) < 50, "long client nginx: client length %zu", strlen(l.log_client));
    CHECKV(has_error(&l, "client field is truncated!"), "long client nginx: no error");
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

int main(void) {
    test_regular_lines();
    test_long_message();
    test_many_tags();
    test_long_client();
    test_long_rule_error();
    test_short_values();
    test_truncated_tail();

    return test_result(DEFAULT_SIZES ? "test_bounds" : "test_bounds (tiny buffers)");
}
