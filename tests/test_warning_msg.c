/*
This file is part of the libmsclogparser project.

Apache "Warning." messages: how parse_ap_warning_message() splits the
message into reason, operand and target name. Table driven: one row per
message shape, see the comment at the top of parse_ap_warning_message().

Build and run: make check (or tests/run-tests.sh).
*/

#include "../src/msclogparser.c"
#include "test_util.h"

#define AP_HEAD "[Thu Feb 15 13:07:04.494742 2024] [security2:error] [pid 1:tid 2] [client 192.0.2.10:1234] ModSecurity: "
#define AP_TAIL " [file \"/etc/crs/rules/REQUEST-920.conf\"] [line \"1\"] [id \"920100\"] [hostname \"www.example.test\"] [uri \"/\"] [unique_id \"Zc3\"]"

typedef struct {
    const char *name;
    const char *msg;        // the ModSecurity message, from "Warning."
    const char *reason;
    const char *operand;
    const char *target_name;
    int broken;
} warning_case;

static const warning_case cases[] = {
    // 1. REASON '.'
    { "reason only",
      "Warning. detected XSS using libinjection.",
      "detected XSS using libinjection", "", "", 0 },
    // 2. REASON ' at ' TARGET '.'
    { "reason at target",
      "Warning. Invalid URL Encoding: Non-hexadecimal digits used at REQUEST_URI.",
      "Invalid URL Encoding: Non-hexadecimal digits used", "", "REQUEST_URI", 0 },
    // 3. REASON '"' OPERAND '"' ' at ' TARGET '.'
    { "operand at target",
      "Warning. String match within \"/proxy/ /lock-token/\" at TX:header_name_accept-charset.",
      "String match within", "/proxy/ /lock-token/", "TX:header_name_accept-charset", 0 },
    { "operand with '. ', message ends with '.'",
      "Warning. Pattern match \"a. b\" at ARGS:q.",
      "Pattern match", "a. b", "ARGS:q", 0 },
    // 4. REASON '"' OPERAND '"' ' at ' TARGET '. ' ...: the target ends at the
    //    first ". " after the operand
    { "target before '. '",
      "Warning. CC# match \"x\" at ARGS:q. [offset \"1\"]",
      "CC# match", "x", "ARGS:q", 0 },
    { "operand with '. ', target before '. '",
      "Warning. CC# match \"a. b\" at ARGS:q. [offset \"1\"]",
      "CC# match", "a. b", "ARGS:q", 0 },
    { "operand with several '. ', target before '. '",
      "Warning. CC# match \"a. b. c. \" at ARGS:q. [offset \"1\"]",
      "CC# match", "a. b. c. ", "ARGS:q", 0 },
    { "operand with '. ', no '. ' after the target",
      "Warning. CC# match \"a. b\" at ARGS:q [offset \"1\"]",
      "CC# match", "a. b", "", 0 },
    // REASON '"' PATTERN '"' ' against ' '"' TARGET_NAME '"' required.
    { "against",
      "Warning. Match of \"rx ^x\" against \"REQUEST_HEADERS:Host\" required.",
      "Match of", "rx ^x", "REQUEST_HEADERS:Host", 0 },
    { "against, pattern with '. '",
      "Warning. Match of \"rx a. b\" against \"ARGS:q\" required.",
      "Match of", "rx a. b", "ARGS:q", 0 },
};

int main(void) {
    size_t n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        const warning_case *c = &cases[i];
        char line[1024];
        snprintf(line, sizeof(line), "%s%s%s", AP_HEAD, c->msg, AP_TAIL);
        logdata l;
        memset(&l, '\0', sizeof(l));
        parse(line, strlen(line), LOG_TYPE_APACHE, &l);
        CHECK(l.entry_is_modsecline == 1, "%s: not a modsec line", c->name);
        CHECK(l.entry_is_broken == c->broken, "%s: broken=%d", c->name, l.entry_is_broken);
        CHECK(strcmp(l.log_modsec_reason, c->reason) == 0, "%s: reason '%s'", c->name, l.log_modsec_reason);
        CHECK(strcmp(l.log_modsec_operand, c->operand) == 0, "%s: operand '%s'", c->name, l.log_modsec_operand);
        CHECK(strcmp(l.log_modsec_target_name, c->target_name) == 0, "%s: target_name '%s'", c->name, l.log_modsec_target_name);
        CHECK(strcmp(l.log_rule_id, "920100") == 0, "%s: id '%s'", c->name, l.log_rule_id);
    }
    printf("test_warning_msg: %zu cases\n", n);
    return test_result("test_warning_msg");
}
