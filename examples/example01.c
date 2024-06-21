#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "msclogparser.h"

char typeoflog[][50] = {
    "Unknown",
    "Warning",
    "Access denied",
    "Request body error",
    "Rule error"
};

int main(int argc, char ** argv) {

    if (argc < 3) {
        printf("Argument missing\n");
        return 1;
    }

    FILE * fp;
    loglinetype t;

    if (strcmp(argv[2], "apache") == 0) {
        t = LOG_TYPE_APACHE;
    }
    else if (strcmp(argv[2], "nginx") == 0) {
        t = LOG_TYPE_NGINX;
    }
    else {
        printf("Invalid logtype\n");
        return 2;
    }

    logdata l;

    fp = fopen(argv[1], "r");
    if (fp == NULL) {
        printf("Can't open file: '%s'\n", argv[1]);
        return 2;
    }

    char line[4096] = {0};
    size_t len      = 0;
    size_t li       = 0;
    while (fgets (line, 4095, fp) != NULL) {
        len = strlen(line);
        if (len > 0) {
            printf("Nr: %zu\n", li++);
            memset(&l, '\0', sizeof(logdata));
            l.entry_is_modsecline = 0;
            parse(line, len, t, &l);
            if (l.entry_is_modsecline == 1) {
                printf("Type of log: '%s'\n", typeoflog[l.log_entry_class]);
                if (l.entry_is_broken == 1) {
                    printf("Errcnt: %d\n", l.log_entry_errors_cnt);
                    if (l.log_entry_errors_cnt > 0) {
                        // reset errpool ptr
                        l.lineerrpool.currptr = l.lineerrpool.pool;
                        for (int c=0; c < l.log_entry_errors_cnt; c++) {
                            msclogerr err;
                            read_msclog_err(&l.lineerrpool, &err);
                            printf("%s - %zu:%zu\n", err.errmsg, *err.startpos, *err.endpos);
                        }
                    }
                    printf("%s", line);
                }
                printf("date: '%s'\n", l.log_date_iso);
                printf("ts: '%lf'\n", l.log_date_timestamp);
                printf("client: '%s'\n", l.log_client);
                printf("msg: '%s'\n", l.log_modsec_msg);
                printf("msgreason: '%s'\n", l.log_modsec_reason);
                printf("msgop: '%s'\n", l.log_modsec_operator);
                printf("msgoperand: '%s'\n", l.log_modsec_operand);
                printf("msgtrgname: '%s'\n", l.log_modsec_target_name);
                printf("msgtrgvalue: '%s'\n", l.log_modsec_target_value);
                printf("rule err: '%s'\n", l.log_modsec_process_error);
                printf(" file: '%s'\n line: '%s'\n id: '%s'\n rev: '%s'\n msg: '%s'\n data: '%s'\n severity: '%s'\n version: '%s'\n maturity: '%s'\n accuracy: '%s'\n",
                    l.log_rule_file,
                    l.log_rule_line,
                    l.log_rule_id,
                    l.log_rule_rev,
                    l.log_rule_msg,
                    l.log_rule_data,
                    l.log_rule_severity,
                    l.log_rule_version,
                    l.log_rule_maturity,
                    l.log_rule_accuracy
                );
                printf(" tagcnt: '%zu'\n", l.log_rule_tags_cnt);
                if (l.log_rule_tags_cnt > 0) {
                    printf(" tags:");
                    for (size_t ti = 0; ti < l.log_rule_tags_cnt; ti++) {
                        printf(" '%s'", l.log_rule_tags);
                        l.log_rule_tags += strlen(l.log_rule_tags) + 1;
                    }
                    printf("\n");
                }
                printf(" hostname: '%s'\n", l.log_hostname);
                printf(" uri: '%s'\n", l.log_uri);
                printf(" unique_id: '%s'\n", l.log_unique_id);
            }
            else {
                printf("Not a modsecurity line\n");
            }
            printf("======\n");
            memset(line, '\0', 4096);
        }
    }

    fclose(fp);


    return 0;

}