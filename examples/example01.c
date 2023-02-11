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
            l.is_modsecline = 0;
            parse(line, len, t, &l);
            if (l.is_modsecline == 1) {
                printf("Type of log: '%s'\n", typeoflog[l.modseclinetype]);
                if (l.is_broken == 1) {
                    printf("Errcnt: %d\n", l.lineerrcnt);
                    if (l.lineerrcnt > 0) {
                        // reset errpool ptr
                        l.lineerrpool.currptr = l.lineerrpool.pool;
                        for (int c=0; c < l.lineerrcnt; c++) {
                            msclogerr err;
                            read_msclog_err(&l.lineerrpool, &err);
                            printf("%s - %zu:%zu\n", err.errmsg, *err.startpos, *err.endpos);
                        }
                    }
                    printf("%s", line);
                }
                printf("date: '%s'\n", l.date_iso);
                printf("ts: '%lf'\n", l.date_epoch);
                printf("client: '%s'\n", l.client);
                printf("msg: '%s'\n", l.modsecmsg);
                printf("denymsg: '%s'\n", l.modsecdenymsg);
                printf("msgreason: '%s'\n", l.modsecmsgreason);
                printf("msgop: '%s'\n", l.modsecmsgop);
                printf("msgoperand: '%s'\n", l.modsecmsgoperand);
                printf("msgtrgname: '%s'\n", l.modsecmsgtrgname);
                printf("msgtrgvalue: '%s'\n", l.modsecmsgtrgvalue);
                printf("rule err: '%s'\n", l.ruleerror);
                printf(" file: '%s'\n line: '%s'\n id: '%s'\n rev: '%s'\n msg: '%s'\n data: '%s'\n severity: '%s'\n version: '%s'\n maturity: '%s'\n accuracy: '%s'\n",
                    l.file,
                    l.line,
                    l.id,
                    l.rev,
                    l.msg,
                    l.data,
                    l.severity,
                    l.version,
                    l.maturity,
                    l.accuracy
                );
                printf(" tagcnt: '%zu'\n", l.tagcnt);
                if (l.tagcnt > 0) {
                    printf(" tags:");
                    for (size_t ti = 0; ti < l.tagcnt; ti++) {
                        printf(" '%s'", l.tags);
                        l.tags += strlen(l.tags) + 1;
                    }
                    printf("\n");
                }
                printf(" hostname: '%s'\n", l.hostname);
                printf(" uri: '%s'\n", l.uri);
                printf(" unique_id: '%s'\n", l.unique_id);
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