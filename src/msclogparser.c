/*
This file is part of the libmsclogparser project.

Copyright (c) 2023 Digitalwave

Authors: Ervin Hegedüs <airween@digitalwave.hu>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License version 3
as published by the Free Software Foundation with the addition of the
following permission added to Section 15 as permitted in Section 7(a):
FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
DIGITALWAVE. DIGITALWAVE DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
OF THIRD PARTY RIGHTS

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.

See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program; if not, see http://www.gnu.org/licenses or write to
the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
Boston, MA, 02110-1301 USA, or download the license from the following URL:
https://www.gnu.org/licenses/agpl-3.0.html

The interactive user interfaces in modified source and object code versions
of this program must display Appropriate Legal Notices, as required under
Section 5 of the GNU Affero General Public License.

In accordance with Section 7(b) of the GNU Affero General Public License, a
covered work must show that the log processing was by libmsclogparser.

You can be released from the requirements of the license by purchasing
a commercial license. Buying such a license is mandatory as soon as you
develop commercial activities involving the library without
disclosing the source code of your own applications.

These activities include: offering paid services to customers as an ASP,
parsing logs on the fly in a web application, shipping libmsclogparser
with a closed source product.

For more information, please contact Digitalwave at this address:

modsecurity@digitalwave.hu
*/

#include <string.h>
#include <stdlib.h>

#define __USE_XOPEN
#define _GNU_SOURCE
#include <time.h>

#include "msclogparser.h"

#include <stdio.h>

typedef enum match_type {
    MATCH_FIRST = 1,
    MATCH_LAST
} match_type;

typedef enum ap_log_msg_type {
    AP_LOG_REGULAR = 1,
    AP_LOG_REQUEST,
    AP_LOG_RULE
} ap_log_msg_type;

void read_msclog_err(msclogpool *pool, msclogerr *err) {
    err->errmsg = pool->currptr;
    pool->currptr += strlen(err->errmsg) + 1;

    err->startpos = (size_t *)pool->currptr;
    pool->currptr += sizeof(size_t);

    err->endpos = (size_t *)pool->currptr;
    pool->currptr += sizeof(size_t);

    return;
}

static char * mscl_stradd(logdata *l, char *src, size_t srclen) {
    char * ptr = l->datapool.currptr;
    memcpy(l->datapool.currptr, src, srclen);
    l->datapool.offset += srclen + 1;
    l->datapool.pool[l->datapool.offset-1] = '\0';
    l->datapool.currptr = l->datapool.pool + l->datapool.offset;

    return ptr;
}

static void set_error(logdata *l, char *errmsg, size_t pos0, size_t pos1) {
    l->is_broken = 1;
    size_t len = strlen(errmsg);

    strcpy(l->lineerrpool.currptr, errmsg);
    l->lineerrpool.offset += len+1;
    l->lineerrpool.currptr = l->lineerrpool.pool + l->lineerrpool.offset;

    memcpy(l->lineerrpool.currptr, &pos0, sizeof(size_t));
    l->lineerrpool.offset += sizeof(size_t);
    l->lineerrpool.currptr = l->lineerrpool.pool + l->lineerrpool.offset;

    memcpy(l->lineerrpool.currptr, &pos1, sizeof(size_t));
    l->lineerrpool.offset += sizeof(size_t);
    l->lineerrpool.currptr = l->lineerrpool.pool + l->lineerrpool.offset;

    l->lineerrcnt++;

    return;
}

static void copy_str_from_line(logdata *l, char *line, char **dest, size_t pos, size_t end, size_t maxlen, size_t (*errpos)[2], int * is_broken) {

    size_t t = 0;
    size_t tpos = pos;

    // try to find the end of the field name
    while(pos < end && line[pos] != ' ') { pos++; }
    // now we are here:
    // ' [file "/usr/..."'
    //        ^- here
    if (line[pos] == ' ') pos++;    // step over the space, if it
    if (line[pos] == '"') pos++;    // step over the ", if it

    // copy the characters till we reach the end
    while(pos < end && t < maxlen) {
        l->datapool.currptr[t++] = line[pos++];
    }
    l->datapool.currptr[t] = '\0';
    t--;
    // remove trailing ' ', ']' and '"' if exists
    while (l->datapool.currptr[t] == ' ') t--;
    if (l->datapool.currptr[t] == ']') { t--; } else { *is_broken = 1; (*errpos)[0] = tpos; (*errpos)[1] = tpos+t; }
    if (l->datapool.currptr[t] == '"') { t--; } else { *is_broken = 1; (*errpos)[0] = tpos; (*errpos)[1] = tpos+t; }
    l->datapool.currptr[t+1] = '\0';

    (*dest) = l->datapool.currptr;
    l->datapool.offset += t+2;
    l->datapool.currptr = l->datapool.pool + l->datapool.offset;

    return;
}

static int parse_date_apache(char * line, logdata *l) {

    // check if the date and time field boundaries are right
    // [Thu Sep 22 14:51:12.636955 2022]
    // 0         0         0         0 2
    struct tm tm;
    char datetime[32] = {0};
    char year[5] = {0};
    char millisec[8] = {0};

    strncpy(year, line+28, 4);
    strncpy(millisec, line+20, 7);

    strncpy(datetime, line+1, 19);
    strcat(datetime, " ");
    strcat(datetime, year);

    memset(&tm, 0, sizeof(struct tm));
    tm.tm_isdst = -1;
    strptime(datetime, "%A %b %0d %H:%M:%S %Y", &tm);

    char date[20] = {0};
    sprintf(date, "%04d-%02d-%02d %02d:%02d:%02d", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    l->date_iso = mscl_stradd(l, date, 19);
    float mili = strtof(millisec, NULL);
    l->date_epoch = mktime(&tm);
    l->date_epoch += mili;

    return 0;
}

static int parse_date_nginx(char * line, logdata *l) {

    // 2022/12/20 17:04:13
    // 0         0       8
    struct tm tm;

    char datetime[20] = {0};

    strncpy(datetime, line+0, 19);

    memset(&tm, 0, sizeof(struct tm));
    tm.tm_isdst = -1;
    strptime(datetime, "%Y/%m/%d %H:%M:%S", &tm);

    char date[20] = {0};
    sprintf(date, "%04d-%02d-%02d %02d:%02d:%02d", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    l->date_iso = mscl_stradd(l, date, 19);
    l->date_epoch = mktime(&tm);

    return 0;
}

static int find_pattern(char * line, size_t offset, size_t maxlen, char *pattern, size_t minlen, size_t (*matches)[2], match_type mtype) {
    int      matchcnt      = 0;

    // get length of pattern, initialize minpatt
    size_t   pattlen = strlen(pattern);
    char     minpatt[minlen+1];

    memcpy(minpatt, pattern, minlen);
    minpatt[minlen] = '\0';

    // find first occurrence of pattern or subpattern (if minlen LT pattlen)
    // if we do not find it, return to caller
    char *p = strstr(line+offset, pattern);
    if (p == NULL) {
        if (minlen < pattlen) {
            p = strstr(line+offset, minpatt);
            if (p == NULL) {
                return matchcnt;
            }
        }
        else {
            return matchcnt;
        }
    }
    // found the pattern or subpattern, set the new offset
    offset = offset+(p - (line+offset));
    matchcnt++;
    (*matches)[0] = offset;
    (*matches)[1] = pattlen;

    // in other cases: minlen < pattlen
    //   OR
    // mtype == MATCH_LAST
    // other case: minlen == pattlen AND mtype == MATCH_FIRST

    // first, find the last pattern if minlen == pattlen
    if (minlen == pattlen) {
        // if pattlen == minlen and we need the first match, return
        if (mtype == MATCH_FIRST) {
            return matchcnt;
        }
        else {
            do {
                p = strstr(line+offset+pattlen, minpatt);
                if (p != NULL) {
                    matchcnt++;
                    offset = offset+(p - (line+offset));
                    (*matches)[0] = offset;
                    (*matches)[1] = pattlen;
                }
            } while (p != NULL);
            return matchcnt;
        }
    }
    else {
        size_t   bestmatchlen  = 0;
        size_t   matchlen      = 0;
        do {
            if (pattern[matchlen] != '\0' && line[offset] == pattern[matchlen]) {
                matchlen++;
                offset++;
            }
            else {
                if (matchlen > bestmatchlen) {
                    bestmatchlen = matchlen;
                }
                // found the best matched pattern
                if (matchlen >= minlen && matchlen >= bestmatchlen) {
                    (*matches)[0] = offset-matchlen;
                    (*matches)[1] = matchlen;
                    matchcnt++;
                    if (mtype == MATCH_FIRST) {
                        return matchcnt;
                    }
                }
                // not found but was some partial matches
                if (matchlen > 0) {
                    offset--;
                }
                matchlen = 0;
                if (bestmatchlen < minlen-1) {
                    bestmatchlen = 0;
                }
                // find new offset
                p = strstr(line+offset, pattern);
                if (p == NULL) {
                    p = strstr(line+offset, minpatt);
                    if (p == NULL && minlen < pattlen) {
                        offset = maxlen;
                    }
                    else {
                        offset = offset+(p - (line+offset));
                    }
                }
                else {
                    offset = offset+(p - (line+offset));
                }
            }
        } while (offset < maxlen && line[offset] != '\0');

        // special case if the pattern at the end of the line
        if (matchlen >= minlen && matchlen >= bestmatchlen) {
            (*matches)[0] = offset-matchlen;
            (*matches)[1] = matchlen;
            matchcnt++;
        }
    }

    return matchcnt;
}

void parse_ap_warning_message(logdata *l) {

    // parse one of these structures:

    // 1.
    // REASON '.'
    // eg: 'detected XSS using libinjection' '.'

    // 2.
    // REASON ' at ' TARGET '.'
    // eg: 'Invalid URL Encoding: Non-hexadecimal digits used at REQUEST_URI.'

    // 3.
    // REASON '"' OPERAND '"' ' at ' TARGET '.'
    // eg: 'String match within "/accept-charset/ /content-encoding/ /proxy/ /lock-token/ /content-range/ /if/" at TX:header_name_accept-charset.'
    // sub-versions:
    // 3/a and 3/b
    // REASON '"' OPERAND '"' ' at ' TARGET '.' Hash parameter hash value...
    // REASON '"' OPERAND '"' ' at ' TARGET '.' No hash parameter

    // 4.
    // REASON '"' OPERAND '"' ' at ' TARGET_NAME. [offset ...]
    // eg: 'CC# match "..." at TARGET. [offset N]

    // ' against ' used for regex messages
    // REASON '"' PATTERN '"' ' against ' '"' TARGET_NAME '"' required.
    size_t matches[2];
    memset(matches, '\0', sizeof(size_t)*2);
    int mcnt;

    // set msgpos to last pos of "Warning. "
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^ to here
    size_t msgpos = 9;

    mcnt = find_pattern(l->modsecmsg, msgpos, l->modsecmsglen, "\"", 1, &matches, MATCH_FIRST);
    if (mcnt == 0) {
        mcnt = find_pattern(l->modsecmsg, msgpos, l->modsecmsglen, " at ", 4, &matches, MATCH_FIRST);
        if (mcnt == 0) {
            // first case above - there is no '"' and no ' at ' therefore no '" at '
            // eg 'detected XSS using libinjection.'
            size_t startpos = 9; // length of "Warning. "
            size_t slen = l->modsecmsglen - startpos;
            if (l->modsecmsg[l->modsecmsglen-1] == '.') {
                // skip '.'
                slen--;
            }
            l->modsecmsgreason = mscl_stradd(l, l->modsecmsg + startpos, slen);
        }
        else {
            // second case above
            // eg 'Invalid URL Encoding: Non-hexadecimal digits used at REQUEST_URI.'
            //                                          matches[0]--^  ^--matches[0] + matches[1]
            size_t startpos = 9; // length of "Warning. "
            size_t slen = matches[0] - startpos;
            l->modsecmsgreason = mscl_stradd(l, l->modsecmsg + startpos, slen);
            startpos = matches[0]+matches[1];
            slen = l->modsecmsglen - startpos;
            if (l->modsecmsg[l->modsecmsglen-1] == '.') {
                // skip '.'
                slen--;
            }
            l->modsecmsgtrgname = mscl_stradd(l, l->modsecmsg + startpos, slen);
        }
    }
    else {
        // third or forth case above
        // eg 'String match within "/accept-charset/ /content-encoding/ /proxy/ /lock-token/ /content-range/ /if/" at TX:header_name_accept-charset.'
        // matches[0] points here -^
        size_t startpos = 9; // len of "Warning. "
        size_t slen = matches[0] - 10; // +1 is because of the space, eg: 'Matched phrase "...' after 'phrase ' or 'within '
        l->modsecmsgreason = mscl_stradd(l, l->modsecmsg + startpos, slen);
        msgpos = matches[0] + matches[1];
        memset(matches, '\0', sizeof(size_t)*2);
        mcnt = find_pattern(l->modsecmsg, msgpos, l->modsecmsglen, "\" at ", 5, &matches, MATCH_FIRST);
        size_t endoffset = 1;
        if (mcnt == 0) {
            mcnt = find_pattern(l->modsecmsg, msgpos, l->modsecmsglen, "\" against \"", 11, &matches, MATCH_FIRST);
            // '" against "' occurrs only in regex message, and follows the " required." at the end, with length of 10 + '"' before := 11
            endoffset = 11;
        }
        if (mcnt == 1) {
            // explicit 1 match
            // old startpos points to reason, slen is the length
            // end of the reason is startpos + length
            // new startpos is startpos + slen + 1 + 1 (last +1 is because of the leading '"')
            startpos = startpos + slen + 2;
            // slen is new match[0] (prev. of found pos) - startpos
            slen = matches[0] - startpos;
            l->modsecmsgoperand = mscl_stradd(l, l->modsecmsg + startpos, slen);
            // check whether the last char is a '.'. This means there is the end of the warning message
            if (l->modsecmsg[l->modsecmsglen-1] == '.') {
                startpos = matches[0] + matches[1];
                slen = l->modsecmsglen - startpos - endoffset;
                l->modsecmsgtrgname = mscl_stradd(l, l->modsecmsg + startpos, slen);
            }
            else {
                msgpos = matches[0] + matches[1];
                memset(matches, '\0', sizeof(size_t)*2);
                mcnt = find_pattern(l->modsecmsg, startpos, l->modsecmsglen, ". ", 11, &matches, MATCH_FIRST);
                if (mcnt == 1) {
                    slen = matches[0]-msgpos;
                    l->modsecmsgtrgname = mscl_stradd(l, l->modsecmsg + msgpos, slen);
                }
            }
        }
        else {
            // mcnt == 0  -> didn't find
            // mcnt > 1   -> more matches, it's not clear which is the correct position
        }
    }
}

void parse_ngx_warning_message(logdata *l) {

    // parse one of these structures:

    // 1.
    // REASON '.'
    // eg: 'detected XSS using libinjection' '.'

    // 2.
    // Matched "Operator `OP' with parameter `PARAM' against variable `VARIABLE' (Value: `VALUE' )
    // eg: 'Warning. Matched "Operator `Rx' with parameter `^[\d.:]+$' against variable `REQUEST_HEADERS:Host' (Value: `1.2.3.4' )'
    //     'Warning. Matched "Operator `PmFromFile' with parameter `unix-shell.data' against variable `ARGS:' (Value: `/bin/bash'' (Value: `' (Value: `/bin/bash'' )

    // 3.
    // Access denied with code CODE (phase PHASE). Matched "Operator `OP' with parameter `PARAM' against variable `VARIABLE' (Value: `VALUE' )
    // eg: 'Access denied with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable `TX:ANOMALY_SCORE' (Value: `8' )'

    // in case of "Access denied..." the modsecdenymsg is already filled, only need to parse the rest
    // this means we can start by "Matched...", so 2nd and 3rd cases almost are the same

    size_t offset = (l->modseclinetype == LOGMSG_ACCDENIED) ? 39 : 9;  // 'Access denied with code 403 (phase 2). ' || 'Warning. '
    size_t matches[2];
    memset(matches, '\0', sizeof(size_t)*2);
    int mcnt;

    mcnt = find_pattern(l->modsecmsg, offset, l->linelen, "Matched \"Operator `", 19, &matches, MATCH_FIRST);
    if (mcnt == 0) {
        // fist case above
        // copy the message without 'Warning. '
        l->modsecmsgreason = mscl_stradd(l, l->modsecmsg+9, l->modsecmsglen-10);
    }
    else {
        size_t startpos = matches[0] + matches[1]; // 'Matched "Operator `'
        memset(&matches, '\0', sizeof(size_t)*2);
        mcnt = find_pattern(l->modsecmsg, startpos, l->linelen, "' with parameter `", 18, &matches, MATCH_FIRST);
        if (mcnt == 1) {
            size_t slen = matches[0]-startpos;
            l->modsecmsgop = mscl_stradd(l, l->modsecmsg+startpos, slen);

            startpos = matches[0] + matches[1];
            memset(&matches, '\0', sizeof(size_t)*2);
            // find "' against variable `"
            mcnt = find_pattern(l->modsecmsg, startpos, l->modsecmsglen, "' against variable `", 20, &matches, MATCH_FIRST);
            if (mcnt > 0) {
                slen = matches[0]-startpos;
                l->modsecmsgoperand = mscl_stradd(l, l->modsecmsg+startpos, slen);

                startpos = matches[0] + matches[1];
                memset(&matches, '\0', sizeof(size_t)*2);
                mcnt = find_pattern(l->modsecmsg, startpos, l->modsecmsglen, "' (Value: `", 11, &matches, MATCH_LAST);
                if (mcnt > 0) {
                    slen = matches[0]-startpos;
                    l->modsecmsgtrgname = mscl_stradd(l, l->modsecmsg+startpos, slen);

                    startpos = matches[0] + matches[1];
                    memset(&matches, '\0', sizeof(size_t)*2);
                    mcnt = find_pattern(l->modsecmsg, startpos, l->modsecmsglen, "' )", 3, &matches, MATCH_LAST);
                    if (mcnt > 0) {
                        slen = matches[0]-startpos;
                        l->modsecmsgtrgvalue = mscl_stradd(l, l->modsecmsg+startpos, slen);
                    }
                    else {
                        set_error(l, "Can't find \"' )\"", startpos, l->modsecmsglen);
                    }
                }
                else {
                    set_error(l, "Can't find \"' (Value: `\"", startpos, l->modsecmsglen);
                }
            }
            else {
                set_error(l, "Can't find \"' against variable '\"", startpos, l->modsecmsglen);
            }
        }
        else {
            set_error(l, "Can't find pattern \"' with parameter `\"", startpos, l->modsecmsglen);
        }
    }
}

static void find_tags(char *line, size_t *offset, logdata *l) {

    size_t matches[2] = { *offset, 0 };
    int mcnt = 1;
    char *tagbck = NULL;
    size_t pos = *offset;

    while (pos < l->linelen && mcnt > 0) {
        int k = matches[0]+2;
        pos = matches[0] + matches[1];

        memset(matches, '\0', sizeof(size_t)*2);
        mcnt = find_pattern(line, pos, l->linelen, " [tag \"", 3, &matches, MATCH_FIRST);
        // if there is no more '[tag]' field, we have to find the '[hostname]'
        if (mcnt == 0) {
            size_t tempcnt = find_pattern(line, pos, l->linelen, " [hostname \"", 3, &matches, MATCH_FIRST);
            // if there is no '[hostname]', the line is broken
            if (tempcnt == 0) {
                set_error(l, "Can't find [hostname] field!", pos, l->linelen);
                break;
            }
        }

        size_t errpos[2] = { 0, 0 };
        int is_broken = 0;
        copy_str_from_line(l, line, &l->tags, k, matches[0], 50, &errpos, &is_broken);
        if (l->tagcnt == 0) {
            // save the first ptr
            tagbck = l->tags;
        }
        l->tagcnt++;
        if (is_broken == 1) {
            char err[50];
            sprintf(err, "The %zu. [tag] field is truncated!", l->tagcnt);
            set_error(l, err, errpos[0], errpos[1]);
            break;
        }
    }
    if (tagbck != NULL) {
        // restore l->tags to the first tag
        l->tags = tagbck;
    }
}

static void parse_tail(loglinetype linetype, char *line, size_t *startpos, logdata *l, size_t *tailstart) {

    // parse tail part of logline
    // Nginx:
    // [hostname "1.2.3.4"] [uri "/"] [unique_id "168142074224.426959"]
    // Apache:
    // [hostname "your.fqdn.name"] [uri "/uri.html"] [unique_id "AAbbTur0ZpO6NHHJAvMHLgAAAIQ"]

    size_t matches[2];
    int k, t;
    int hostlast = 0;
    size_t tlen = 2048;
    int mcnt;
    char tbuff[tlen+1];

    memset(&matches, '\0', sizeof(size_t)*2);
    mcnt = find_pattern(line, *startpos, l->linelen, "[hostname \"", 11, &matches, MATCH_LAST);
    if (mcnt > 0) {
        k = matches[0] + matches[1];
        t = 0;
        while(k < l->linelen && line[k] != '"' && line[k] != '\0' && t < tlen) {
            tbuff[t++] = line[k++];
        }
        if (k == l->linelen) {
            set_error(l, "[hostname] field is truncated!", *startpos, l->linelen);
            return;
        }
        // 'hostname' is relevant only if type of log is Apache
        // Nginx [hostname ""] contains the IP address, therefore we
        // have to process that later - see end of this function
        if (linetype == LOG_TYPE_APACHE) {
            tbuff[t] = '\0';
            l->hostname = mscl_stradd(l, tbuff, t);
            *startpos = k;
            if (tailstart != NULL) {
                *tailstart = matches[0];
            }
        }
    }
    else {
        // broken line
        set_error(l, "Can't find [hostname] field!", *startpos, l->linelen);
        return;
    }

    memset(&matches, '\0', sizeof(size_t)*2);
    int uniquefirst = 0;
    mcnt = find_pattern(line, hostlast, l->linelen, "[unique_id \"", 12, &matches, MATCH_LAST);
    if (mcnt > 0) {
        k = matches[0] + matches[1];
        t = 0;
        while(k < l->linelen && line[k] != '"' && t < tlen) {
            tbuff[t++] = line[k++];
        }
        if (k == l->linelen) {
            set_error(l, "[unique_id] field is truncated!", *startpos, l->linelen);
            return;
        }
        tbuff[t] = '\0';
        l->unique_id = mscl_stradd(l, tbuff, t);
        uniquefirst = matches[0];
    }
    else {
        // broken line
        set_error(l, "Can't find [unique_id] field!", hostlast, l->linelen);
        return;
    }

    memset(&matches, '\0', sizeof(size_t)*2);
    mcnt = find_pattern(line, hostlast, l->linelen, "[uri \"", 6, &matches, MATCH_FIRST);
    if (mcnt > 0) {
        k = matches[0] + matches[1];
        t = 0;
        while(k < uniquefirst && t < tlen) {
            tbuff[t++] = line[k++];
        }
        if (k > uniquefirst) {
            set_error(l, "[uri] field is truncated!", uniquefirst, l->linelen);
            return;
        }
        t--;
        // remove trailing ' ', ']' and '"' if exists
        while (tbuff[t] == ' ') t--;
        if (tbuff[t] == ']') { t--; } else { set_error(l, "[uri] field is truncated!", hostlast, l->linelen); }
        if (tbuff[t] == '"') { t--; } else { set_error(l, "[uri] field is truncated!", hostlast, l->linelen); }
        tbuff[t+1] = '\0';
        l->uri = mscl_stradd(l, tbuff, t);
    }
    else {
        // broken line
        set_error(l, "Can't find [uri] field!", hostlast, l->linelen);
        return;
    }

    // Nginx [hostname ""] filed contains the server IP address, we have to process
    // the last 'host: "..."' field
    if (linetype == LOG_TYPE_NGINX) {
        memset(&matches, '\0', sizeof(size_t)*2);
        mcnt = find_pattern(line, hostlast, l->linelen, "host: \"", 7, &matches, MATCH_FIRST);
        if (mcnt > 0) {
            k = matches[0] + matches[1];
            t = 0;
            while(k < l->linelen && line[k] != '"' && t < tlen) {
                tbuff[t++] = line[k++];
            }
            tbuff[t] = '\0';
            l->hostname = mscl_stradd(l, tbuff, t);
        }
        else {
            // broken line
            set_error(l, "Can't find 'host: \"\"' field!", hostlast, l->linelen);
            return;
        }
    }

    return;
}

static void parse_regular(char * line, size_t *pos, logdata *l, loglinetype linetype) {

    size_t matches[2], prevstart;
    int mcnt = 0;

    // find the ' [file ' pattern, usually it exists
    // its position is the end of the ModSec message
    memset(matches, '\0', sizeof(size_t)*2);
    mcnt = find_pattern(line, *pos, l->linelen, " [file \"", 8, &matches, MATCH_LAST);
    if (mcnt > 0) {
        char tbuff[4096];
        int pi = 0;
        for(size_t k = *pos+1; k < matches[0]; k++) {
            tbuff[pi++] = line[k];
        }
        tbuff[pi] = '\0';
        l->modsecmsg = mscl_stradd(l, tbuff, pi);
        l->modsecmsglen = pi;
    }
    else {
        // if no ' [file ' pattern, the line is broken
        set_error(l, "Can't find [file] field!", *pos, l->linelen);
        return;
    }
    // store the previous match position (+2 is because we leave the leading ' [')
    prevstart = matches[0]+2; // +2 -> leading space + [
    char fields[][20] = {
        " [line \"",          // 0
        " [id \"",            // 1
        " [rev \"",
        " [msg \"",
        " [data \"",
        " [severity \"",
        " [ver \"",
        " [maturity \"",
        " [accuracy \"",
        " [tag \"",           // 9
        " [hostname \"",      // 10 - this exists in any case
        ""
    };

    int          fi = 0;     // field index
    char      **tmp = NULL;  // temporary pointer
    size_t   maxlen = 0;     // max length of token
    size_t  lastpos = matches[0] + matches[1];
    int           k;         // position in line
    char tfield[20] = {0};
    match_type   mt;

    // find the pattern in the line from the current position,
    // and copy the value if it found
    while(lastpos-1 < l->linelen && fields[fi][0] != '\0') {
        // if last matches was success, copy the string to its value
        memset(matches, '\0', sizeof(size_t)*2);
        mt = ((fi == 9) ? MATCH_FIRST : MATCH_LAST);
        mcnt = find_pattern(line, lastpos-1, l->linelen, fields[fi], 3, &matches, mt);
        if (mcnt > 0) {
            // if the found pattern is shorter than given, check
            // whether the next chars are space or '['
            // if not, then it's not a (truncated) field
            if (strlen(fields[fi]) > matches[1]) {
                size_t nextpos = matches[0]+matches[1];
                if (line[nextpos] != ' ' && line[nextpos+1] != '[') {
                    fi++;
                    continue;
                }
            }
            k = prevstart;
            // based on first char of previous position we choose the current field
            // prev. position in first case is where we found the ' [file ' pattern
            switch (line[k]) {
                case 'f':
                    tmp = &l->file;
                    strcpy(tfield, "[file]");
                    maxlen = 256;
                    break;

                case 'l':
                    tmp = &l->line;
                    strcpy(tfield, "[line]");
                    maxlen = 20;
                    break;

                case 'i':
                    tmp = &l->id;
                    strcpy(tfield, "[id]");
                    maxlen = 20;
                    break;

                case 'r':
                    tmp = &l->rev;
                    strcpy(tfield, "[rev]");
                    maxlen = 20;
                    break;

                case 'm':
                    if (line[k+1] == 's') {
                        tmp = &l->msg;
                        strcpy(tfield, "[msg]");
                        maxlen = 512;
                    }
                    else if (line[k+1] == 'a') {
                        tmp = &l->maturity;
                        strcpy(tfield, "[maturity]");
                        maxlen = 20;
                    }
                    break;

                case 'd':
                    tmp = &l->data;
                    strcpy(tfield, "[data]");
                    maxlen = 1024;
                    break;

                case 's':
                    tmp = &l->severity;
                    strcpy(tfield, "[severity]");
                    maxlen = 20;
                    break;

                case 'v':
                    tmp = &l->version;
                    strcpy(tfield, "[version]");
                    maxlen = 20;
                    break;

                case 'a':
                    tmp = &l->accuracy;
                    strcpy(tfield, "[accuracy]");
                    maxlen = 20;
                    break;

                default:
                    tmp = NULL;
                    maxlen = 0;
                    break;
            }
            // line[k] still points to previous position
            // eg. ' [file ' in first case
            //        ^- here (because +2)
            if (maxlen > 0) {  // check that some of switch cases above matched
                size_t errpos[2] = { 0, 0 };
                int is_broken = 0;
                copy_str_from_line(l, line, tmp, k, matches[0], maxlen, &errpos, &is_broken);
                if (is_broken == 1) {
                    char err[50];
                    sprintf(err, "Field %s is truncated!", tfield);
                    if (errpos[1] < errpos[0]) {
                        // this means there is no value
                        // 3 is the minimal length to recognize the field
                        // see above the find_pattern() call 5th parameter
                        errpos[1] = errpos[0] + 3;
                    }
                    set_error(l, err, errpos[0], errpos[1]);
                    //l->is_broken = 0;   // these fields are not mandatory
                }
            }
            else {
                set_error(l, "Unknown character!", k, k);
                return;
            }

            prevstart = matches[0]+2;
            lastpos = matches[0] + matches[1];
            *pos = lastpos;
        }

        // if we reach the ' [tag ' or ' [hostname ' field, jump out of the cycle
        if (fi >= 9 && mcnt > 0) {
            break;
        }

        fi++;
    }

    // if we are on first [tag]
    if (fi == 9) {
        find_tags(line, &prevstart, l);
    }
    prevstart--;
    *pos = prevstart;

    parse_tail(linetype, line, pos, l, NULL);

    return;
}

void parse_rule_error(char * line, size_t *pos, logdata *l, loglinetype linetype) {

    size_t matches[2], prevstart;
    int mcnt = 0;
    char tbuff[4096];

    // find the ' [id ' pattern, usually it exists
    // its position is the end of the ModSec message
    memset(matches, '\0', sizeof(size_t)*2);
    mcnt = find_pattern(line, *pos, l->linelen, "[id \"", 5, &matches, MATCH_LAST);
    if (mcnt > 0) {
        int pi = 0;
        // matches[0]-1 because of the leading space in front of
        // '[id '
        for(size_t p = *pos+1; p < matches[0]-1; p++) {
            tbuff[pi++] = line[p];
        }
        tbuff[pi] = '\0';
        l->modsecmsg = mscl_stradd(l, tbuff, pi);
    }
    else {
        // if no ' [id ' pattern, the line is broken
        set_error(l, "Can't find [id] field!", *pos, l->linelen);
        return;
    }
    // store the previous match position (+1 is because we leave the leading '[')
    prevstart = matches[0]+1;
    char fields[][20] = {
        "[file ",
        "[line ",
        ""
    };

    int          fi = 0;      // field index
    char       *tmp = NULL;   // temporary pointer
    size_t   maxlen = 0;      // max length of token
    size_t  lastpos = matches[0] + matches[1];     
    int           k;          // pos in line
    char tfield[20] = {0};

    // find the pattern in the line from the current position,
    // and copy the value if it found
    while(fields[fi][0] != '\0') {
        // if last matches was success, copy the string to its value
        memset(matches, '\0', sizeof(size_t)*2);
        mcnt = find_pattern(line, lastpos-1, l->linelen, fields[fi], 3, &matches, MATCH_FIRST);
        if (mcnt > 0) {
            k = prevstart;
            // based on first char of previous position we choose the current field
            // prev. position in first case is where we found the ' [id ' pattern
            switch (line[k]) {
                case 'i':
                    tmp = l->id;
                    strcpy(tfield, "[id]");
                    maxlen = 20;
                    break;

                case 'f':
                    tmp = l->file;
                    strcpy(tfield, "[file]");
                    maxlen = 256;
                    break;

                case 'l':
                    tmp = l->line;
                    strcpy(tfield, "[line]");
                    maxlen = 20;
                    break;

                default:
                    tmp = NULL;
                    strcpy(tfield, "[UNKNOWN]");
                    maxlen = 0;
                    break;
            }
            // line[k] still points to previous position
            // eg. ' [id ' in first case
            //        ^- here
            // but later it points
            //     '[file '
            //       ^- here
            if (maxlen > 0) {
                size_t errpos[2] = { 0, 0 };
                int is_broken = 0;
                copy_str_from_line(l, line, &tmp, k, matches[0], maxlen, &errpos, &is_broken);
                if (is_broken == 1) {
                    char err[50];
                    sprintf(err, "Field %s is truncated!", tfield);
                    set_error(l, err, errpos[0], errpos[1]);
                    //break;
                }
                prevstart = matches[0]+1;
                lastpos = matches[0] + matches[1];
                *pos = lastpos;
            }
            else {
                set_error(l, "Unknown character!", k, k);
                return;
            }
        }
        else {
            l->is_broken = 1;
            char err[50] = {0};
            sprintf(err, "Can't find field: %s!", fields[fi]);
            set_error(l, err, *pos, l->linelen);
            return;
        }
        fi++;
    }

    memset(matches, '\0', sizeof(size_t)*2);
    mcnt = find_pattern(line, lastpos-1, l->linelen, "]", 1, &matches, MATCH_FIRST);
    if (mcnt == 1) {
        k = prevstart;
        tmp = l->line;
        maxlen = 20;

        size_t errpos[2] = { 0, 0 };
        int is_broken = 0;
        copy_str_from_line(l, line, &tmp, k, matches[0]+1, maxlen, &errpos, &is_broken);
        if (is_broken == 1) {
            set_error(l, "Field [line] is truncated!", errpos[0], errpos[1]);
        }

        prevstart = matches[0]+1;
        lastpos = matches[0] + matches[1];
        *pos = lastpos;
    }
    else {
        // broken line, no trailing ']'
        set_error(l, "Can't find trailing ']' character!", lastpos-1, l->linelen);
        return;
    }

    size_t hostpos = 0;
    parse_tail(linetype, line, pos, l, &hostpos);
    if (l->is_broken == 1) {
        return;
    }

    int li = 0;
    k = lastpos+3;
    while(k < hostpos) {
        tbuff[li++] = line[k++];
    }
    // remove trailing spaces
    while(tbuff[--li] == ' ');
    tbuff[++li] = '\0';
    l->ruleerror = mscl_stradd(l, tbuff, li);

    return;
}

int parse (char * line, size_t len, loglinetype t, logdata * l) {

    size_t offset = 0;
    l->lineerrpool.currptr = l->lineerrpool.pool;
    l->lineerrpool.offset = 0;

    l->datapool.currptr = l->datapool.pool;
    l->datapool.offset = 0;

    // remove EOL-s from the end of line
    while(len > 0 && (line[len-1] == '\0' || line[len-1] == '\n')) {
        len--;
    }
    line[len] = '\0';

    // initialize string pointers with an empty string
    l->date_iso          = mscl_stradd(l, "", 0);
    l->client            = mscl_stradd(l, "", 0);
    l->modsecmsg         = mscl_stradd(l, "", 0);
    l->modsecdenymsg     = mscl_stradd(l, "", 0);
    l->modsecmsgreason   = mscl_stradd(l, "", 0);
    l->modsecmsgop       = mscl_stradd(l, "", 0);
    l->modsecmsgoperand  = mscl_stradd(l, "", 0);
    l->modsecmsgtrgname  = mscl_stradd(l, "", 0);
    l->modsecmsgtrgvalue = mscl_stradd(l, "", 0);
    l->ruleerror         = mscl_stradd(l, "", 0);
    l->file              = mscl_stradd(l, "", 0);
    l->line              = mscl_stradd(l, "", 0);
    l->id                = mscl_stradd(l, "", 0);
    l->rev               = mscl_stradd(l, "", 0);
    l->msg               = mscl_stradd(l, "", 0);
    l->data              = mscl_stradd(l, "", 0);
    l->severity          = mscl_stradd(l, "", 0);
    l->version           = mscl_stradd(l, "", 0);
    l->maturity          = mscl_stradd(l, "", 0);
    l->accuracy          = mscl_stradd(l, "", 0);
    l->tags              = mscl_stradd(l, "", 0);
    l->hostname          = mscl_stradd(l, "", 0);
    l->uri               = mscl_stradd(l, "", 0);
    l->unique_id         = mscl_stradd(l, "", 0);

    if (t == LOG_TYPE_APACHE) {
        // [Thu Sep 22 14:51:12.636955 2022] [:error] [pid 19765:tid 139903325140736] [client 165.232.134.42:52179] [client 165.232.134.42] 
        // [Thu Sep 22 14:51:12.636955 2022] [:info] [pid 1:tid 1] [client 1.2.3.4:1] [client 1.2.3.4] 
        //          |         |         |         |         |         |         |         |         |         |         |         |         |
        offset = 90;
    }
    else if (t == LOG_TYPE_NGINX) {
        // 2022/12/20 17:04:13 [info] 59513#59513: *1
        // 2022/12/20 17:04:13 [info] 1#1: *1
        //          |         |         |         |  
        offset = 30;
    }

    if (len <= offset + 13) { // offset + length of ModSecurity
        return 1;
    }

    l->linelen = len;

    // store position and length
    size_t matches[2];
    memset(matches, '\0', sizeof(size_t)*2);
    // first find the " ModSecurity:" string, if exists in the line
    int mcnt = find_pattern(line, offset, len, " ModSecurity:", 13, &matches, MATCH_FIRST);
    // continue only if it is there
    if (mcnt == 1) {
        l->is_modsecline = 1;
        if (t == LOG_TYPE_APACHE) {
            parse_date_apache(line, l);
        }
        else if (t == LOG_TYPE_NGINX) {
            parse_date_nginx(line, l);
        }
        // continue from the position
        // toffset points here:
        // '... ModSecurity: '
        //              ~~~^
        size_t toffset = matches[0] + matches[1];
        if (t == LOG_TYPE_APACHE) {

            // catch the [client ...] fields
            // first possible occurrance position of first [client ...] is 55
            // only in case of Apache

            // catch the [client ...] fields
            memset(matches, '\0', sizeof(size_t)*2);
            // first possible occurrance position of first [client ...] is 55
            // only in case of Apache
            mcnt = find_pattern(line, 55, len, "[client ", 8, &matches, MATCH_FIRST);
            if (mcnt != 1) {
                set_error(l, "Can't find [client] field!", 0, len);
                return 1;
            }
            else {
                size_t pos = matches[0] + matches[1];
                memset(matches, '\0', sizeof(size_t)*2);
                // find the second [client] position, this shows the end of real [client]
                mcnt = find_pattern(line, pos, len, "[client ", 8, &matches, MATCH_FIRST);
                if (mcnt != 1) {
                    set_error(l, "Can't find second [client] field!", 0, len);
                    return 1;
                }
                else {
                    int ci = 0;
                    int k = pos;
                    char client[50];
                    while(k < matches[0]-1 && line[k] != ']') {
                        client[ci++] = line[k++];
                    }
                    client[ci] = '\0';
                    l->client = mscl_stradd(l, client, ci);
                }
            }

            //ap_log_msg_type log_msg_type;
            memset(matches, '\0', sizeof(size_t)*2);
            // order of most frequent patterns:
            // "Warning" - Warning. Pattern match...
            // "Access" - Access denied with code...
            // "Request" - Request body (Content-Length) is larger
            // "Rule" - Rule 7fxx ... - Execution error - PCRE limits exceeded (-8)
            // based on next substring it determines what do we have to look for

            // structure of Warning and Access lines are the same
            mcnt = find_pattern(line, toffset, toffset+10, "Warning.", 8, &matches, MATCH_FIRST);
            if (mcnt == 0) {
                mcnt = find_pattern(line, toffset, toffset+8, "Access", 6, &matches, MATCH_FIRST);
            }
            else {
                l->modseclinetype = LOGMSG_WARNING;
            }
            if (mcnt == 1 && toffset == matches[0]-1) {
                parse_regular(line, &toffset, l, LOG_TYPE_APACHE);
                if (l->modseclinetype == LOGMSG_UNKNOWN) {
                    l->modseclinetype = LOGMSG_ACCDENIED;
                    l->modsecdenymsg = mscl_stradd(l, l->modsecmsg, l->modsecmsglen);
                }
                if (l->modseclinetype == LOGMSG_WARNING) {
                    parse_ap_warning_message(l);
                }
            }
            else {
                mcnt = find_pattern(line, toffset, toffset+6, "Rule", 4, &matches, MATCH_FIRST);
                if (mcnt == 1) {
                    l->modseclinetype = LOGMSG_ERROR;
                    parse_rule_error(line, &toffset, l, LOG_TYPE_APACHE);
                }
                else {
                    char tbuff[4096];
                    mcnt = find_pattern(line, toffset, toffset+14, "Request body", 12, &matches, MATCH_FIRST);
                    if (mcnt == 1) {
                        l->modseclinetype = LOGMSG_REQBODY;
                        size_t offs = toffset;
                        size_t hostpos = 0;
                        parse_tail(t, line, &offs, l, &hostpos);
                        if (hostpos > 0) {
                            int k = toffset+1;
                            int i = 0;
                            while(k < hostpos-1) {
                                tbuff[i++] = line[k++];
                            }
                            tbuff[i] = '\0';
                            l->modsecmsg = mscl_stradd(l, tbuff, i);
                        }
                    }
                    else {
                        mcnt = find_pattern(line, toffset, toffset+14, "Audit log", 9, &matches, MATCH_FIRST);
                        if (mcnt == 1) {
                            l->modseclinetype = LOGMSG_AUDITLOG;
                            size_t offs = toffset;
                            size_t hostpos = 0;
                            parse_tail(t, line, &offs, l, &hostpos);
                            if (hostpos > 0) {
                                int k = toffset+1;
                                int i = 0;
                                while(k < hostpos-1) {
                                    tbuff[i++] = line[k++];
                                }
                                tbuff[i] = '\0';
                                l->modsecmsg = mscl_stradd(l, tbuff, i);
                            }
                        }
                    }
                }
            }
        }

        if (t == LOG_TYPE_NGINX) {
            parse_regular(line, &toffset, l, LOG_TYPE_NGINX);
            memset(&matches, '\0', sizeof(size_t)*2);
            mcnt = find_pattern(line, toffset, len, ", client: ", 10, &matches, MATCH_FIRST);
            if (mcnt == 1) {
                int ci = 0;
                int k = matches[0] + matches[1];
                char client[50];
                while(line[k] != ',') {
                    client[ci++] = line[k++];
                }
                client[ci] = '\0';
                l->client = mscl_stradd(l, client, ci);
                // possible messages:
                // 
                // Matched "Operator `OP' with parameter `PARAM' against variable `VARIABLE' (Value: `VALUE' )
                // Access denied with code CODE (phase PHASE). Matched "Operator `OP' with parameter `PARAM' against variable `VARIABLE' (Value: `VALUE' )
                // detected XSS using libinjection.
                // detected SQLi using libinjection.
                memset(&matches, '\0', sizeof(size_t)*2);
                mcnt = find_pattern(l->modsecmsg, 0, 8, "Access ", 7, &matches, MATCH_FIRST);
                if (mcnt == 1 && matches[0] == 0) {
                    l->modseclinetype = LOGMSG_ACCDENIED;
                    size_t startpos = matches[0]+matches[1];
                    memset(&matches, '\0', sizeof(size_t)*2);
                    mcnt = find_pattern(l->modsecmsg, startpos, 50, "Matched", 7, &matches, MATCH_FIRST);
                    if (mcnt == 1) {
                        l->modsecdenymsg = mscl_stradd(l, l->modsecmsg, matches[0]-2); // -2: '. ' before the 'Matched'
                        parse_ngx_warning_message(l);
                    }
                }
                else {
                    mcnt = find_pattern(l->modsecmsg, 0, 9, "Warning.", 8, &matches, MATCH_FIRST);
                    if (mcnt == 1 && matches[0] == 0) {
                        l->modseclinetype = LOGMSG_WARNING;
                        parse_ngx_warning_message(l);
                    }
                }
            }
            else {
                set_error(l, "Can't find client field!", toffset, len);
            }
        }
    }

    return 0;
}
