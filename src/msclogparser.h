/*
This file is part of the libmsclogparser project.

Copyright (c) 2023-2026 Digitalwave

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

#ifndef MSCLOGPARSER_H
#define MSCLOGPARSER_H

#define MSCLOGPARSER_MAJOR "1"
#define MSCLOGPARSER_MINOR "0"
#define MSCLOGPARSER_PATCH "0"
#define MSCLOGPARSER_VERSION MSCLOGPARSER_MAJOR"."MSCLOGPARSER_MINOR"."MSCLOGPARSER_PATCH

#define LOGTYPE_APACHE 1
#define LOGTYPE_NGINX  2

#include <stddef.h>

typedef enum loglinetype {
    LOG_TYPE_APACHE,
    LOG_TYPE_NGINX
} loglinetype;

typedef enum logmsgtype {
    LOGMSG_UNKNOWN,
    LOGMSG_WARNING,
    LOGMSG_ACCDENIED,
    LOGMSG_REQBODY,
    LOGMSG_ERROR,
    LOGMSG_AUDITLOG
} logmsgtype;

typedef struct msclogpool {
    char    pool[8192];
    char    *currptr;
    size_t  offset;
} msclogpool;

typedef struct msclogerr {
    char    *errmsg;
    size_t  *startpos;
    size_t  *endpos;
} msclogerr;

typedef enum logfields {
    LOGFIELD_LOG_DATE_ISO,
    LOGFIELD_LOG_DATE_TIMESTAMP,
    LOGFIELD_LOG_CLIENT,
    LOGFIELD_LOG_MODSEC_MSG,
    LOGFIELD_LOG_MODSEC_REASON,
    LOGFIELD_LOG_MODSEC_OPERATOR,
    LOGFIELD_LOG_MODSEC_OPERAND,
    LOGFIELD_LOG_MODSEC_TARGET_NAME,
    LOGFIELD_LOG_MODSEC_TARGET_VALUE,
    LOGFIELD_LOG_MODSEC_PROCESS_ERROR,
    LOGFIELD_LOG_RULE_FILE,
    LOGFIELD_LOG_RULE_LINE,
    LOGFIELD_LOG_RULE_ID,
    LOGFIELD_LOG_RULE_REV,
    LOGFIELD_LOG_RULE_MSG,
    LOGFIELD_LOG_RULE_DATA,
    LOGFIELD_LOG_RULE_SEVERITY,
    LOGFIELD_LOG_RULE_VERSION,
    LOGFIELD_LOG_RULE_MATURITY,
    LOGFIELD_LOG_RULE_ACCURACY,
    LOGFIELD_LOG_RULE_TAGS,
    LOGFIELD_LOG_HOSTNAME,
    LOGFIELD_LOG_URI,
    LOGFIELD_LOG_UNIQUE_ID
} logfields;


typedef struct logdata {
    int             entry_is_modsecline;
    int             entry_is_broken;
    size_t          log_entry_raw_length;
    double          log_date_timestamp;
    logmsgtype      log_entry_class;
    size_t          log_modsec_msg_length;
    size_t          log_rule_tags_cnt;
    int             log_entry_errors_cnt;
    char          * fields[LOGFIELD_LOG_UNIQUE_ID+1];
    msclogpool      datapool;
    msclogpool      lineerrpool;
} logdata;

#define log_date_iso               fields[LOGFIELD_LOG_DATE_ISO]
#define log_client                 fields[LOGFIELD_LOG_CLIENT]
#define log_modsec_msg             fields[LOGFIELD_LOG_MODSEC_MSG]
#define log_modsec_reason          fields[LOGFIELD_LOG_MODSEC_REASON]
#define log_modsec_operator        fields[LOGFIELD_LOG_MODSEC_OPERATOR]
#define log_modsec_operand         fields[LOGFIELD_LOG_MODSEC_OPERAND]
#define log_modsec_target_name     fields[LOGFIELD_LOG_MODSEC_TARGET_NAME]
#define log_modsec_target_value    fields[LOGFIELD_LOG_MODSEC_TARGET_VALUE]
#define log_modsec_process_error   fields[LOGFIELD_LOG_MODSEC_PROCESS_ERROR]
#define log_rule_file              fields[LOGFIELD_LOG_RULE_FILE]
#define log_rule_line              fields[LOGFIELD_LOG_RULE_LINE]
#define log_rule_id                fields[LOGFIELD_LOG_RULE_ID]
#define log_rule_rev               fields[LOGFIELD_LOG_RULE_REV]
#define log_rule_msg               fields[LOGFIELD_LOG_RULE_MSG]
#define log_rule_data              fields[LOGFIELD_LOG_RULE_DATA]
#define log_rule_severity          fields[LOGFIELD_LOG_RULE_SEVERITY]
#define log_rule_version           fields[LOGFIELD_LOG_RULE_VERSION]
#define log_rule_maturity          fields[LOGFIELD_LOG_RULE_MATURITY]
#define log_rule_accuracy          fields[LOGFIELD_LOG_RULE_ACCURACY]
#define log_rule_tags              fields[LOGFIELD_LOG_RULE_TAGS]
#define log_hostname               fields[LOGFIELD_LOG_HOSTNAME]
#define log_uri                    fields[LOGFIELD_LOG_URI]
#define log_unique_id              fields[LOGFIELD_LOG_UNIQUE_ID]

typedef char * logvalptr;

void read_msclog_err(msclogpool *pool, msclogerr *err);
int parse (char * line, size_t len, loglinetype t, logdata * l);

#endif