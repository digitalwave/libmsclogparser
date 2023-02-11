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

#ifndef MSCLOGPARSER_H
#define MSCLOGPARSER_H

#define MSCLOGPARSER_MAJOR "0"
#define MSCLOGPARSER_MINOR "1"
#define MSCLOGPARSER_PATCH "0"
#define MSCLOGPARSER_VERSION MSCLOGPARSER_MAJOR"."MSCLOGPARSER_MINOR"."MSCLOGPARSER_PATCH

#define LOGTYPE_APACHE 1
#define LOGTYPE_NGINX  2

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
    char    pool[4096];
    char    *currptr;
    size_t  offset;
} msclogpool;

typedef struct msclogerr {
    char    *errmsg;
    size_t  *startpos;
    size_t  *endpos;
} msclogerr;

typedef struct logdata {
    msclogpool      datapool;
    size_t          linelen;
    int             is_modsecline;
    int             is_broken;
    char            *date_iso;
    double          date_epoch;
    char            *client;
    logmsgtype      modseclinetype;
    char            *modsecmsg;
    size_t          modsecmsglen;
    char            *modsecdenymsg;
    char            *modsecmsgreason;
    char            *modsecmsgop;
    char            *modsecmsgoperand;
    char            *modsecmsgtrgname;
    char            *modsecmsgtrgvalue;
    char            *ruleerror;
    char            *file;
    char            *line;
    char            *id;
    char            *rev;
    char            *msg;
    char            *data;
    char            *severity;
    char            *version;
    char            *maturity;
    char            *accuracy;
    size_t          tagcnt;
    char            *tags;
    char            *hostname;
    char            *uri;
    char            *unique_id;
    msclogpool      lineerrpool;
    int             lineerrcnt;
} logdata;

void read_msclog_err(msclogpool *pool, msclogerr *err);
int parse (char * line, size_t len, loglinetype t, logdata * l);

#endif