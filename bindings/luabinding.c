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

#include "lua.h"
#include "lauxlib.h"

#include <stdio.h>
#include <string.h>

#include "../src/msclogparser.h"

#define MODULE_VERSION "2.0.0"

// the len argument is bigger than the line: the line is parsed with its own
// length, and this error is added
#define MSCLEN_ERROR_FMT "The given length (%zu) is bigger than the line (%zu bytes)!"

static int msclualogparser_parse (lua_State *L) {
    if (lua_gettop(L) != 3) {
        return luaL_error(L, "incorrect number of arguments");
    }

    size_t linelen;
    const char *line = luaL_checklstring(L, 1, &linelen);
    lua_Integer ilen = luaL_checkinteger(L, 2);
    luaL_argcheck(L, ilen >= 0, 2, "len must not be negative");
    size_t len = (size_t)ilen;
    loglinetype ltype = (loglinetype)luaL_checkinteger(L, 3);

    // a len bigger than the line would make parse() read after its end: the
    // line is parsed with its own length, and the error is reported
    size_t givenlen = len;
    int lenerr = len > linelen;
    if (lenerr) {
        len = linelen;
    }

    logdata l;
    memset(&l, '\0', sizeof(logdata));

    parse(line, len, ltype, &l);
    if (lenerr) {
        l.entry_is_broken = 1;
    }

    lua_newtable(L);
    int maintable = lua_gettop(L);

    lua_pushstring(L, "entry_is_modsecline");
    lua_pushinteger(L, l.entry_is_modsecline);
    lua_settable(L, maintable);

    lua_pushstring(L, "entry_is_broken");
    lua_pushinteger(L, l.entry_is_broken);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_entry_raw_length");
    lua_pushinteger(L, l.log_entry_raw_length);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_date_iso");
    lua_pushstring(L, l.log_date_iso);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_date_timestamp");
    lua_pushnumber(L, l.log_date_timestamp);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_client");
    lua_pushstring(L, l.log_client);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_entry_class");
    lua_pushinteger(L, l.log_entry_class);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_modsec_msg");
    lua_pushstring(L, l.log_modsec_msg);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_modsec_msg_length");
    lua_pushinteger(L, l.log_modsec_msg_length);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_modsec_reason");
    lua_pushstring(L, l.log_modsec_reason);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_modsec_operator");
    lua_pushstring(L, l.log_modsec_operator);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_modsec_operand");
    lua_pushstring(L, l.log_modsec_operand);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_modsec_target_name");
    lua_pushstring(L, l.log_modsec_target_name);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_modsec_target_value");
    lua_pushstring(L, l.log_modsec_target_value);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_modsec_process_error");
    lua_pushstring(L, l.log_modsec_process_error);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_rule_file");
    lua_pushstring(L, l.log_rule_file);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_rule_line");
    lua_pushstring(L, l.log_rule_line);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_rule_id");
    lua_pushstring(L, l.log_rule_id);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_rule_rev");
    lua_pushstring(L, l.log_rule_rev);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_rule_msg");
    lua_pushstring(L, l.log_rule_msg);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_rule_data");
    lua_pushstring(L, l.log_rule_data);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_rule_severity");
    lua_pushstring(L, l.log_rule_severity);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_rule_version");
    lua_pushstring(L, l.log_rule_version);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_rule_maturity");
    lua_pushstring(L, l.log_rule_maturity);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_rule_accuracy");
    lua_pushstring(L, l.log_rule_accuracy);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_rule_tags_cnt");
    lua_pushinteger(L, l.log_rule_tags_cnt);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_rule_tags");

    lua_newtable(L);
    int subtable = lua_gettop(L);
    for(size_t ti = 0; ti < l.log_rule_tags_cnt; ti++) {
        lua_pushinteger(L, ti+1);
        lua_pushstring(L, l.log_rule_tags);
        lua_settable(L, subtable);
        l.log_rule_tags += strlen(l.log_rule_tags) + 1;
    }
    lua_settable(L, maintable);


    lua_pushstring(L, "log_hostname");
    lua_pushstring(L, l.log_hostname);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_uri");
    lua_pushstring(L, l.log_uri);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_unique_id");
    lua_pushstring(L, l.log_unique_id);
    lua_settable(L, maintable);

    lua_pushstring(L, "log_server");
    lua_pushstring(L, l.log_server);
    lua_settable(L, maintable);


    lua_pushstring(L, "log_entry_errors_cnt");
    lua_pushinteger(L, l.log_entry_errors_cnt + lenerr);
    lua_settable(L, maintable);


    lua_pushstring(L, "log_entry_errors");
    lua_newtable(L);
    int errorstable = lua_gettop(L);

    if (l.log_entry_errors_cnt > 0) {
        // reset errpool ptr
        l.lineerrpool.currptr = l.lineerrpool.pool;
        msclogerr logerr;
        for (int c=0; c < l.log_entry_errors_cnt; c++) {
            read_msclog_err(&l.lineerrpool, &logerr);
            lua_pushinteger(L, c+1);
            lua_pushstring(L, logerr.errmsg);
            lua_settable(L, errorstable);            
        }
    }
    if (lenerr) {
        char msg[128];
        snprintf(msg, sizeof(msg), MSCLEN_ERROR_FMT, givenlen, linelen);
        lua_pushinteger(L, l.log_entry_errors_cnt + 1);
        lua_pushstring(L, msg);
        lua_settable(L, errorstable);
    }

    lua_settable(L, maintable);


    lua_pushstring(L, "log_entry_errors_pos");
    lua_newtable(L);
    int errorspostable = lua_gettop(L);

    if (l.log_entry_errors_cnt > 0) {
        // reset errpool ptr
        l.lineerrpool.currptr = l.lineerrpool.pool;
        msclogerr logerr;
        for (int c=0; c < l.log_entry_errors_cnt; c++) {
            read_msclog_err(&l.lineerrpool, &logerr);

            lua_pushinteger(L, c+1);

            lua_newtable(L);
            subtable = lua_gettop(L);

            lua_pushinteger(L, 1);
            lua_pushinteger(L, *logerr.startpos);
            lua_settable(L, subtable);

            lua_pushinteger(L, 2);
            lua_pushinteger(L, *logerr.endpos);
            lua_settable(L, subtable);

            lua_settable(L, errorspostable);
        }
    }
    if (lenerr) {
        lua_pushinteger(L, l.log_entry_errors_cnt + 1);
        lua_newtable(L);
        subtable = lua_gettop(L);
        lua_pushinteger(L, 1);
        lua_pushinteger(L, (lua_Integer)linelen);
        lua_settable(L, subtable);
        lua_pushinteger(L, 2);
        lua_pushinteger(L, (lua_Integer)givenlen);
        lua_settable(L, subtable);
        lua_settable(L, errorspostable);
    }

    lua_settable(L, maintable);

    return 1;
}

int luaopen_msclualogparser(lua_State *L) {
    lua_newtable(L);
    lua_pushcfunction (L, msclualogparser_parse);
    lua_setfield (L, -2, "parse");


    lua_pushstring(L, "LOG_TYPE_APACHE");
    lua_pushinteger(L, LOG_TYPE_APACHE);
    lua_settable(L, -3);

    lua_pushstring(L, "LOG_TYPE_NGINX");
    lua_pushinteger(L, LOG_TYPE_NGINX);
    lua_settable(L, -3);

    lua_pushstring(L, "LOGMSG_UNKNOWN");
    lua_pushinteger(L, LOGMSG_UNKNOWN);
    lua_settable(L, -3);

    lua_pushstring(L, "LOGMSG_WARNING");
    lua_pushinteger(L, LOGMSG_WARNING);
    lua_settable(L, -3);

    lua_pushstring(L, "LOGMSG_ACCDENIED");
    lua_pushinteger(L, LOGMSG_ACCDENIED);
    lua_settable(L, -3);

    lua_pushstring(L, "LOGMSG_REQBODY");
    lua_pushinteger(L, LOGMSG_REQBODY);
    lua_settable(L, -3);

    lua_pushstring(L, "LOGMSG_ERROR");
    lua_pushinteger(L, LOGMSG_ERROR);
    lua_settable(L, -3);

    lua_pushstring(L, "LOGMSG_AUDITLOG");
    lua_pushinteger(L, LOGMSG_AUDITLOG);
    lua_settable(L, -3);

    lua_pushstring(L, "LIBRARY_VERSION");
    lua_pushstring(L, MSCLOGPARSER_VERSION);
    lua_settable(L, -3);

    lua_pushstring(L, "MODULE_VERSION");
    lua_pushstring(L, MODULE_VERSION);
    lua_settable(L, -3);
 
    return 1;
}