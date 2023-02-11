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

#include "lua.h"
#include "lauxlib.h"

#include <string.h>

#include "msclogparser.h"

#define MODULE_VERSION "0.1.0"

int msclualogparser_parse (lua_State *L) {
    int n = lua_gettop(L);

    if (n != 3) {
        lua_pushliteral(L, "incorrect number of arguments");
        lua_error(L);
    }

    if (!lua_isstring(L, 1)) {
        lua_pushliteral(L, "incorrect 1st argument");
        lua_error(L);
    }
    const char *line = lua_tostring(L, 1);
    if (line == NULL) {
        lua_pushliteral(L, "can't access to log line");
        lua_error(L);
    }

    if (!lua_isnumber(L, 2)) {
        lua_pushliteral(L, "incorrect 2nd argument");
        lua_error(L);
    }
    size_t len = lua_tointeger(L, 2);

    if (!lua_isnumber(L, 3)) {
        lua_pushliteral(L, "incorrect 3nd argument");
        lua_error(L);
    }
    loglinetype ltype = lua_tointeger(L, 3);

    logdata l;
    memset(&l, '\0', sizeof(logdata));

    parse((char *)line, len, ltype, &l);

    lua_newtable(L);
    int maintable = lua_gettop(L);

    lua_pushstring(L, "linelen");
    lua_pushinteger(L, l.linelen);
    lua_settable(L, maintable);

    lua_pushstring(L, "is_modsecline");
    lua_pushinteger(L, l.is_modsecline);
    lua_settable(L, maintable);

    lua_pushstring(L, "is_broken");
    lua_pushinteger(L, l.is_broken);
    lua_settable(L, maintable);

    lua_pushstring(L, "date_iso");
    lua_pushstring(L, l.date_iso);
    lua_settable(L, maintable);

    lua_pushstring(L, "date_epoch");
    lua_pushnumber(L, l.date_epoch);
    lua_settable(L, maintable);

    lua_pushstring(L, "client");
    lua_pushstring(L, l.client);
    lua_settable(L, maintable);

    lua_pushstring(L, "modseclinetype");
    lua_pushinteger(L, l.modseclinetype);
    lua_settable(L, maintable);

    lua_pushstring(L, "modsecmsg");
    lua_pushstring(L, l.modsecmsg);
    lua_settable(L, maintable);

    lua_pushstring(L, "modsecmsglen");
    lua_pushinteger(L, l.modsecmsglen);
    lua_settable(L, maintable);

    lua_pushstring(L, "modsecdenymsg");
    lua_pushstring(L, l.modsecdenymsg);
    lua_settable(L, maintable);

    lua_pushstring(L, "modsecmsgreason");
    lua_pushstring(L, l.modsecmsgreason);
    lua_settable(L, maintable);

    lua_pushstring(L, "modsecmsgop");
    lua_pushstring(L, l.modsecmsgop);
    lua_settable(L, maintable);

    lua_pushstring(L, "modsecmsgoperand");
    lua_pushstring(L, l.modsecmsgoperand);
    lua_settable(L, maintable);

    lua_pushstring(L, "modsecmsgtrgname");
    lua_pushstring(L, l.modsecmsgtrgname);
    lua_settable(L, maintable);

    lua_pushstring(L, "modsecmsgtrgvalue");
    lua_pushstring(L, l.modsecmsgtrgvalue);
    lua_settable(L, maintable);

    lua_pushstring(L, "ruleerror");
    lua_pushstring(L, l.ruleerror);
    lua_settable(L, maintable);

    lua_pushstring(L, "file");
    lua_pushstring(L, l.file);
    lua_settable(L, maintable);

    lua_pushstring(L, "line");
    lua_pushstring(L, l.line);
    lua_settable(L, maintable);

    lua_pushstring(L, "id");
    lua_pushstring(L, l.id);
    lua_settable(L, maintable);

    lua_pushstring(L, "rev");
    lua_pushstring(L, l.rev);
    lua_settable(L, maintable);

    lua_pushstring(L, "msg");
    lua_pushstring(L, l.msg);
    lua_settable(L, maintable);

    lua_pushstring(L, "data");
    lua_pushstring(L, l.data);
    lua_settable(L, maintable);

    lua_pushstring(L, "severity");
    lua_pushstring(L, l.severity);
    lua_settable(L, maintable);

    lua_pushstring(L, "version");
    lua_pushstring(L, l.version);
    lua_settable(L, maintable);

    lua_pushstring(L, "maturity");
    lua_pushstring(L, l.maturity);
    lua_settable(L, maintable);

    lua_pushstring(L, "accuracy");
    lua_pushstring(L, l.accuracy);
    lua_settable(L, maintable);

    lua_pushstring(L, "tagcnt");
    lua_pushinteger(L, l.tagcnt);
    lua_settable(L, maintable);

    lua_pushstring(L, "tags");

    lua_newtable(L);
    int subtable = lua_gettop(L);
    int ti = 0;
    for(size_t ti = 0; ti < l.tagcnt; ti++) {
        lua_pushinteger(L, ti+1);
        lua_pushstring(L, l.tags);
        lua_settable(L, subtable);
        l.tags += strlen(l.tags) + 1;
    }
    lua_settable(L, maintable);


    lua_pushstring(L, "hostname");
    lua_pushstring(L, l.hostname);
    lua_settable(L, maintable);

    lua_pushstring(L, "uri");
    lua_pushstring(L, l.uri);
    lua_settable(L, maintable);

    lua_pushstring(L, "unique_id");
    lua_pushstring(L, l.unique_id);
    lua_settable(L, maintable);


    lua_pushstring(L, "lineerrcnt");
    lua_pushinteger(L, l.lineerrcnt);
    lua_settable(L, maintable);


    lua_pushstring(L, "lineerrors");
    lua_newtable(L);
    int errorstable = lua_gettop(L);

    if (l.lineerrcnt > 0) {
        // reset errpool ptr
        l.lineerrpool.currptr = l.lineerrpool.pool;
        msclogerr logerr;
        for (int c=0; c < l.lineerrcnt; c++) {
            read_msclog_err(&l.lineerrpool, &logerr);
            lua_pushinteger(L, c+1);
            lua_pushstring(L, logerr.errmsg);
            lua_settable(L, errorstable);            
        }
    }

    lua_settable(L, maintable);


    lua_pushstring(L, "lineerrorspos");
    lua_newtable(L);
    int errorspostable = lua_gettop(L);

    if (l.lineerrcnt > 0) {
        // reset errpool ptr
        l.lineerrpool.currptr = l.lineerrpool.pool;
        msclogerr logerr;
        for (int c=0; c < l.lineerrcnt; c++) {
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

    lua_settable(L, maintable);

    return 1;
}

int luaopen_msclualogparser(lua_State *L) {
    lua_newtable(L);
    lua_pushcfunction (L, msclualogparser_parse);
    lua_setfield (L, -2, "parse");


    lua_pushstring(L, "LOG_TYPE_APACHE");
    lua_pushnumber(L, LOG_TYPE_APACHE);
    lua_settable(L, -3);

    lua_pushstring(L, "LOG_TYPE_NGINX");
    lua_pushnumber(L, LOG_TYPE_NGINX);
    lua_settable(L, -3);

    lua_pushstring(L, "LOGMSG_UNKNOWN");
    lua_pushnumber(L, LOGMSG_UNKNOWN);
    lua_settable(L, -3);

    lua_pushstring(L, "LOGMSG_WARNING");
    lua_pushnumber(L, LOGMSG_WARNING);
    lua_settable(L, -3);

    lua_pushstring(L, "LOGMSG_ACCDENIED");
    lua_pushnumber(L, LOGMSG_ACCDENIED);
    lua_settable(L, -3);

    lua_pushstring(L, "LOGMSG_REQBODY");
    lua_pushnumber(L, LOGMSG_REQBODY);
    lua_settable(L, -3);

    lua_pushstring(L, "LOGMSG_ERROR");
    lua_pushnumber(L, LOGMSG_ERROR);
    lua_settable(L, -3);

    lua_pushstring(L, "LOGMSG_AUDITLOG");
    lua_pushnumber(L, LOGMSG_AUDITLOG);
    lua_settable(L, -3);

    lua_pushstring(L, "LIBRARY_VERSION");
    lua_pushstring(L, MSCLOGPARSER_VERSION);
    lua_settable(L, -3);

    lua_pushstring(L, "MODULE_VERSION");
    lua_pushstring(L, MODULE_VERSION);
    lua_settable(L, -3);
 
    return 1;
}