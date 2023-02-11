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

#include "ruby.h"

#include "msclogparser.h"

#define MODULE_VERSION "0.1.0"

static VALUE mscrubylogparser_parse(VALUE self, VALUE arg1, VALUE arg2, VALUE arg3) {

    const char *line  = StringValueCStr(arg1);
    size_t      len   = NUM2INT(arg2);
    loglinetype ltype = NUM2INT(arg3);

    logdata l;
    memset(&l, '\0', sizeof(logdata));

    parse((char *)line, len, ltype, &l);

    VALUE result = rb_hash_new();

    rb_hash_aset(result, ID2SYM(rb_intern("linelen")), INT2NUM(l.linelen));
    rb_hash_aset(result, ID2SYM(rb_intern("is_modsecline")), INT2NUM(l.is_modsecline));
    rb_hash_aset(result, ID2SYM(rb_intern("is_broken")), INT2NUM(l.is_broken));
    rb_hash_aset(result, ID2SYM(rb_intern("date_iso")), rb_str_new2(l.date_iso));
    rb_hash_aset(result, ID2SYM(rb_intern("date_epoch")), DBL2NUM(l.date_epoch));
    rb_hash_aset(result, ID2SYM(rb_intern("client")), rb_str_new2(l.client));
    rb_hash_aset(result, ID2SYM(rb_intern("modseclinetype")), INT2NUM(l.modseclinetype));
    rb_hash_aset(result, ID2SYM(rb_intern("modsecmsg")), rb_str_new2(l.modsecmsg));
    rb_hash_aset(result, ID2SYM(rb_intern("modsecmsglen")), INT2NUM(l.modsecmsglen));
    rb_hash_aset(result, ID2SYM(rb_intern("modsecdenymsg")), rb_str_new2(l.modsecdenymsg));
    rb_hash_aset(result, ID2SYM(rb_intern("modsecmsgreason")), rb_str_new2(l.modsecmsgreason));
    rb_hash_aset(result, ID2SYM(rb_intern("modsecmsgop")), rb_str_new2(l.modsecmsgop));
    rb_hash_aset(result, ID2SYM(rb_intern("modsecmsgoperand")), rb_str_new2(l.modsecmsgoperand));
    rb_hash_aset(result, ID2SYM(rb_intern("modsecmsgtrgname")), rb_str_new2(l.modsecmsgtrgname));
    rb_hash_aset(result, ID2SYM(rb_intern("modsecmsgtrgvalue")), rb_str_new2(l.modsecmsgtrgvalue));
    rb_hash_aset(result, ID2SYM(rb_intern("ruleerror")), rb_str_new2(l.ruleerror));
    rb_hash_aset(result, ID2SYM(rb_intern("file")), rb_str_new2(l.file));
    rb_hash_aset(result, ID2SYM(rb_intern("line")), rb_str_new2(l.line));
    rb_hash_aset(result, ID2SYM(rb_intern("id")), rb_str_new2(l.id));

    rb_hash_aset(result, ID2SYM(rb_intern("rev")), rb_str_new2(l.rev));
    rb_hash_aset(result, ID2SYM(rb_intern("msg")), rb_str_new2(l.msg));
    rb_hash_aset(result, ID2SYM(rb_intern("data")), rb_str_new2(l.data));

    rb_hash_aset(result, ID2SYM(rb_intern("severity")), rb_str_new2(l.severity));
    rb_hash_aset(result, ID2SYM(rb_intern("version")), rb_str_new2(l.version));
    rb_hash_aset(result, ID2SYM(rb_intern("maturity")), rb_str_new2(l.maturity));
    rb_hash_aset(result, ID2SYM(rb_intern("accuracy")), rb_str_new2(l.accuracy));

    rb_hash_aset(result, ID2SYM(rb_intern("tagcnt")), INT2NUM(l.tagcnt));

    VALUE tags = rb_ary_new();
    for(size_t ti = 0; ti < l.tagcnt; ti++) {
        rb_ary_push(tags, rb_str_new2(l.tags));
        l.tags += strlen(l.tags);
    }
    rb_hash_aset(result, ID2SYM(rb_intern("tags")), tags);

    rb_hash_aset(result, ID2SYM(rb_intern("hostname")), rb_str_new2(l.hostname));
    rb_hash_aset(result, ID2SYM(rb_intern("uri")), rb_str_new2(l.uri));
    rb_hash_aset(result, ID2SYM(rb_intern("unique_id")), rb_str_new2(l.unique_id));
    rb_hash_aset(result, ID2SYM(rb_intern("lineerrcnt")), INT2NUM(l.lineerrcnt));

    VALUE errors = rb_ary_new();
    VALUE errorspos = rb_ary_new();
    if (l.lineerrcnt > 0) {
        // reset errpool ptr
        l.lineerrpool.currptr = l.lineerrpool.pool;
        msclogerr logerr;
        for(int c = 0; c < l.lineerrcnt; c++) {
            read_msclog_err(&l.lineerrpool, &logerr);
            rb_ary_push(errors, rb_str_new2(logerr.errmsg));
            rb_ary_push(errorspos, rb_ary_new3(2, INT2NUM(*logerr.startpos), INT2NUM(*logerr.endpos)));
        }
    }
    rb_hash_aset(result, ID2SYM(rb_intern("lineerrors")), errors);
    rb_hash_aset(result, ID2SYM(rb_intern("lineerrorspos")), errorspos);


    return result;
}

void Init_mscrubylogparser(void) {

    rb_define_method(rb_cObject, "parse", mscrubylogparser_parse, 3);

    rb_define_const(rb_cObject, "LOG_TYPE_APACHE", INT2NUM(LOG_TYPE_APACHE));
    rb_define_const(rb_cObject, "LOG_TYPE_NGINX", INT2NUM(LOG_TYPE_NGINX));

    rb_define_const(rb_cObject, "LOGMSG_UNKNOWN", INT2NUM(LOGMSG_UNKNOWN));
    rb_define_const(rb_cObject, "LOGMSG_WARNING", INT2NUM(LOGMSG_WARNING));
    rb_define_const(rb_cObject, "LOGMSG_ACCDENIED",INT2NUM( LOGMSG_ACCDENIED));
    rb_define_const(rb_cObject, "LOGMSG_REQBODY", INT2NUM(LOGMSG_REQBODY));
    rb_define_const(rb_cObject, "LOGMSG_ERROR", INT2NUM(LOGMSG_ERROR));
    rb_define_const(rb_cObject, "LOGMSG_AUDITLOG", INT2NUM(LOGMSG_AUDITLOG));

    rb_define_const(rb_cObject, "LIBRARY_VERSION", rb_str_new2(MSCLOGPARSER_VERSION));
    rb_define_const(rb_cObject, "MODULE_VERSION", rb_str_new2(MODULE_VERSION));
}
