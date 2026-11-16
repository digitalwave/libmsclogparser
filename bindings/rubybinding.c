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

#include "ruby.h"
#include "ruby/encoding.h"

#include "../src/msclogparser.h"

#define MODULE_VERSION "3.0.0"

// the len argument is bigger than the line: the line is parsed with its own
// length, and this error is added
#define MSCLEN_ERROR_FMT "The given length (%zu) is bigger than the line (%zu bytes)!"

static VALUE mscrubylogparser_parse(VALUE self, VALUE arg1, VALUE arg2, VALUE arg3) {

    // a NUL character in the line is reported by parse(), like in the other
    // bindings (StringValueCStr() would raise an ArgumentError for it)
    const char  *line  = StringValuePtr(arg1);
    size_t       linelen = RSTRING_LEN(arg1);
    ssize_t      slen  = NUM2SSIZET(arg2);
    if (slen < 0) {
        rb_raise(rb_eArgError, "len must not be negative");
    }
    size_t       len   = (size_t)slen;
    int          itype = NUM2INT(arg3);
    if (itype != LOG_TYPE_APACHE && itype != LOG_TYPE_NGINX) {
        rb_raise(rb_eArgError, "ltype must be LOG_TYPE_APACHE or LOG_TYPE_NGINX");
    }
    loglinetype  ltype = (loglinetype)itype;
    // the values are parts of the line, they get its encoding
    rb_encoding *enc   = rb_enc_get(arg1);

    // a len bigger than the line would make parse() read after its end: the
    // line is parsed with its own length, and the error is reported
    size_t givenlen = len;
    int lenerr = len > linelen;
    if (lenerr) {
        len = linelen;
    }

    logdata l;
    parse(line, len, ltype, &l);
    if (lenerr) {
        l.entry_is_broken = 1;
    }

    VALUE result = rb_hash_new();

    rb_hash_aset(result, ID2SYM(rb_intern("entry_is_modsecline")), INT2NUM(l.entry_is_modsecline));
    rb_hash_aset(result, ID2SYM(rb_intern("entry_is_broken")), INT2NUM(l.entry_is_broken));
    rb_hash_aset(result, ID2SYM(rb_intern("log_entry_raw_length")), SIZET2NUM(l.log_entry_raw_length));
    rb_hash_aset(result, ID2SYM(rb_intern("log_date_iso")), rb_enc_str_new_cstr(l.log_date_iso, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_date_timestamp")), DBL2NUM(l.log_date_timestamp));
    rb_hash_aset(result, ID2SYM(rb_intern("log_client")), rb_enc_str_new_cstr(l.log_client, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_entry_class")), INT2NUM(l.log_entry_class));
    rb_hash_aset(result, ID2SYM(rb_intern("log_modsec_msg")), rb_enc_str_new_cstr(l.log_modsec_msg, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_modsec_msg_length")), SIZET2NUM(l.log_modsec_msg_length));
    rb_hash_aset(result, ID2SYM(rb_intern("log_modsec_reason")), rb_enc_str_new_cstr(l.log_modsec_reason, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_modsec_operator")), rb_enc_str_new_cstr(l.log_modsec_operator, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_modsec_operand")), rb_enc_str_new_cstr(l.log_modsec_operand, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_modsec_target_name")), rb_enc_str_new_cstr(l.log_modsec_target_name, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_modsec_target_value")), rb_enc_str_new_cstr(l.log_modsec_target_value, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_modsec_process_error")), rb_enc_str_new_cstr(l.log_modsec_process_error, enc));

    rb_hash_aset(result, ID2SYM(rb_intern("log_rule_file")), rb_enc_str_new_cstr(l.log_rule_file, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_rule_line")), rb_enc_str_new_cstr(l.log_rule_line, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_rule_id")), rb_enc_str_new_cstr(l.log_rule_id, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_rule_rev")), rb_enc_str_new_cstr(l.log_rule_rev, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_rule_msg")), rb_enc_str_new_cstr(l.log_rule_msg, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_rule_data")), rb_enc_str_new_cstr(l.log_rule_data, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_rule_severity")), rb_enc_str_new_cstr(l.log_rule_severity, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_rule_version")), rb_enc_str_new_cstr(l.log_rule_version, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_rule_maturity")), rb_enc_str_new_cstr(l.log_rule_maturity, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_rule_accuracy")), rb_enc_str_new_cstr(l.log_rule_accuracy, enc));

    rb_hash_aset(result, ID2SYM(rb_intern("log_rule_tags_cnt")), SIZET2NUM(l.log_rule_tags_cnt));

    VALUE tags = rb_ary_new();
    for(size_t ti = 0; ti < l.log_rule_tags_cnt; ti++) {
        rb_ary_push(tags, rb_enc_str_new_cstr(l.log_rule_tags, enc));
        l.log_rule_tags += strlen(l.log_rule_tags) + 1;
    }
    rb_hash_aset(result, ID2SYM(rb_intern("log_rule_tags")), tags);

    rb_hash_aset(result, ID2SYM(rb_intern("log_hostname")), rb_enc_str_new_cstr(l.log_hostname, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_uri")), rb_enc_str_new_cstr(l.log_uri, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_unique_id")), rb_enc_str_new_cstr(l.log_unique_id, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_server")), rb_enc_str_new_cstr(l.log_server, enc));
    rb_hash_aset(result, ID2SYM(rb_intern("log_entry_errors_cnt")), INT2NUM(l.log_entry_errors_cnt + lenerr));

    VALUE errors = rb_ary_new();
    VALUE errorspos = rb_ary_new();
    if (l.log_entry_errors_cnt > 0) {
        // reset errpool ptr
        l.lineerrpool.currptr = l.lineerrpool.pool;
        msclogerr logerr;
        for(int c = 0; c < l.log_entry_errors_cnt; c++) {
            read_msclog_err(&l.lineerrpool, &logerr);
            rb_ary_push(errors, rb_enc_str_new_cstr(logerr.errmsg, enc));
            rb_ary_push(errorspos, rb_ary_new3(2, SIZET2NUM(*logerr.startpos), SIZET2NUM(*logerr.endpos)));
        }
    }
    if (lenerr) {
        char msg[128];
        snprintf(msg, sizeof(msg), MSCLEN_ERROR_FMT, givenlen, linelen);
        rb_ary_push(errors, rb_enc_str_new_cstr(msg, enc));
        rb_ary_push(errorspos, rb_ary_new3(2, SIZET2NUM(linelen), SIZET2NUM(givenlen)));
    }
    rb_hash_aset(result, ID2SYM(rb_intern("log_entry_errors")), errors);
    rb_hash_aset(result, ID2SYM(rb_intern("log_entry_errors_pos")), errorspos);


    return result;
}

void Init_mscrubylogparser(void) {

    VALUE mod = rb_define_module("MscRubyLogParser");

    rb_define_module_function(mod, "parse", mscrubylogparser_parse, 3);

    rb_define_const(mod, "LOG_TYPE_APACHE", INT2NUM(LOG_TYPE_APACHE));
    rb_define_const(mod, "LOG_TYPE_NGINX", INT2NUM(LOG_TYPE_NGINX));

    rb_define_const(mod, "LOGMSG_UNKNOWN", INT2NUM(LOGMSG_UNKNOWN));
    rb_define_const(mod, "LOGMSG_WARNING", INT2NUM(LOGMSG_WARNING));
    rb_define_const(mod, "LOGMSG_ACCDENIED", INT2NUM(LOGMSG_ACCDENIED));
    rb_define_const(mod, "LOGMSG_REQBODY", INT2NUM(LOGMSG_REQBODY));
    rb_define_const(mod, "LOGMSG_ERROR", INT2NUM(LOGMSG_ERROR));
    rb_define_const(mod, "LOGMSG_AUDITLOG", INT2NUM(LOGMSG_AUDITLOG));

    rb_define_const(mod, "LIBRARY_VERSION", rb_str_new2(MSCLOGPARSER_VERSION));
    rb_define_const(mod, "MODULE_VERSION", rb_str_new2(MODULE_VERSION));
}
