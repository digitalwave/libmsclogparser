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

#define COMPILE_DL_MSCPHPLOGPARSER 1

#include "php.h"
#include "ext/standard/info.h"

#include "msclogparser.h"

#define MODULE_VERSION "0.1.0"

extern zend_module_entry mscphplogparser_module_entry;
# define phpext_mscphplogparser_ptr &mscphplogparser_module_entry

# define PHP_MSCPHPLOGPARSER_VERSION "0.1"


PHP_MINIT_FUNCTION(mscphplogparser);
PHP_RINIT_FUNCTION(mscphplogparser);
PHP_MINFO_FUNCTION(mscphplogparser);
PHP_FUNCTION(parse);

# if defined(ZTS) && defined(COMPILE_DL_MSCPHPLOGPARSER)
ZEND_TSRMLS_CACHE_EXTERN()
# endif

static zend_class_entry *logparser_lp = NULL;

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
    ZEND_PARSE_PARAMETERS_START(0, 0) \
    ZEND_PARSE_PARAMETERS_END()
#endif

PHP_FUNCTION(parse)
{
    zend_string  *line;
    zend_long     len;
    zend_long     ltype;

    zend_string *retval;

    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sll", &line, &len, &ltype) == FAILURE) {
        return;
    }

    logdata l;
    memset(&l, '\0', sizeof(logdata));

    parse(ZSTR_VAL(line), (size_t)len, (loglinetype)ltype, &l);

    zval arr, tags, errors, errorspos;
    array_init(&arr);

    add_assoc_long(&arr,   "linelen",       l.linelen);
    add_assoc_long(&arr,   "is_modsecline", l.is_modsecline);
    add_assoc_long(&arr,   "is_broken",     l.is_broken);
    add_assoc_string(&arr, "date_iso",      l.date_iso);
    add_assoc_double(&arr, "date_epoch",    l.date_epoch);
    add_assoc_string(&arr, "client",        l.client);
    add_assoc_long(&arr,   "modseclinetype", l.modseclinetype);
    add_assoc_string(&arr, "modsecmsg",     l.modsecmsg);
    add_assoc_long(&arr,   "modsecmsglen",  l.modsecmsglen);
    add_assoc_string(&arr, "modsecdenymsg", l.modsecdenymsg);
    add_assoc_string(&arr, "modsecmsgreason",   l.modsecmsgreason);
    add_assoc_string(&arr, "modsecmsgop",   l.modsecmsgop);
    add_assoc_string(&arr, "modsecmsgoperand",  l.modsecmsgoperand);
    add_assoc_string(&arr, "modsecmsgtrgname",  l.modsecmsgtrgname);
    add_assoc_string(&arr, "modsecmsgtrgvalue", l.modsecmsgtrgvalue);
    add_assoc_string(&arr, "ruleerror",     l.ruleerror);
    add_assoc_string(&arr, "file",          l.file);
    add_assoc_string(&arr, "line",          l.line);
    add_assoc_string(&arr, "id",            l.id);
    add_assoc_string(&arr, "rev",           l.rev);
    add_assoc_string(&arr, "msg",           l.msg);
    add_assoc_string(&arr, "data",          l.data);
    add_assoc_string(&arr, "severity",      l.severity);
    add_assoc_string(&arr, "version",       l.version);
    add_assoc_string(&arr, "maturity",      l.maturity);
    add_assoc_string(&arr, "accuracy",      l.accuracy);

    add_assoc_long(&arr,   "tagcnt",        l.tagcnt);

    array_init(&tags);
    for(size_t ti = 0; ti < l.tagcnt; ti++) {
        add_next_index_string(&tags, l.tags);
        l.tags += strlen(l.tags) + 1;
    }
    add_assoc_zval(&arr, "tags", &tags);

    add_assoc_string(&arr, "hostname",      l.hostname);
    add_assoc_string(&arr, "uri",           l.uri);
    add_assoc_string(&arr, "unique_id",     l.unique_id);

    add_assoc_long(&arr,   "lineerrcnt",    l.lineerrcnt);
    array_init(&errors);
    array_init(&errorspos);

    if (l.lineerrcnt > 0) {
        // reset errpool ptr
        l.lineerrpool.currptr = l.lineerrpool.pool;
        msclogerr logerr;
        for (int c=0; c < l.lineerrcnt; c++) {
            read_msclog_err(&l.lineerrpool, &logerr);
            add_next_index_string(&errors, logerr.errmsg);
            zval pairs;
            array_init(&pairs);
            add_next_index_long(&pairs, *logerr.startpos);
            add_next_index_long(&pairs, *logerr.endpos);
            add_next_index_zval(&errorspos, &pairs);
        }
    }

    add_assoc_zval(&arr, "lineerrors", &errors);
    add_assoc_zval(&arr, "lineerrorspos", &errorspos);


    RETURN_ZVAL(&arr, 0, 1);

}

// functions
static const zend_function_entry mscphplogparser_functions[] = {
    PHP_FE(parse,        NULL)
    PHP_FE_END
};

PHP_MINIT_FUNCTION(mscphplogparser) {
#if defined(ZTS) && defined(COMPILE_DL_TEST)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif

    REGISTER_LONG_CONSTANT("LOG_TYPE_APACHE", LOG_TYPE_APACHE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("LOG_TYPE_NGINX",  LOG_TYPE_NGINX,  CONST_CS | CONST_PERSISTENT);

    REGISTER_LONG_CONSTANT("LOGMSG_UNKNOWN", LOGMSG_UNKNOWN, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("LOGMSG_WARNING", LOGMSG_WARNING, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("LOGMSG_ACCDENIED", LOGMSG_ACCDENIED, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("LOGMSG_REQBODY", LOGMSG_REQBODY, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("LOGMSG_ERROR", LOGMSG_ERROR, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("LOGMSG_AUDITLOG", LOGMSG_AUDITLOG, CONST_CS | CONST_PERSISTENT);


    REGISTER_STRING_CONSTANT("LIBRARY_VERSION",  MSCLOGPARSER_VERSION,  CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("MODULE_VERSION",  MODULE_VERSION,  CONST_CS | CONST_PERSISTENT);

    return SUCCESS;
}

PHP_RINIT_FUNCTION(mscphplogparser)
{
#if defined(ZTS) && defined(COMPILE_DL_MSCPHPLOGPARSER)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif

    return SUCCESS;
}

PHP_MINFO_FUNCTION(mscphplogparser)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "mscphplogparser support", "enabled");
    php_info_print_table_end();
}

zend_module_entry mscphplogparser_module_entry = {
    STANDARD_MODULE_HEADER,
    "mscphplogparser",                       /* Extension name */
    mscphplogparser_functions,               /* zend_function_entry */
    PHP_MINIT(mscphplogparser),              /* PHP_MINIT - Module initialization */
    NULL,                                    /* PHP_MSHUTDOWN - Module shutdown */
    PHP_RINIT(mscphplogparser),              /* PHP_RINIT - Request initialization */
    NULL,                                    /* PHP_RSHUTDOWN - Request shutdown */
    PHP_MINFO(mscphplogparser),              /* PHP_MINFO - Module info */
    PHP_MSCPHPLOGPARSER_VERSION,             /* Version */
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_MSCPHPLOGPARSER
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(mscphplogparser)
#endif
