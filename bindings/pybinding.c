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

#include <stdio.h>
#include <string.h>
#include <Python.h>
#include "../src/msclogparser.h"


#define MODULE_VERSION "3.0.0"

// the len argument is bigger than the line: the line is parsed with its own
// length, and this error is added
#define MSCLEN_ERROR_FMT "The given length (%zu) is bigger than the line (%zu bytes)!"

static char mscpylogparser_parse_doc[] = "parse(line, len, type) - Parse a ModSecurity generated error.log line.\n\n"
    "line is str or bytes, len is its length in bytes. The values of the fields\n"
    "are str if line is str, and bytes if line is bytes.";

// the result: the values of the fields are S, "s" (str) or "y" (bytes)
#define MSCPY_RESULT_FORMAT(S) \
    "{s:i,s:i,s:k,s:" S ",s:f,s:" S ",s:i,s:" S ",s:k," \
    "s:" S ",s:" S ",s:" S ",s:" S ",s:" S ",s:" S "," \
    "s:" S ",s:" S ",s:" S ",s:" S ",s:" S ",s:" S ",s:" S ",s:" S ",s:" S ",s:" S "," \
    "s:k,s:O,s:" S ",s:" S ",s:" S ",s:" S ",s:i,s:O,s:O}"

// append a new reference to the list, and release it
// returns -1 (with the exception set) if item is NULL or the append fails
static int list_append_new(PyObject *list, PyObject *item) {
    if (item == NULL) {
        return -1;
    }
    int rc = PyList_Append(list, item);
    Py_DECREF(item);
    return rc;
}

static PyObject* mscpylogparser_parse(PyObject *self, PyObject *args) {
    PyObject     *lineobj = NULL;
    char         *line = NULL;
    Py_ssize_t    linelen = 0;
    Py_ssize_t    len;
    int           ltype;
    logdata       l;

    // PyArg_ParseTuple() sets the exception that tells what is wrong
    if (!PyArg_ParseTuple(args, "Oni", &lineobj, &len, &ltype)) {
        return NULL;
    }
    if (len < 0) {
        PyErr_SetString(PyExc_ValueError, "len must not be negative");
        return NULL;
    }

    // a bytes line can be parsed without decoding it, eg. if it isn't valid UTF-8
    int as_bytes = PyBytes_Check(lineobj);
    if (as_bytes) {
        if (PyBytes_AsStringAndSize(lineobj, &line, &linelen) < 0) {
            return NULL;
        }
    }
    else if (PyUnicode_Check(lineobj)) {
        line = (char *)PyUnicode_AsUTF8AndSize(lineobj, &linelen);
        if (line == NULL) {
            return NULL;
        }
    }
    else {
        PyErr_Format(PyExc_TypeError, "argument 1 must be str or bytes, not %.200s",
                     Py_TYPE(lineobj)->tp_name);
        return NULL;
    }
    if (strlen(line) != (size_t)linelen) {
        PyErr_SetString(PyExc_ValueError, "embedded null character");
        return NULL;
    }

    // a len bigger than the line would make parse() read after its end: the
    // line is parsed with its own length, and the error is reported
    size_t givenlen = (size_t)len;
    int lenerr = givenlen > (size_t)linelen;
    if (lenerr) {
        len = linelen;
    }

    parse(line, (size_t)len, (loglinetype)ltype, &l);

    PyObject *tags = PyList_New(0);
    PyObject *errors = PyList_New(0);
    PyObject *errorspos = PyList_New(0);
    PyObject *rv = NULL;

    if (tags == NULL || errors == NULL || errorspos == NULL) {
        goto cleanup;
    }

    for(size_t i = 0; i < l.log_rule_tags_cnt; i++) {
        if (list_append_new(tags, Py_BuildValue(as_bytes ? "y" : "s", l.log_rule_tags)) < 0) {
            goto cleanup;
        }
        l.log_rule_tags += strlen(l.log_rule_tags) + 1;
    }

    if (l.log_entry_errors_cnt > 0) {
        // reset errpool ptr
        l.lineerrpool.currptr = l.lineerrpool.pool;
        msclogerr logerr;
        for (int c=0; c < l.log_entry_errors_cnt; c++) {
            read_msclog_err(&l.lineerrpool, &logerr);
            if (list_append_new(errors, Py_BuildValue("s", logerr.errmsg)) < 0 ||
                list_append_new(errorspos, Py_BuildValue("[k,k]", (unsigned long)*logerr.startpos, (unsigned long)*logerr.endpos)) < 0) {
                goto cleanup;
            }
        }
    }

    if (lenerr) {
        char msg[128];
        snprintf(msg, sizeof(msg), MSCLEN_ERROR_FMT, givenlen, (size_t)linelen);
        if (list_append_new(errors, Py_BuildValue("s", msg)) < 0 ||
            list_append_new(errorspos, Py_BuildValue("[k,k]", (unsigned long)linelen, (unsigned long)givenlen)) < 0) {
            goto cleanup;
        }
        l.entry_is_broken = 1;
        l.log_entry_errors_cnt++;
    }

    rv = Py_BuildValue(as_bytes ? MSCPY_RESULT_FORMAT("y") : MSCPY_RESULT_FORMAT("s"),
        "entry_is_modsecline",        l.entry_is_modsecline,
        "entry_is_broken",            l.entry_is_broken,
        "log_entry_raw_length",       (unsigned long)l.log_entry_raw_length,
        "log_date_iso",               l.log_date_iso,
        "log_date_timestamp",         l.log_date_timestamp,
        "log_client",                 l.log_client,
        "log_entry_class",            (int)l.log_entry_class,
        "log_modsec_msg",             l.log_modsec_msg,
        "log_modsec_msg_length",      (unsigned long)l.log_modsec_msg_length,
        "log_modsec_reason",          l.log_modsec_reason,
        "log_modsec_operator",        l.log_modsec_operator,
        "log_modsec_operand",         l.log_modsec_operand,
        "log_modsec_target_name",     l.log_modsec_target_name,
        "log_modsec_target_value",    l.log_modsec_target_value,
        "log_modsec_process_error",   l.log_modsec_process_error,
        "log_rule_file",              l.log_rule_file,
        "log_rule_line",              l.log_rule_line,
        "log_rule_id",                l.log_rule_id,
        "log_rule_rev",               l.log_rule_rev,
        "log_rule_msg",               l.log_rule_msg,
        "log_rule_data",              l.log_rule_data,
        "log_rule_severity",          l.log_rule_severity,
        "log_rule_version",           l.log_rule_version,
        "log_rule_maturity",          l.log_rule_maturity,
        "log_rule_accuracy",          l.log_rule_accuracy,
        "log_rule_tags_cnt",          (unsigned long)l.log_rule_tags_cnt,
        "log_rule_tags",              tags,
        "log_hostname",               l.log_hostname,
        "log_uri",                    l.log_uri,
        "log_unique_id",              l.log_unique_id,
        "log_server",                 l.log_server,
        "log_entry_errors_cnt",       l.log_entry_errors_cnt,
        "log_entry_errors",           errors,
        "log_entry_errors_pos",       errorspos
    );

cleanup:
    // Py_BuildValue("O") and PyList_Append() take their own references
    Py_XDECREF(tags);
    Py_XDECREF(errors);
    Py_XDECREF(errorspos);

    return rv;
}

static PyMethodDef mscpylogparser_methods[] = {
    {"parse", mscpylogparser_parse, METH_VARARGS, mscpylogparser_parse_doc},
    {NULL, NULL}
};

static struct PyModuleDef mscpylogparser = {
    PyModuleDef_HEAD_INIT,
    "mscpylogparser",
    "Python interface for parsing ModSecurity generated error.log lines",
    -1,
    mscpylogparser_methods
};

PyMODINIT_FUNC PyInit_mscpylogparser(void) {

    PyObject *module = PyModule_Create(&mscpylogparser);
    if (module == NULL) {
        return NULL;
    }

    PyModule_AddIntConstant(module, "LOG_TYPE_APACHE", LOG_TYPE_APACHE);
    PyModule_AddIntConstant(module, "LOG_TYPE_NGINX", LOG_TYPE_NGINX);

    PyModule_AddIntConstant(module, "LOGMSG_UNKNOWN", LOGMSG_UNKNOWN);
    PyModule_AddIntConstant(module, "LOGMSG_WARNING", LOGMSG_WARNING);
    PyModule_AddIntConstant(module, "LOGMSG_ACCDENIED", LOGMSG_ACCDENIED);
    PyModule_AddIntConstant(module, "LOGMSG_REQBODY", LOGMSG_REQBODY);
    PyModule_AddIntConstant(module, "LOGMSG_ERROR", LOGMSG_ERROR);
    PyModule_AddIntConstant(module, "LOGMSG_AUDITLOG", LOGMSG_AUDITLOG);

    PyModule_AddStringConstant(module, "LIBRARY_VERSION", MSCLOGPARSER_VERSION);
    PyModule_AddStringConstant(module, "MODULE_VERSION", MODULE_VERSION);

    return module;
}


