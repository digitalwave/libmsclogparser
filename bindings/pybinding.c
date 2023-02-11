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

#include <stdio.h>
#include <string.h>
#include <Python.h>
#include "msclogparser.h"


#define MODULE_VERSION "0.1.0"

static char mscpylogparser_parse_doc[] = "parse(line, len, type) - Parse a ModSecurity generated error.log.";

static PyObject* mscpylogparser_parse(PyObject *self, PyObject *args) {
    char       *line = NULL;
    size_t      len;
    loglinetype ltype;
    logdata     l;

    if (!PyArg_ParseTuple(args, "ski", &line, &len, &ltype)) {
        PyErr_SetString(PyExc_TypeError, "one or more argument missing.");
        return NULL;
    }

    memset(&l, '\0', sizeof(logdata));

    parse(line, len, ltype, &l);

    PyObject *tags = PyList_New(0);

    for(size_t i = 0; i < l.tagcnt; i++) {
        PyList_Append(tags, Py_BuildValue("s", l.tags));
        l.tags += strlen(l.tags) + 1;
    }


    PyObject *errors = PyList_New(0);
    PyObject *errorspos = PyList_New(0);

    if (l.lineerrcnt > 0) {
        // reset errpool ptr
        l.lineerrpool.currptr = l.lineerrpool.pool;
        msclogerr logerr;
        for (int c=0; c < l.lineerrcnt; c++) {
            read_msclog_err(&l.lineerrpool, &logerr);
            PyList_Append(errors, Py_BuildValue("s", logerr.errmsg));
            PyList_Append(errorspos, Py_BuildValue("[k,k]", *logerr.startpos, *logerr.endpos));
        }
    }

    PyObject * rv = Py_BuildValue("{s:k,s:i,s:i,s:s,s:f,s:s,s:i,s:s,s:k,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:i,s:O,s:s,s:s,s:s,s:i,s:O,s:O}",
        "linelen",           l.linelen,
        "is_modsecline",     l.is_modsecline,
        "is_broken",         l.is_broken,
        "date_iso",          l.date_iso,
        "date_epoch",        l.date_epoch,
        "client",            l.client,
        "modseclinetype",    l.modseclinetype,
        "modsecmsg",         l.modsecmsg,
        "modsecmsglen",      l.modsecmsglen,
        "modsecdenymsg",     l.modsecdenymsg,
        "modsecmsgreason",   l.modsecmsgreason,
        "modsecmsgop",       l.modsecmsgop,
        "modsecmsgoperand",  l.modsecmsgoperand,
        "modsecmsgtrgname",  l.modsecmsgtrgname,
        "modsecmsgtrgvalue", l.modsecmsgtrgvalue,
        "ruleerror",         l.ruleerror,
        "file",              l.file,
        "line",              l.line,
        "id",                l.id,
        "rev",               l.rev,
        "msg",               l.msg,
        "data",              l.data,
        "severity",          l.severity,
        "version",           l.version,
        "maturity",          l.maturity,
        "accuracy",          l.accuracy,
        "tagcnt",            l.tagcnt,
        "tags",              tags,
        "hostname",          l.hostname,
        "uri",               l.uri,
        "unique_id",         l.unique_id,
        "lineerrorcnt",      l.lineerrcnt,
        "lineerrors",        errors,
        "lineerrorspos",     errorspos
    );

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


