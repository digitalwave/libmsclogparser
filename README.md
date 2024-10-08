# libmsclogparser

The **libmsclogparser** is a library, which can parse ModSecurity's (both [mod_security2](https://github.com/SpiderLabs/ModSecurity/tree/v2/master) and [libmodsecurity3](https://github.com/SpiderLabs/ModSecurity/tree/v3/master)) format.

The "input" is a web server error log line, generated by ModSecurity. The output is a parsed structure.

The library is written in C, therefore you can embed it in other C, C++, Go or Rust applications. Moreover it contains several bindings for different script languages: Python, Lua, Ruby, and PHP. Bindings are also written in native C, so you don't need any code compile framework, eg. SWIG.

# Content
* [Project purpose](#project-purpose)
* [Licensing](#licensing)
* [Current version](#current-version)
* [API](#api)
  * [Constants](#constants)
    * [Constant values](#constant-values)
    * [Constant explanations](#constants-explanation)
    * [Constants in bindings](#constants-in-bindings)
  * [Structure](#structure)
    * [datapool](#datapool)
    * [entry_is_modsecline](#entry_is_modsecline)
    * [entry_is_broken](#entry_is_broken)
    * [log_entry_raw_length](#log_entry_raw_length)
    * [log_date_iso](#log_date_iso)
    * [log_date_timestamp](#log_date_timestamp)
    * [log_client](#log_client)
    * [log_entry_class](#log_entry_class)
    * [log_modsec_msg](#log_modsec_msg)
    * [log_modsec_msg_length](#log_modsec_msg_length)
    * [log_modsec_reason](#log_modsec_reason)
    * [log_modsec_operator](#log_modsec_operator)
    * [log_modsec_operand](#log_modsec_operand)
    * [log_modsec_target_name](#log_modsec_target_name)
    * [log_modsec_target_value](#log_modsec_target_value)
    * [log_modsec_process_error](#log_modsec_process_error)
    * [log_rule_file](#log_rule_file)
    * [log_rule_line](#log_rule_line)
    * [log_rule_id](#log_rule_id)
    * [log_rule_rev](#log_rule_rev)
    * [log_rule_msg](#log_rule_msg)
    * [log_rule_data](#log_rule_data)
    * [log_rule_severity](#log_rule_severity)
    * [log_rule_version](#log_rule_version)
    * [log_rule_maturity](#log_rule_maturity)
    * [log_rule_accuracy](#log_rule_accuracy)
    * [log_rule_tags_cnt](#log_rule_tags_cnt)
    * [log_rule_tags](#log_rule_tags)
    * [log_hostname](#log_hostname)
    * [log_uri](#log_uri)
    * [log_unique_id](#log_unique_id)
    * [lineerrpool](#lineerrpool)
    * [log_entry_errors_cnt](#log_entry_errors_cnt)
  * [Methods](#methods)
  * [Strucure in bindings](#strucure-in-bindings)
* [Compile, install](#compile-install)


## Project purpose

The purpose of this project is to analyze the "always present" log output of ModSecurity engines (usually the 'error.log'). As you know, there are two types of engines, and the structure of these logs is a bit different. Not only because of web servers, but in general: these log entries are made with different logic.

The writing of the code was preceded by thorough research. The expectation was that a method that knew all log formats and could recognize and show truncated (or duplicated) fields produced during known procedures.

Even though the code is written in C, but it does not use any dynamic memory handling. It also does not have any library dependecy (eg. PCRE/PCRE2). Therefore it's really fast and convenience to use it.

## Licensing

libmsclogparser is dual licensed under the following licenses. You can use the software according to the terms of your chosen license.

* [GNU Affero General Public License (AGPL) v3 with additional terms](https://www.gnu.org/licenses/agpl-3.0.html)
* Our Own Proprietary License - please contact with us

This means, we can apply any pull requests from any contributor after the agreement of our CLA. For mor information, please check our [contrbuting reference](CONTRIBUTING.md)


## Current version

The current version of library is `0.2.0`.

## API

The API provides two constants, the structure of a parsed line and a function:

### Constants

#### Constant values
```
LOG_TYPE_APACHE
LOG_TYPE_NGINX

LOGMSG_UNKNOWN
LOGMSG_WARNING
LOGMSG_ACCDENIED
LOGMSG_REQBODY
LOGMSG_ERROR
LOGMSG_AUDITLOG

LIBRARY_VERSION
MODULE_VERSION
```

#### Constants explanation
Depends on your log source, you have to use one of `LOG_TYPE_APACHE` or `LOG_TYPE_NGINX`. If you use a different type, your output structure will empty.

`LOGMSG_...` constants show the modsecurity message type. For eg. it could be "ModSecurity: Warning. Pattern match...", or "ModSecurity: Access denied. ...". Depends on these messages, the parsed structure contains the member `modseclinetype`, which can be one of these values (see belove).

`LIBRARY_VERSION` shows the current library version. It has a major, a minor and a patch version number. If library will have any modification, this version number will incremented.

`MODULE_VERSION` exists only in binding modules. This constant describes the module version, which could be different than the `LIBRARY_VERSION` (normally a bigger value), and could be different in bindings.

#### Constants in bindings
Depends on the used binding, these constants will appear in different ways: in some cases they are available through the module prefix (eg. in Python: `mscpylogparser.LOG_TYPE_APACHE`) or just simple the constant itself (eg. in Ruby: `LOG_TYPE_NGINX`). For more information, please check the test scripts.

### Structure

Originally, this is a C structure, 

```C
typedef struct logdata {
    msclogpool      datapool;
    int             entry_is_modsecline;
    int             entry_is_broken;
    size_t          log_entry_raw_length;
    char            *log_date_iso;
    double          log_date_timestamp;
    char            *log_client;
    logmsgtype      log_entry_class;
    char            *log_modsec_msg;
    size_t          log_modsec_msg_length;
    char            *log_modsec_reason;
    char            *log_modsec_operator;
    char            *log_modsec_operand;
    char            *log_modsec_target_name;
    char            *log_modsec_target_value;
    char            *log_modsec_process_error;
    char            *log_rule_file;
    char            *log_rule_line;
    char            *log_rule_id;
    char            *log_rule_rev;
    char            *log_rule_msg;
    char            *log_rule_data;
    char            *log_rule_severity;
    char            *log_rule_version;
    char            *log_rule_maturity;
    char            *log_rule_accuracy;
    size_t          log_rule_tags_cnt;
    char            *log_rule_tags;
    char            *log_hostname;
    char            *log_uri;
    char            *log_unique_id;
    msclogpool      lineerrpool;
    int             log_entry_errors_cnt;
} logdata;
```

Lets see what field contains which data.

##### `datapool`
This is a pre-allocated memory pool with fix size. Basicly, that's a structure:

```C
typedef struct msclogpool {
    char    pool[8192];
    char    *currptr;
    size_t  offset;
} msclogpool;
```

Type: `msclogpool`

This needed for the parser to work, you do not need to know about - **do not touch it or read/write it**!

##### `entry_is_modsecline`
Indicates that the line is produced by ModSecurity.

This is determined by searching for the `' ModSecurity:'` substring (please note the leading space and `:`). If found, this value is 1, otherwise 0. If 0, the common fields are not filled (`date_iso`, `date_epoch`, `client`).

Type: `int`
Eg.: `0` | `1`

##### `entry_is_broken`
Indicates that the line is produced by ModSecurity **AND** has a chunked field.

This is decided based if a field recognizable (it has at least one character, eg ` [v`) but does not have the trailing `]` or `"`. If the value is 1, then the `lineerror` will contain the reason, and `lineerrpos` (it's an array with two fields) will contain the start and end positions.

Type: `int`
Eg.: `0` | `1`

##### `log_entry_raw_length`
Contains the length of line; this value comes from the user, and does not change.

Type: `size_t`
Eg.: `1238`

##### `log_date_iso`
Contains the parsed date field from the log in ISO format (`YYYY-MM-DD HH:ii:ss`).

Type: `*char`
Max length: 19 bytes
Eg.:
```
2022/11/05 13:19:51 [info] 58602#58602... (Nginx)
[Sat Nov 05 13:19:51.041880 2022] [:error]... (Apache)
```
will give
```
2022-11-05 13:19:51
```

##### `log_date_timestamp`
Contains the parsed date field from the log in unix timestamp.

Type: `double`
Eg.:
```
2022/11/05 13:19:51 [info] 58602#58602... (Nginx)
[Sat Nov 05 13:19:51.041880 2022] [:error]... (Apache)
```
will give
```
1667650791 (Nginx)
1667650791.041880 (Apache)
```

##### `log_client`
Contains the parsed client source address and (in case of Apache) source port.

Type: `*char`
Max length: 49 bytes
Eg.:
```
...tid 139766615992064] [client 45.134.144.140:33326] [client... (Apache)
...[ref "o12,5v51,21t:lowercase"], client: 45.134.144.140, server: ... (Nginx)
```
will give
```
45.134.144.140:33326 (Apache)
45.134.144.140 (Nginx)
```

As you can see, in case of Apache the parser will process the first `[client]` field. In case of Nginx this value is at the end of the line.

##### `log_entry_class`
Contains the parsed ModSecurity message type.

Type: `logmsgtype`
This is an enum type, and the values can be one of the `LOGMSG_...` constants.
Eg.:
```
... ModSecurity: Warning. Pattern match "^[\\\\d.:]+$" at REQUEST_HEADERS:Host. [file "... (Apache)
```
will provide a `LOGMSG_WARNING` value for this field.

##### `log_modsec_msg`
Contains the parsed ModSecurity message.

Type: `*char`
Eg.:
```
... ModSecurity: Warning. Pattern match "^[\\\\d.:]+$" at REQUEST_HEADERS:Host. [file "... (Apache)
... ModSecurity: Warning. Matched "Operator `Rx' with parameter `^[\d.:]+$' against variable `REQUEST_HEADERS:Host' (Value: `1.2.3.4' ) [file "... (Nginx)
```
will give
```
Warning. Pattern match "^[\\\\d.:]+$" at REQUEST_HEADERS:Host. (Apache)
ModSecurity: Warning. Matched "Operator `Rx' with parameter `^[\d.:]+$' against variable `REQUEST_HEADERS:Host' (Value: `1.2.3.4' ) (Nginx)
```

#### log_modsec_msg_length
Contains the length of the message field above.

Type: `size_t`

#### log_modsec_reason
Holds the reason of the rule triggered.

Type: `*char`
Eg.: `Pattern match`, `detected XSS using libinjection`, ...

#### log_modsec_operator
Contains the operator of the triggered rule **only in case of libmodsecurity3**

Type: `*char`
Eg.: `PmFromFile`, `Rx`, `Ge`, ...

Consider the log contains: `Warning. Matched "Operator `PmFromFile' with parameter `scanners-user-agents.data' against variable `REQUEST_HEADERS:User-Agent' (Value: `Mozilla/5.0 zgrab/0.x' )`. In this case this value will be `PmFromFile`.

#### log_modsec_operand
Contains the rule's operand what engine uses with the operator (above). This field is filled **only in case of libmodsecurity3**

Type: `*char`
Eg.: `scanners-user-agents.data`

Consider the log contains: `Warning. Matched "Operator `PmFromFile' with parameter `scanners-user-agents.data' against variable `REQUEST_HEADERS:User-Agent' (Value: `Mozilla/5.0 zgrab/0.x' )`. In this case this value will be `scanners-user-agents.data`.

#### log_modsec_target_name
Contains the name of the target, where the operator matched. This field is filled **only in case of libmodsecurity3**

Type: `*char`
Eg.: `REQUEST_HEADERS:User-Agent`

Consider the log contains: `Warning. Matched "Operator `PmFromFile' with parameter `scanners-user-agents.data' against variable `REQUEST_HEADERS:User-Agent' (Value: `Mozilla/5.0 zgrab/0.x' )`. In this case this value will be `REQUEST_HEADERS:User-Agent`.

#### log_modsec_target_value
Contains the value of the target (see below) where the operator matched (below too). This field is filled **only in case of libmodsecurity3**

Type: `*char`
Eg.: `Mozilla/5.0 zgrab/0.x`

Consider the log contains: `Warning. Matched "Operator `PmFromFile' with parameter `scanners-user-agents.data' against variable `REQUEST_HEADERS:User-Agent' (Value: `Mozilla/5.0 zgrab/0.x' )`. In this case this value will be `Mozilla/5.0 zgrab/0.x`.

##### `log_modsec_process_error`
Usually this field is filled only in case of Apache. This field contains the message if a rule error occurred.

Type: `*char`
Eg. (only in case of Apache)
```
 ModSecurity: Rule 7fb77198ed38 [id "-"][file "/.../.../RESPONSE-951-DATA-LEAKAGES-SQL.conf"][line "123"] - Execution error - PCRE limits exceeded (-8): (null). 
```

```
Execution error - PCRE limits exceeded (-8): (null).
```

##### `log_rule_file`
Contains the parsed `[file]` field.

Type: `*char`
Eg.:
```
...REQUEST_HEADERS:Host. [file "/usr/share/modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line ... (Apache)
 ) [file "/usr/share/modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line ... (Nginx)
```
will give
```
/usr/share/modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
```

Important note: the pattern ` [file ` is the first "structured", easily recognizable field after the ModSecurity message. With a speciel crafted request, the client can put this pattern into that message, eg:

```
curl -v -F ") [file \"/dev/null\"]=@somefile.csv" http://your.host
```
will produce the line
```
... ModSecurity: Warning. Pattern match "(?<!&(?:[...]" at FILES_NAMES:%22 at [file %22/dev/null%22]. [file ...
```

The only recognizable pattern is ` [file "` - a substring with leading space and trailing `"`. This is the "reference" point in the operation of the parser.

##### `log_rule_line`
Contains the line number of the file.

Type: `*char`
Eg.:
```
....conf"] [line "735"] [id "...
```
will give
```
735
```

##### `log_rule_id`
Contains the id of the rule.

Type: `*char`
Eg.:
```
...line "735"] [id "920350"] [msg...
```
will give
```
920350
```

Please note, that in some special cases this value can be a single char: `-`, eg.:
```
...Rule 7f0c68755d38 [id "-"][file "...
```

##### `log_rule_rev`
Contains the `rev` value of the rule.

Type: `*char`

In case of Apache, this field is optional: if rule does not have it, then the whole field will missing.
In case of libmodsecurity3, this field is always presents, but could be empty:
```
... [rev ""] ...
```

##### `log_rule_msg`
Contains the `msg` field of the rule.

Type: `*char`
Max length: 511 bytes
Eg.:
```
....[id "920280"] [msg "Request Missing a Host Header"] [severity "WARNING"] [ver "OWASP_CRS/3.3.2"]...
```
will give
```
Request Missing a Host Header
```

##### `log_rule_data`
Contains the `data` of the rule.

Type: `*char`
Eg.:
```
... [msg "Host header is a numeric IP address"] [data "1.2.3.4:443"] ...
```
will give
```
1.2.3.4:443
```

In case of Apache, this field is optional: if rule does not have it, then the whole field will missing.
In case of libmodsecurity3, this field is always presents, but could be empty:
```
... [data ""] ...
```

##### `log_rule_severity`
Contains the `severity` of the rule.

Type: `*char`
Eg.:
```
... [severity "CRITICAL"] ... (Apache)
... [severity "2"] ... (Nginx)
```
will give
```
CRITICAL (Apache)
2 (Nginx)
```

In case of Apache, this field is optional: if rule does not have it, then the whole field will missing.
In case of libmodsecurity3, this field is always presents, but could be empty:
```
... [severity ""] ...
```

##### `log_rule_version`
Contains the `version` of the rule.

Type: `*char`
Eg.:
```
... [ver "OWASP_CRS/3.3.4"] ...
```
will give
```
OWASP_CRS/3.3.4
```

In case of Apache, this field is optional: if rule does not have it, then the whole field will missing.
In case of libmodsecurity3, this field is always presents, but could be empty:
```
... [version ""] ...
```

##### `log_rule_maturity`
Contains the `maturity` of the rule.

Type: `*char`

In case of Apache, this field is optional: if rule does not have it, then the whole field will missing.
In case of libmodsecurity3, this field is always presents, but could be empty:
```
... [matrity ""] ...
```

##### `log_rule_accuracy`
Contains the `accuracy` of the rule.

Type: `*char`

In case of Apache, this field is optional: if rule does not have it, then the whole field will missing.
In case of libmodsecurity3, this field is always presents, but could be empty:
```
... [accuracy ""] ...
```
##### `log_rule_tagcnt`
Contains the number of recognized tags.

If a tag is chunked, but the field was recognized during parsing, it will count to this.
Eg.:

```
[tag "application/multi] [t [hostname "..."]
```

will produces `2` for value of `tagcnt`.

##### `log_rule_tags`
Contains the list of tags of the rule.

Type: `*char`
Eg.:
```
... [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] ...
```
will give
```
application-multi, language-multi, platform-multi, attack-generic
```
in a list.

This field is optional both in mod_security2 and libmodsecurity3: if rule does not have it, then the whole field will missing. In this case, the result will an empty string. The number of tags is in the `tagcnt` above.

Note, that tags are stored one after the other in the pool. The memory map looks like:

```
application-multi\0language-multi\0platform-multi\0attack-generic
```

If you want to access all of them, you should read by sequence, while the pointer moves to after the end of the current tag + 1 position:

```C
if (l.tagcnt > 0) {
    printf("tags:");
    for (size_t ti = 0; ti < l.tagcnt; ti++) {
        printf(" '%s'", l.tags);
        l.tags += strlen(l.tags) + 1;
    }
    printf("\n");
}
```

##### `log_hostname`
Contains the hostname of the virtual host. This property is independent from the rule, and always presents.

Type: `*char`
Eg.:
```
... [hostname "modsecurity.digitalwave.hu"] ...
```
will give
```
modsecurity.digitalwave.hu
```

This field can't be chunked.

##### `log_uri`
Contains the URI of the request. This property is independent from the rule, and always presents.

Type: `*char`
Eg.:
```
... [uri "/ab2"] ...
```
will give
```
/ab2
```

This field can't be chunked.

##### `log_unique_id`
Contains the unique_id of the request in webserver. This property is independent from the rule, and always presents.

Type: `*char`
Eg.:
```
... [uri "Y7Z3aSfpYv3U3aB8MPMHjAAAABY"] ...
```
will give
```
Y7Z3aSfpYv3U3aB8MPMHjAAAABY
```

This field can't be chunked.

##### `lineerrpool`
This field contains the list of error messages and positions (start, end) where the error occurred.

Type: `*char`

The error stored in a structure:
```C
typedef struct msclogerr {
    char    *errmsg;
    size_t  *startpos;
    size_t  *endpos;
} msclogerr;
```

To get the items, you can use the method `read_msclog_err()`. See this [methods](#methods) section.

##### `log_entry_errors_cnt`
Contains the number of errors.

Type: `int`

### Methods
Library contains these methods:
```C
int parse(char *line, size_t len, loglinetype LT, logdata *l);
```
where the arguments:
* pointer to the line itself
* lenght of the line
* type of the line, see [constants](#constants) above
* a logdata [structure](#structure)

Note, that the last argument (logdata) is necessary only in C. If you use any kind of bindings, you don't need to care of that.

To see an example, you should check the examples directory. Here is a sample:
```C
    char line[4096] = {0};
    size_t len      = 0;
    while (fgets (line, 4095, fp) != NULL) {
        len = strlen(line);
        if (len > 0) {
            memset(&l, '\0', sizeof(logdata));

            parse(line, len, t, &l);

            if (l.is_modsecline == 1) {
                ...
```

```C
void read_msclog_err(msclogpool *pool, msclogerr *err);
```
where the arguments:
* pointer to the pool, namely `l.lineerrpool`
* pointer to the structure of `msclogerr`, see above

The example is above, but here again:

```C
if (l.lineerrcnt > 0) {
    l.lineerrpool.currptr = l.lineerrpool.pool;     // set the ptr to the start pos
    for (int c=0; c < l.lineerrcnt; c++) {          // iterate while cnt counts

        msclogerr err;                              // structure above

        read_msclog_err(&l.lineerrpool, &err);      // call the fn and fill it
        printf("%s - %zu:%zu\n", err.errmsg, *err.startpos, *err.endpos);
    }
}
```
Eg.: consider a line with chunked field:

```
..."] [severity "CRITICAL"] [v [hostname "...
```
In this case, the `[version]` field is chunked, therefore the message will
```
Field [version] is chunked! - 1234:1236
```

Note: this method is not available in bindings, because the errors are expanded.

### Strucure in bindings

As you can see above, in the available bindings (Lua, PHP, Python, Ruby) there is only one function exists, the `parse()`. For more details, please see the tests scripts under the `bindings/` directory.

Note, that the PHP script runs with this command (after build and install):
```bash
php -d extension=mscphplogparser bindings/phptest.php /path/to/log apache
```

The given structure from the `parse()` method is a bit different than the C structure above. Here is the used one (in JSON):

```JSON
{
  "linelen": 1287,
  "is_modsecline": 1,
  "is_broken": 1,
  "date_iso": "2022-08-11 07:43:59",
  "date_epoch": 1660196639.069593,
  "client": "141.98.83.248:40904",
  "modseclinetype": 1,
  "modsecmsg": "Warning. Pattern match \"(?:\\\\\\\\b(?:having\\\\\\\\b ?(?:[\\\\\\\\'\\\\\"][^=]{1,10}[\\\\\\\\'\\\\\" ?[=<>]+|\\\\\\\\d{1,10} ?[=<>]+)|(?i:having)\\\\\\\\b\\\\\\\\s+(?:'[^=]{1,10}'|\\\\\\\\d{1,10})\\\\\\\\s*?[=<>])|exists\\\\\\\\s(?:s(?:elect\\\\\\\\S(?:if(?:null)?\\\\\\\\s\\\\\\\\(|concat|top)|ystem\\\\\\\\s\\\\\\\\()|\\\\\\\\b(?i:having)\\\\\\\\b\\\\\\\\s+\\\\\\\\d{1,10}|'[^=]{1,10}'|\\\\\\\\sselec ...\" at ARGS:email.",
  "modsecmsglen": 338,
  "modsecdenymsg": "",
  "modsecmsgreason": "Pattern match",
  "modsecmsgop": "",
  "modsecmsgoperand": "(?:\\\\\\\\b(?:having\\\\\\\\b ?(?:[\\\\\\\\'\\\\\"][^=]{1,10}[\\\\\\\\'\\\\\" ?[=<>]+|\\\\\\\\d{1,10} ?[=<>]+)|(?i:having)\\\\\\\\b\\\\\\\\s+(?:'[^=]{1,10}'|\\\\\\\\d{1,10})\\\\\\\\s*?[=<>])|exists\\\\\\\\s(?:s(?:elect\\\\\\\\S(?:if(?:null)?\\\\\\\\s\\\\\\\\(|concat|top)|ystem\\\\\\\\s\\\\\\\\()|\\\\\\\\b(?i:having)\\\\\\\\b\\\\\\\\s+\\\\\\\\d{1,10}|'[^=]{1,10}'|\\\\\\\\sselec ...",
  "modsecmsgtrgname": "ARGS:email",
  "modsecmsgtrgvalue": "",
  "ruleerror": "",
  "file": "/usr/share/modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
  "line": "962",
  "id": "942380",
  "rev": "",
  "msg": "SQL Injection Attack",
  "data": "Matched Data: SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(122)||CHR(120)||CHR(113)||CHR(113)||(SELECT (CASE found within ARGS:email: auderworter777@google.com') AND 9336=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(122)||CHR(120)||CHR(113)||CHR(113)||(SELECT (CASE WHEN (9336=9336) THEN 1 ELSE 0 END) FROM DUAL)||CHR(113)||CHR(107)||CHR(118)||CHR(120)||CHR(113)||CHR(62))) FROM DUAL) AND ('WPlw'='WPlw",
  "severity": "CRITICAL",
  "version": "OWASP_CRS/3.3.2",
  "maturity": "",
  "accuracy": "",
  "tagcnt": 6,
  "tags": [
    "application-multi",
    "language-multi",
    "platform-multi",
    "attack-sqli",
    "OWASP_CRS",
    ""
  ],
  "hostname": "my.host.name",
  "uri": "",
  "unique_id": "YvSXH-fY9JSguWbdJ6KaSwAAAEo",
  "lineerrorcnt": 1,
  "lineerrors": [
    "The 6. [tag] field is chunked!"
  ],
  "lineerrorspos": [
    [
      1205,
      1204
    ]
  ]
}
```
or an Nginx output:
```JSON
{
  "linelen": 1031,
  "is_modsecline": 1,
  "is_broken": 0,
  "date_iso": "2023-01-17 09:15:47",
  "date_epoch": 1673943347,
  "client": "198.199.114.126",
  "modseclinetype": 1,
  "modsecmsg": "Warning. Matched \"Operator `PmFromFile' with parameter `scanners-user-agents.data' against variable `REQUEST_HEADERS:User-Agent' (Value: `Mozilla/5.0 zgrab/0.x' )",
  "modsecmsglen": 162,
  "modsecdenymsg": "",
  "modsecmsgreason": "",
  "modsecmsgop": "PmFromFile",
  "modsecmsgoperand": "scanners-user-agents.data",
  "modsecmsgtrgname": "REQUEST_HEADERS:User-Agent",
  "modsecmsgtrgvalue": "Mozilla/5.0 zgrab/0.x",
  "ruleerror": "",
  "file": "/usr/share/modsecurity-crs/rules/REQUEST-913-SCANNER-DETECTION.conf",
  "line": "34",
  "id": "913100",
  "rev": "",
  "msg": "Found User-Agent associated with security scanner",
  "data": "Matched Data: zgrab found within REQUEST_HEADERS:User-Agent: mozilla/5.0 zgrab/0.x",
  "severity": "2",
  "version": "OWASP_CRS/3.3.4",
  "maturity": "0",
  "accuracy": "0",
  "tagcnt": 8,
  "tags": [
    "application-multi",
    "language-multi",
    "platform-multi",
    "attack-reputation-scanner",
    "paranoia-level/1",
    "OWASP_CRS",
    "capec/1000/118/224/541/310",
    "PCI/6.5.10"
  ],
  "hostname": "185.43.207.66",
  "uri": "/owa/auth/logon.asp",
  "unique_id": "167394334781.436951",
  "lineerrorcnt": 0,
  "lineerrors": [],
  "lineerrorspos": []
}
```

Please see the parsed structure (in case of Nginx) in this example.

## Compile, install
To build the library, you need at least:
* a C compiler
* autotools
* make

There is no other library dependencies, if you want to use it for your C codes.

If you want to bind the library for any kind of supported supported languages (Python3, Lua, Ruby, PHP), you have to install its development tool.

To compile the code, just download the source and type as regular user:
```bash
./configure --help
```

You can set the target directory given `--prefix=/path/to`, and set other options.

To compile the bindings, these options are avaliable:
```bash
--enable-python \
--enable-lua \
--enable-ruby \
--enable-php
```

Please note, that if you have more versions of a choosed language, you have to set explicit the used interpreter. Eg.:

```bash
PYTHON=/usr/bin/python3 RUBY=/path/to/ruby LUA=/path/to/lua5.4 PHP=/usr/local/bin/php7.4 \
./configure \
--enable-python \
--enable-lua \
--enable-ruby \
--enable-php
```

At the end of the `configure` script run you will see the summary:
```
----------------------------------------------------------------------

 msclogparser Version 0.2.0 configuration:

 OS Type        Linux
 Prefix         /usr/local
 Preprocessor   gcc -E 
 C Compiler     gcc -g -O2
 Bindings:
    Python      yes
    Lua         yes
    Ruby        yes
    PHP         yes

-----------------------------------------------------------------------
```

Now you type `make` and `sudo make install`. This will build the library, and the modules for interpreters. Also will install the compiled modules to the destination directories.

## Naming convention
To avoid the name collison of modules in the `bindings/` directory, the compiled modules will have different names: `mscpylogparser.so` for Python, `msclualogparser.so` for Lua, `mscrubylogparser.so` for Ruby, and `mscphplogparser.so` for PHP.

## Using of module

Both for native and embedding usage you can find an example under the `examples/` and `bindings` directory. The names of tests scripts are `pytest.py`, `luatest.lua`, `rubytest.rb` and `phptest.php`. Please note, that the necessary import module names are different in each language.

In those tests scripts you can see the method to access for the constants and how should you call the `parse()` method.

In case of PHP please note, that normally PHP does not allow to import the extension from other place than the `php.ini` listed. You should install the module before you want to test it.

Also if you do not set `--prefix`, then it will be the `/usr/local`, and the library will installed to `/usr/local/lib`. Perhaps you should run `sudo ldconfig` after the install process.

## Bugs, feature requests
If you have any problem or feature request, please open an issue on Github, or send us an e-mail: modsecurity at digitalwave dot hu.
