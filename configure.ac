
AC_INIT([msclogparser], [0.2.0], [modsecurity@digitalwave.hu])
#AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_DEFUN([VER_MAJOR], m4_esyscmd_s(cat src/msclogparser.h | grep "define MSCLOGPARSER_MAJOR " | awk {'print $3'} | sed 's/\"//g'))
AC_DEFUN([VER_MINOR], m4_esyscmd_s(cat src/msclogparser.h | grep "define MSCLOGPARSER_MINOR " | awk {'print $3'} | sed 's/\"//g'))
AC_DEFUN([VER_PATCH], m4_esyscmd_s(cat src/msclogparser.h | grep "define MSCLOGPARSER_PATCH " | awk {'print $3'} | sed 's/\"//g'))

VER_NUMBER=VER_MAJOR:VER_MINOR:VER_PATCH
AC_SUBST([VER_NUMBER])

AC_LANG([C])

AC_PROG_CC

AC_PROG_INSTALL
AM_PROG_AR
# AC_PROG_RANLIB

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_CHECK_HEADER([string.h], [], [AC_MSG_ERROR([unable to find string.h])])
AC_CHECK_HEADER([stdlib.h], [], [AC_MSG_ERROR([unable to find stdlib.h])])
AC_CHECK_HEADER([time.h], [], [AC_MSG_ERROR([unable to find time.h])])
AC_CHECK_HEADER([stdio.h], [], [AC_MSG_ERROR([unable to find stdio.h])])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# AX_VALGRIND_CHECK

AC_CONFIG_FILES([\
    Makefile \
    src/Makefile \
    examples/Makefile \
    bindings/Makefile \
    ])

LT_INIT

# check host os
AC_CANONICAL_HOST

build_linux=no
os_type=unknown

case "${host_os}" in
    linux*)
        build_linux=yes
        os_type=Linux
        ;;
    *)
        AC_MSG_ERROR(["OS $host_os is not supported"])
        ;;
esac

BINDING_ALL=""
BINDING_INSTALL_EXEC=""
BINDING_CLEAN=""

dnl Check if user wants Python3 binding
AC_MSG_CHECKING([whether to build Python binding])
AC_ARG_ENABLE([python-binding],
	[AS_HELP_STRING([--enable-python-binding],
		[Enable Python binding])],
	[wantpythonbinding=true],
	[wantpythonbinding=false])

AS_IF([test "x$wantpythonbinding" = xtrue],
    [
        dnl Look for Python
        AC_MSG_RESULT([yes])
        AM_PATH_PYTHON(,, [:])
        python_main_ver=`$PYTHON -c "import sys; print(sys.version.split('.')[[0]])"`
        python_sub_ver=`$PYTHON -c "import sys; print(sys.version.split('.')[[1]])"`
        AC_ARG_VAR([PYTHON_INCLUDE], [Include flags for python, bypassing python-config])
        AC_ARG_VAR([PYTHON_CONFIG], [Path to python-config])
        #AC_ARG_VAR([PYTHON_SITE_PKG], [Patho to install path])
        AS_IF(
            [test -z "$PYTHON_INCLUDE"],
            [
            AS_IF([test -z "$PYTHON_CONFIG"], [
            AC_PATH_PROGS([PYTHON_CONFIG],
                [python$PYTHON_VERSION-config python-config],
                [no],
                [`dirname $PYTHON`])
            AS_IF([test "$PYTHON_CONFIG" = no], [AC_MSG_ERROR([cannot find python-config for $PYTHON.])])
            ])
            AC_MSG_CHECKING([python include flags])
            pyinc=`$PYTHON_CONFIG --includes`
            AC_SUBST([PYTHON_INCLUDE], [$pyinc])
            AC_MSG_RESULT([$pyinc])
            AC_MSG_CHECKING([python libs])
            AS_IF([test $python_sub_ver -gt 7], [pylibs=`$PYTHON_CONFIG --libs --embed`], [pylibs=`$PYTHON_CONFIG --libs`])
            AC_SUBST([PYTHON_LIBS], [$pylibs])
            AC_MSG_RESULT([$pylibs])
                AC_DEFINE([HAVE_PYTHON], [1],
                [Define to 1 if you have the Python3 libraries.])
            ]
        )
        BINDING_ALL="${BINDING_ALL} all-py"
        BINDING_CLEAN="${BINDING_CLEAN} clean-py"
	],
    [AC_MSG_RESULT([no])]
)

AM_CONDITIONAL([ENABLE_PYTHON],[test "x$wantpythonbinding" = xtrue])

dnl Check if user wants Lua binding
# Lua bindings

AC_MSG_CHECKING([whether to build Lua binding])
AC_ARG_ENABLE([lua-binding],
	[AS_HELP_STRING([--enable-lua-binding],
		[Enable Lua binding])],
	[wantluabinding=true],
	[wantluabinding=false])

AS_IF(
    [test "x$wantluabinding" = xtrue],
    [
        AC_MSG_RESULT([yes])
        AX_PROG_LUA
        AX_LUA_HEADERS
        AX_LUA_LIBS
        BINDING_ALL="${BINDING_ALL} all-lua"
        BINDING_INSTALL_EXEC="${BINDING_INSTALL_EXEC} install-exec-lua"
        BINDING_CLEAN="${BINDING_CLEAN} clean-lua"

        AC_SUBST(LUA_INCLUDE)
        AC_SUBST(LUA_LIB)
    ],
    [AC_MSG_RESULT([no])]
)

AM_CONDITIONAL([ENABLE_LUA],[test "x$wantluabinding" = xtrue])

dnl Check if user wants Ruby binding
# Ruby bindings

AC_MSG_CHECKING([whether to build Ruby binding])
AC_ARG_ENABLE([ruby-binding],
	[AS_HELP_STRING([--enable-ruby-binding],
		[Enable Ruby binding])],
	[wantrubybinding=true],
	[wantrubybinding=false])

AS_IF([test "x$wantrubybinding" = xtrue],[
    AC_MSG_RESULT([yes])
    AC_ARG_VAR([RUBY], [The Ruby interpreter, e.g. /usr/bin/ruby2.7])
    #AC_ARG_VAR([RUBY_INCLUDE], [The Ruby includes, e.g. -I/usr/include/ruby-2.7.0])
    #AC_ARG_VAR([RUBY_LIB], [The Ruby library, e.g. -lruby-2.7])
    
    AS_IF([test "x$RUBY" = 'x'],
        [ RUBY="ruby" ],
        []
    )

    AC_CHECK_PROG([RUBY_CHECK],[ ${RUBY} ], [yes], [no])
    AS_IF([test "x$RUBY_CHECK" = xyes ], [], [AC_MSG_ERROR([required program 'ruby' not found.])])
    ax_display_RUBY="${RUBY}"

    RUBY_VERSION=`${RUBY} -e "puts RbConfig::CONFIG.then { |x| [x['RUBY_API_VERSION']] }"`
    RUBY_HDRDIR=`${RUBY} -e "puts RbConfig::CONFIG.then { |x| [x['rubyhdrdir']] }"`
    RUBY_ARCHHDRDIR=`${RUBY} -e "puts RbConfig::CONFIG.then { |x| [x['rubyarchhdrdir']] }"`
    RUBY_ARCHLIBDIR=`${RUBY} -e "puts RbConfig::CONFIG.then { |x| [x['archlibdir']] }"`
    RUBY_LIBRUBYARG=`${RUBY} -e "puts RbConfig::CONFIG.then { |x| [x['LIBRUBYARG']] }"`
    RUBY_RUBY_SO_NAME=`${RUBY} -e "puts RbConfig::CONFIG.then { |x| [x['RUBY_SO_NAME']] }"`
    RUBY_ARCHDIR=`${RUBY} -e "puts RbConfig::CONFIG.then { |x| [x['rubyarchdir']] }"`
    RUBY_VENDORARCHDIR=`${RUBY} -e "puts RbConfig::CONFIG.then { |x| [x['vendorarchdir']] }"`

    OLD_CPPFLAGS="$CPPFLAGS"
    OLD_LDFLAGS="$LDFLAGS"

    CPPFLAGS="$CPPFLAGS -I$RUBY_HDRDIR -I$RUBY_ARCHHDRDIR"
    LDFLAGS="$LDFLAGS -L$RUBY_ARCHLIBDIR $RUBY_LIBRUBYARG"
    AC_CHECK_HEADERS([ruby.h], [], [AC_MSG_ERROR([ruby.h not found.])], [])
    AC_CHECK_HEADERS([ruby/config.h], [], [AC_MSG_ERROR([ruby/config.h not found.])], [])
    AC_CHECK_LIB($RUBY_RUBY_SO_NAME, rb_define_method, [], [AC_MSG_ERROR([ruby function "rb_define_method" not found.])])
    BINDING_ALL="${BINDING_ALL} all-ruby"
    BINDING_INSTALL_EXEC="${BINDING_INSTALL_EXEC} install-exec-ruby"
    BINDING_CLEAN="${BINDING_CLEAN} clean-ruby"

    CPPFLAGS="$OLD_CPPFLAGS"
    LDFLAGS="$OLD_LDFLAGS"

    AC_SUBST(RUBY_VERSION)
    AC_SUBST(RUBY_HDRDIR)
    AC_SUBST(RUBY_ARCHHDRDIR)
    AC_SUBST(RUBY_ARCHLIBDIR)
    AC_SUBST(RUBY_LIBRUBYARG)
    AC_SUBST(RUBY_RUBY_SO_NAME)
    AC_SUBST(RUBY_ARCHDIR)
    AC_SUBST(RUBY_VENDORARCHDIR)

    ],
    [AC_MSG_RESULT([no])]
    )

AM_CONDITIONAL([ENABLE_RUBY],[test "x$wantrubybinding" = xtrue])

dnl Check if user wants PHP binding
# PHP bindings

AC_MSG_CHECKING([whether to build PHP binding])
AC_ARG_ENABLE([php-binding],
	[AS_HELP_STRING([--enable-php-binding],
		[Enable PHP binding])],
	[wantphpbinding=true],
	[wantphpbinding=false])

AS_IF([test "x$wantphpbinding" = xtrue],[
    AC_MSG_RESULT([yes])
    AC_ARG_VAR([PHP_CONFIG], [The 'php-config' program, e.g. /usr/bin/php-config])

    AS_IF([test "x$PHP_CONFIG" = 'x'],
        [ PHP_CONFIG="php-config" ],
        []
    )

    AC_CHECK_PROG([PHP_CHECK],[ ${PHP_CONFIG} ], [yes], [no])
    AS_IF([test "x$PHP_CHECK" = xyes ], [], [AC_MSG_ERROR([required program 'php-config' not found.])])
    ax_display_PHP_CONFIG="${PHP_CONFIG}"

    PHP_INCLUDE_PATH=`${PHP_CONFIG} --includes`
    PHP_LDFLAGS=`${PHP_CONFIG} --ldflags`
    PHP_LIBS=`${PHP_CONFIG} --libs`
    PHP_EXT_DIR=`${PHP_CONFIG} --extension-dir`

    OLD_CPPFLAGS="$CPPFLAGS"
    OLD_LDFLAGS="$LDFLAGS"

    CPPFLAGS="$CPPFLAGS $PHP_INCLUDE_PATH"
    LDFLAGS="$LDFLAGS $PHP_LDFLAGS $PHP_LIBS"

    AC_CHECK_HEADERS([php.h], [], [AC_MSG_ERROR([php.h not found.])], [])
    AC_CHECK_HEADERS([ext/standard/info.h], [], [AC_MSG_ERROR([ext/standard/info.h not found.])], [#include <php.h>])
    BINDING_ALL="${BINDING_ALL} all-php"
    BINDING_INSTALL_EXEC="${BINDING_INSTALL_EXEC} install-exec-php"
    BINDING_CLEAN="${BINDING_CLEAN} clean-php"

    CPPFLAGS="$OLD_CPPFLAGS"
    LDFLAGS="$OLD_LDFLAGS"

    AC_SUBST(PHP_INCLUDE_PATH)
    AC_SUBST(PHP_LDFLAGS)
    AC_SUBST(PHP_LIBS)
    AC_SUBST(PHP_EXT_DIR)

    ],
    [AC_MSG_RESULT([no])]
    )

AM_CONDITIONAL([ENABLE_PHP],[test "x$wantphpbinding" = xtrue])


AC_SUBST([BINDING_ALL])
AC_SUBST([BINDING_INSTALL_EXEC])
AC_SUBST([BINDING_CLEAN])

AC_OUTPUT

echo \
"----------------------------------------------------------------------

 ${PACKAGE_NAME} Version ${PACKAGE_VERSION} configuration:

 OS Type        ${os_type}
 Prefix         ${prefix}
 Preprocessor   ${CPP} ${CPPFLAGS}
 C Compiler     ${CC} ${CFLAGS}
 Bindings:
    Python      ${enable_python_binding}
    Lua         ${enable_lua_binding}
    Ruby        ${enable_ruby_binding}
    PHP         ${enable_php_binding}

-----------------------------------------------------------------------"

