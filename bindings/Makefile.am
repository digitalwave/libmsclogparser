
if ENABLE_PYTHON

all-py: pybinding.c
	(cd $(srcdir); $(PYTHON) setup.py build \
	--build-base $(shell readlink -f $(builddir))/build \
	--verbose)

install-exec-py:
	$(PYTHON) $(srcdir)/setup.py install \
	--prefix $(DESTDIR)$(prefix) \
	--verbose

clean-py:
	rm -rf *.o *.so *.la build

endif


if ENABLE_LUA

LUALIBFLAG= -shared -fpic
LUACFLAGS= -I../src $(LUA_INCLUDE) -L../src/.libs 

all-lua: luabinding.c
	$(CC) $(LUACFLAGS) $(LUALIBFLAG) -o msclualogparser.so luabinding.c $(LUA_LIB) -lmsclogparser

install-exec-lua:
	mkdir -p $(luaexecdir)
	$(INSTALL) msclualogparser.so $(luaexecdir)

clean-lua:
	rm -f msclualogparser.so

endif

if ENABLE_RUBY

RUBYLIBFLAG= -shared -fPIC -L$(RUBY_ARCHLIBDIR)
RUBYCFLAGS= -I../src/ -I$(RUBY_HDRDIR) -I$(RUBY_ARCHHDRDIR) -L../src/.libs

all-ruby: rubybinding.c
	$(CC) $(RUBYCFLAGS) $(RUBYLIBFLAG) -o mscrubylogparser.so rubybinding.c $(RUBY_LIBRUBYARG) -lmsclogparser

install-exec-ruby:
	mkdir -p $(RUBY_VENDORARCHDIR)
	$(INSTALL) mscrubylogparser.so $(RUBY_VENDORARCHDIR)

clean-ruby:
	rm -f mscrubylogparser.so

endif

if ENABLE_PHP

all-php: phpbinding.c

    #$(CC) -I. -DPHP_ATOM_INC -I/usr/include/php/20190902 -I/usr/include/php/20190902/main -I/usr/include/php/20190902/TSRM -I/usr/include/php/20190902/Zend -I/usr/include/php/20190902/ext -I/usr/include/php/20190902/ext/date/lib -DHAVE_CONFIG_H -g -O2 -c phpbinding.c -fPIC -DPIC -o phpbinding.o
    #$(CC) -shared -fPIC -DPIC phpbinding.o -g -O2 -Wl,-soname -Wl,mscphplogparser.so -o mscphplogparser.so

	$(CC) -I. -I../src/ -L../src/.libs -DPHP_ATOM_INC $(PHP_INCLUDE_PATH) -DHAVE_CONFIG_H -c phpbinding.c -fPIC -DPIC -o phpbinding.o -lmsclogparser
	$(CC) -L../src/.libs -shared -fPIC -DPIC phpbinding.o -Wl,-soname -Wl,mscphplogparser.so -o mscphplogparser.so -lmsclogparser

install-exec-php:
	mkdir -p $(PHP_EXT_DIR)
	$(INSTALL) mscphplogparser.so $(PHP_EXT_DIR)

clean-php:
	rm -f mscphplogparser.so phpbinding.o

endif


all-local:
	$(MAKE) $(BINDING_ALL)

install-exec-local:
	$(MAKE) $(BINDING_INSTALL_EXEC)

clean-local:
	$(MAKE) $(BINDING_CLEAN)

