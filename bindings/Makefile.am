
if ENABLE_PYTHON

all-py: pybinding.c
	(cd $(srcdir); $(PYTHON) setup.py build \
	--build-base $(shell readlink -f $(builddir))/build \
	--verbose)

# the pip of $(PYTHON), so the module is installed for the same interpreter
# that uninstall-py asks for its directories
PYTHON_INSTALL_CMD = $(PYTHON) -m pip install --root=$(DESTDIR)/ \
                --no-deps \
                --ignore-installed \
                --no-build-isolation .

# pip installs the module and its dist-info into a site directory of the
# interpreter (eg. /usr/local/lib/python3.X/dist-packages on Debian,
# site-packages elsewhere; it depends on the scheme of pip), under DESTDIR:
# they are removed from each of them
uninstall-py:
	for d in `$(PYTHON) -c "import site, sysconfig; print(' '.join(sorted(set([sysconfig.get_path('platlib'), sysconfig.get_path('purelib')] + site.getsitepackages()))))"`; do \
	    rm -rf "$(DESTDIR)$$d"/mscpylogparser*; \
	done


clean-py:
	rm -rf *.o *.so *.la build

else
PYTHON_INSTALL_CMD = @echo "Python support disabled, skipping..."
endif


if ENABLE_LUA

LUALIBFLAG= -shared -fpic
LUACFLAGS= -I../src $(LUA_INCLUDE) -L../src/.libs 

all-lua: luabinding.c
	$(CC) $(LUACFLAGS) $(LUALIBFLAG) -o msclualogparser.so luabinding.c $(LUA_LIB) -lmsclogparser

install-exec-lua:
	mkdir -p $(DESTDIR)$(luaexecdir)
	$(INSTALL) msclualogparser.so $(DESTDIR)$(luaexecdir)

uninstall-lua:
	rm -f $(DESTDIR)$(luaexecdir)/msclualogparser.so

clean-lua:
	rm -f msclualogparser.so

endif

if ENABLE_RUBY

RUBYLIBFLAG= -shared -fPIC -L$(RUBY_ARCHLIBDIR)
RUBYCFLAGS= -I../src/ -I$(RUBY_HDRDIR) -I$(RUBY_ARCHHDRDIR) -L../src/.libs

all-ruby: rubybinding.c
	$(CC) $(RUBYCFLAGS) $(RUBYLIBFLAG) -o mscrubylogparser.so rubybinding.c $(RUBY_LIBRUBYARG) -lmsclogparser

install-exec-ruby:
	mkdir -p $(DESTDIR)$(RUBY_VENDORARCHDIR)
	$(INSTALL) mscrubylogparser.so $(DESTDIR)$(RUBY_VENDORARCHDIR)

uninstall-ruby:
	rm -f $(DESTDIR)$(RUBY_VENDORARCHDIR)/mscrubylogparser.so

clean-ruby:
	rm -f mscrubylogparser.so

endif

if ENABLE_PHP

all-php: phpbinding.c

	$(CC) -I. -I../src/ -L../src/.libs -DPHP_ATOM_INC $(PHP_INCLUDE_PATH) -DHAVE_CONFIG_H -c phpbinding.c -fPIC -DPIC -o phpbinding.o -lmsclogparser
	$(CC) -L../src/.libs -shared -fPIC -DPIC phpbinding.o -Wl,-soname -Wl,mscphplogparser.so -o mscphplogparser.so -lmsclogparser

install-exec-php:
	mkdir -p $(DESTDIR)$(PHP_EXT_DIR)
	$(INSTALL) mscphplogparser.so $(DESTDIR)$(PHP_EXT_DIR)

uninstall-php:
	rm -f $(DESTDIR)$(PHP_EXT_DIR)/mscphplogparser.so

clean-php:
	rm -f mscphplogparser.so phpbinding.o

endif


# With no binding enabled the target lists are empty, and a bare $(MAKE)
# would build "all" again, which calls all-local again, endlessly.
all-local:
	test -z "$(BINDING_ALL)" || $(MAKE) $(BINDING_ALL)

install-exec-local:
	test -z "$(BINDING_INSTALL_EXEC)" || $(MAKE) $(BINDING_INSTALL_EXEC)
	$(PYTHON_INSTALL_CMD)

uninstall-local:
	test -z "$(BINDING_UNINSTALL)" || $(MAKE) $(BINDING_UNINSTALL)

clean-local:
	test -z "$(BINDING_CLEAN)" || $(MAKE) $(BINDING_CLEAN)

