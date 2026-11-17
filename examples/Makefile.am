# the header of the source tree (not ../src, which is the build tree in a
# VPATH build, eg. make distcheck, and not an installed older one), and the
# library of the build tree
AM_CPPFLAGS = -I$(top_srcdir)/src

bin_PROGRAMS = example01
example01_SOURCES = example01.c
example01_LDADD = $(top_builddir)/src/libmsclogparser.la
