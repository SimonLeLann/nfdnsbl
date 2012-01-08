ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

AM_CFLAGS = $(LIBCONFIG_CFLAGS) $(LIBNFQUEUE_CFLAGS) $(LIBBSD_CFLAGS)

bin_PROGRAMS = nfdnsbl
dist_sysconf_DATA = nfdnsbl.conf

nfdnsbl_SOURCES = src/nfdnsbl.c src/nfdnsbl_config.c src/nfdnsbl_config.h src/uthash.h

nfdnsbl_LDADD = $(LIBCONFIG_LIBS) $(LIBNFQUEUE_LIBS) $(LIBBSD_LIBS)


