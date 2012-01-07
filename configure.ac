AC_INIT([nfdnsbl], [0.1_alpha], [simon.le-lann@dosadi.fr], [nfdnsbl], [http://nfdnsbl.dosadi.fr/])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 no-define])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_HEADER_STDC

AC_CHECK_HEADERS(netinet/in.h)

AC_CHECK_HEADER(linux/netfilter.h,[],[],[[#include <netinet/in.h>]])

PKG_CHECK_MODULES([LIBCONFIG], [libconfig >= 1.4],,
	AC_MSG_ERROR([libconfig 1.4 or newer not found.])
)
AC_SUBST(LIBCONFIG_CFLAGS)
AC_SUBST(LIBCONFIG_LIBS)

PKG_CHECK_MODULES([LIBNFQUEUE], [libnetfilter_queue >= 1.0],,
	AC_MSG_ERROR([libnetfilter_queue 1.0 or newer not found.])
)
AC_SUBST(LIBNFQUEUE_CFLAGS)
AC_SUBST(LIBNFQUEUE_LIBS)

AC_CONFIG_FILES([Makefile])
AC_DEFINE_UNQUOTED(CONFFILE, "$sysconfdir/nfdnsbl.conf", [Config file path])
AC_OUTPUT
