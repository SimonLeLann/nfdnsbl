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

PKG_CHECK_MODULES([LIBBSD], [libbsd >= 0.2],,
	AC_MSG_ERROR([libbsd 0.2 or newer not found.])
)
AC_SUBST(LIBBSD_CFLAGS)
AC_SUBST(LIBBSD_LIBS)

AC_ARG_ENABLE([syslog], AS_HELP_STRING([--enable-syslog], [Enable syslog logging]))

AS_IF([test "x$enable_syslog" = "xyes"], [
  AC_CHECK_HEADER(syslog.h)
  AC_DEFINE(ENABLE_SYSLOG, 1, [Enable syslog])
])

AC_ARG_ENABLE([cache], AS_HELP_STRING([--enable-cache], [Enable ip caching]))

AS_IF([test "x$enable_cache" = "xyes"], [
  AC_DEFINE(ENABLE_CACHE, 1, [Enable ip caching])
])

AC_CONFIG_FILES([Makefile])
AC_DEFINE_UNQUOTED(CONFFILE, "$sysconfdir/nfdnsbl.conf", [Config file path])
AC_OUTPUT
