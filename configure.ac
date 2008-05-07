#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(wicrawl, 0.4a, david@newgas.net)

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

AC_CHECK_LIB([pcap], [pcap_open_live],,AC_MSG_ERROR([libpcap missing]))
AC_CHECK_LIB([pthread], [pthread_create],,AC_MSG_ERROR([libpthread missing]))
AC_CHECK_LIB([m], [cos],,AC_MSG_ERROR([libm missing]))
AC_CHECK_LIB([ssl], [MD5_Init],,AC_MSG_ERROR([libssl missing]))

AC_SUBST(package, wicrawl)

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
