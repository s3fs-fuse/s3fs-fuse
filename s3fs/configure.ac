# Process this file with autoconf to produce a configure script.

AC_INIT
AM_INIT_AUTOMAKE(s3fs,1.0.0)

AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL

PKG_CHECK_MODULES(DEPS, fuse libcurl libxml-2.0)

AC_SUBST(DEPS_LIBS)
AC_SUBST(DEPS_CFLAGS)

AC_OUTPUT(Makefile)
