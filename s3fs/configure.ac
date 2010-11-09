dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(s3fs, 1.11)


AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE()

AC_PROG_CXX

PKG_CHECK_MODULES([DEPS], [fuse >= 2.7 libcurl >= 7.0 libxml-2.0 >= 2.6 libcrypto >= 0.9])

AC_CONFIG_FILES(Makefile src/Makefile test/Makefile)
AC_OUTPUT

