dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(s3fs, 1.61)


AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE()

AC_PROG_CXX

CXXFLAGS="$CXXFLAGS -Wall -D_FILE_OFFSET_BITS=64"

PKG_CHECK_MODULES([DEPS], [fuse >= 2.8.4 libcurl >= 7.0 libxml-2.0 >= 2.6 libcrypto >= 0.9])

AC_CONFIG_FILES(Makefile src/Makefile test/Makefile doc/Makefile)
AC_OUTPUT

