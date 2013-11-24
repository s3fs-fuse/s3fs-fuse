######################################################################
# s3fs - FUSE-based file system backed by Amazon S3
#
# Copyright 2007-2008 Randy Rizun <rrizun@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
######################################################################
dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(s3fs, 1.74)

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE()

AC_PROG_CXX

CXXFLAGS="$CXXFLAGS -Wall -D_FILE_OFFSET_BITS=64"

PKG_CHECK_MODULES([DEPS], [fuse >= 2.8.4 libcurl >= 7.0 libxml-2.0 >= 2.6 libcrypto >= 0.9])

dnl malloc_trim function
AC_CHECK_FUNCS(malloc_trim, , )

dnl Initializing NSS(temporally)
AC_MSG_CHECKING([Initializing libcurl build with NSS])
AC_ARG_ENABLE(
  nss-init,
  [
    AS_HELP_STRING(
      [--enable-nss-init],
      [Inilializing libcurl with NSS (default is no)]
    )
  ],
  [
    case "${enableval}" in
    yes)
      AC_MSG_RESULT(yes)
      nss_init_enabled=yes
      ;;
    *)
      AC_MSG_RESULT(no)
      nss_init_enabled=no
      ;;
    esac
  ],
  [
    AC_MSG_RESULT(no)
    nss_init_enabled=no
  ])

AS_IF(
  [test $nss_init_enabled = yes],
  [
    AC_DEFINE(NSS_INIT_ENABLED, 1)
    AC_CHECK_LIB(nss3, NSS_NoDB_Init, , [AC_MSG_ERROR(not found NSS libraries)])
    AC_CHECK_LIB(plds4, PL_ArenaFinish, , [AC_MSG_ERROR(not found PL_ArenaFinish)])
    AC_CHECK_LIB(nspr4, PR_Cleanup, , [AC_MSG_ERROR(not found PR_Cleanup)])
    AC_CHECK_HEADER(nss.h, , [AC_MSG_ERROR(not found nss.h)])
    AC_CHECK_HEADER(nspr4/prinit.h, , [AC_MSG_ERROR(not found prinit.h)])
    AC_PATH_PROG(NSSCONFIG, [nss-config], no)
    AS_IF(
      [test $NSSCONFIG = no],
      [
        DEPS_CFLAGS="$DEPS_CFLAGS -I/usr/include/nss3"
        DEPS_LIBS="$DEPS_LIBS -lnss3"
      ],
      [
        addcflags=`nss-config --cflags`
        DEPS_CFLAGS="$DEPS_CFLAGS $addcflags"
        dnl addlib=`nss-config --libs`
        dnl DEPS_LIBS="$DEPS_LIBS $addlib"
        DEPS_LIBS="$DEPS_LIBS -lnss3"
      ])
    AC_PATH_PROG(NSPRCONFIG, [nspr-config], no)
    AS_IF(
      [test $NSPRCONFIG = no],
      [
        DEPS_CFLAGS="$DEPS_CFLAGS -I/usr/include/nspr4"
        DEPS_LIBS="$DEPS_LIBS -lnspr4 -lplds4"
      ],
      [
        addcflags=`nspr-config --cflags`
        DEPS_CFLAGS="$DEPS_CFLAGS $addcflags"
        dnl addlib=`nspr-config --libs`
        dnl DEPS_LIBS="$DEPS_LIBS $addlib"
        DEPS_LIBS="$DEPS_LIBS -lnspr4 -lplds4"
      ])
  ])

AS_UNSET(nss_enabled)

AC_CONFIG_FILES(Makefile src/Makefile test/Makefile doc/Makefile)
AC_OUTPUT

