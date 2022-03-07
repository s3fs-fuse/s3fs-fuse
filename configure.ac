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
AC_INIT(s3fs, 1.91)
AC_CONFIG_HEADER([config.h])

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CXX
AC_PROG_CC

AC_CHECK_HEADERS([sys/xattr.h])
AC_CHECK_HEADERS([attr/xattr.h])
AC_CHECK_HEADERS([sys/extattr.h])
AC_CHECK_FUNCS([fallocate])

CXXFLAGS="$CXXFLAGS -Wall -fno-exceptions -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=2"

dnl ----------------------------------------------
dnl For macOS
dnl ----------------------------------------------
case "$target" in
   *-cygwin* )
      # Do something specific for windows using winfsp
      CXXFLAGS="$CXXFLAGS -D_GNU_SOURCE=1"
      min_fuse_version=2.8
      ;;
   *-darwin* )
      # Do something specific for mac
      min_fuse_version=2.7.3
      ;;
   *)
      # Default Case
      # assume other supported linux system
      min_fuse_version=2.8.4
      ;;
esac

dnl ----------------------------------------------
dnl Choice SSL library
dnl ----------------------------------------------
auth_lib=na
nettle_lib=no

dnl
dnl nettle library
dnl
AC_MSG_CHECKING([s3fs build with nettle(GnuTLS)])
AC_ARG_WITH(
  nettle,
  [AS_HELP_STRING([--with-nettle], [s3fs build with nettle in GnuTLS(default no)])],
  [
    case "${withval}" in
    yes)
      AC_MSG_RESULT(yes)
      nettle_lib=yes
      ;;
    *)
      AC_MSG_RESULT(no)
      ;;
    esac
  ],
  [
    AC_MSG_RESULT(no)
  ])

dnl
dnl use openssl library for ssl
dnl
AC_MSG_CHECKING([s3fs build with OpenSSL])
AC_ARG_WITH(
  openssl,
  [AS_HELP_STRING([--with-openssl], [s3fs build with OpenSSL(default is no)])],
  [
    case "${withval}" in
    yes)
      AC_MSG_RESULT(yes)
      AS_IF(
        [test $nettle_lib = no],
        [auth_lib=openssl],
        [AC_MSG_ERROR([could not set openssl with nettle, nettle is only for gnutls library])])
      ;;
    *)
      AC_MSG_RESULT(no)
      ;;
    esac
  ],
  [
    AC_MSG_RESULT(no)
  ])

dnl
dnl use GnuTLS library for ssl
dnl
AC_MSG_CHECKING([s3fs build with GnuTLS])
AC_ARG_WITH(
  gnutls,
  [AS_HELP_STRING([--with-gnutls], [s3fs build with GnuTLS(default is no)])],
  [
    case "${withval}" in
    yes)
      AC_MSG_RESULT(yes)
      AS_IF(
        [test $auth_lib = na],
        [
          AS_IF(
            [test $nettle_lib = no],
            [auth_lib=gnutls],
            [auth_lib=nettle])
        ],
        [AC_MSG_ERROR([could not set gnutls because already set another ssl library])])
      ;;
    *)
      AC_MSG_RESULT(no)
      ;;
    esac
  ],
  [
    AC_MSG_RESULT(no)
  ])

dnl
dnl use nss library for ssl
dnl
AC_MSG_CHECKING([s3fs build with NSS])
AC_ARG_WITH(
  nss,
  [AS_HELP_STRING([--with-nss], [s3fs build with NSS(default is no)])],
  [
    case "${withval}" in
    yes)
      AC_MSG_RESULT(yes)
      AS_IF(
        [test $auth_lib = na],
        [
          AS_IF(
            [test $nettle_lib = no],
            [auth_lib=nss],
            [AC_MSG_ERROR([could not set openssl with nettle, nettle is only for gnutls library])])
        ],
        [AC_MSG_ERROR([could not set nss because already set another ssl library])])
      ;;
    *)
      AC_MSG_RESULT(no)
      ;;
    esac
  ],
  [
    AC_MSG_RESULT(no)
  ])

AS_IF(
  [test $auth_lib = na],
  AS_IF(
    [test $nettle_lib = no],
    [auth_lib=openssl],
    [AC_MSG_ERROR([could not set nettle without GnuTLS library])]
  )
)

dnl
dnl For PKG_CONFIG before checking nss/gnutls.
dnl this is redundant checking, but we need checking before following.
dnl
PKG_CHECK_MODULES([common_lib_checking], [fuse >= ${min_fuse_version} libcurl >= 7.0 libxml-2.0 >= 2.6 ])

AC_MSG_CHECKING([compile s3fs with])
case "${auth_lib}" in
openssl)
  AC_MSG_RESULT(OpenSSL)
  PKG_CHECK_MODULES([DEPS], [fuse >= ${min_fuse_version} libcurl >= 7.0 libxml-2.0 >= 2.6 libcrypto >= 0.9 ])
  ;;
gnutls)
  AC_MSG_RESULT(GnuTLS-gcrypt)
  gnutls_nettle=""
  AC_CHECK_LIB(gnutls, gcry_control, [gnutls_nettle=0])
  AS_IF([test "$gnutls_nettle" = ""], [AC_CHECK_LIB(gcrypt, gcry_control, [gnutls_nettle=0])])
  AS_IF([test $gnutls_nettle = 0],
    [
      PKG_CHECK_MODULES([DEPS], [fuse >= ${min_fuse_version} libcurl >= 7.0 libxml-2.0 >= 2.6 gnutls >= 2.12.0 ])
      LIBS="-lgnutls -lgcrypt $LIBS"
      AC_MSG_CHECKING([gnutls is build with])
      AC_MSG_RESULT(gcrypt)
    ],
    [AC_MSG_ERROR([GnuTLS found, but gcrypt not found])])
  ;;
nettle)
  AC_MSG_RESULT(GnuTLS-nettle)
  gnutls_nettle=""
  AC_CHECK_LIB(gnutls, nettle_MD5Init, [gnutls_nettle=1])
  AS_IF([test "$gnutls_nettle" = ""], [AC_CHECK_LIB(nettle, nettle_MD5Init, [gnutls_nettle=1])])
  AS_IF([test $gnutls_nettle = 1],
    [
      PKG_CHECK_MODULES([DEPS], [fuse >= ${min_fuse_version} libcurl >= 7.0 libxml-2.0 >= 2.6 nettle >= 2.7.1 ])
      LIBS="-lgnutls -lnettle $LIBS"
      AC_MSG_CHECKING([gnutls is build with])
      AC_MSG_RESULT(nettle)
    ],
    [AC_MSG_ERROR([GnuTLS found, but nettle not found])])
  ;;
nss)
  AC_MSG_RESULT(NSS)
  PKG_CHECK_MODULES([DEPS], [fuse >= ${min_fuse_version} libcurl >= 7.0 libxml-2.0 >= 2.6 nss >= 3.15.0 ])
  ;;
*)
  AC_MSG_ERROR([unknown ssl library type.])
  ;;
esac

AM_CONDITIONAL([USE_SSL_OPENSSL], [test "$auth_lib" = openssl])
AM_CONDITIONAL([USE_SSL_GNUTLS], [test "$auth_lib" = gnutls -o "$auth_lib" = nettle])
AM_CONDITIONAL([USE_GNUTLS_NETTLE], [test "$auth_lib" = nettle])
AM_CONDITIONAL([USE_SSL_NSS], [test "$auth_lib" = nss])

dnl ----------------------------------------------
dnl check functions
dnl ----------------------------------------------
dnl malloc_trim function
AC_CHECK_FUNCS([malloc_trim])

dnl clock_gettime function(macos)
AC_SEARCH_LIBS([clock_gettime],[rt posix4]) 
AC_CHECK_FUNCS([clock_gettime])

dnl ----------------------------------------------
dnl check symbols/macros/enums
dnl ----------------------------------------------
dnl PTHREAD_MUTEX_RECURSIVE
AC_MSG_CHECKING([pthread mutex recursive])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([[#include <pthread.h>]],
                   [[int i = PTHREAD_MUTEX_RECURSIVE;]])
  ],
  [AC_DEFINE(S3FS_MUTEX_RECURSIVE, PTHREAD_MUTEX_RECURSIVE, [Define if you have PTHREAD_MUTEX_RECURSIVE])
   AC_MSG_RESULT(PTHREAD_MUTEX_RECURSIVE)
  ],
  [AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <pthread.h>]],
                     [[int i = PTHREAD_MUTEX_RECURSIVE_NP;]])
    ],
    [AC_DEFINE(S3FS_MUTEX_RECURSIVE, PTHREAD_MUTEX_RECURSIVE_NP, [Define if you have PTHREAD_MUTEX_RECURSIVE_NP])
     AC_MSG_RESULT(PTHREAD_MUTEX_RECURSIVE_NP)
    ],
    [AC_MSG_ERROR([do not have PTHREAD_MUTEX_RECURSIVE symbol])])
  ]
)

dnl ----------------------------------------------
dnl check CURLoption
dnl ----------------------------------------------
dnl CURLOPT_TCP_KEEPALIVE (is supported by 7.25.0 and later)
AC_MSG_CHECKING([checking CURLOPT_TCP_KEEPALIVE])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([[#include <curl/curl.h>]],
                   [[CURLoption opt = CURLOPT_TCP_KEEPALIVE;]])
  ],
  [AC_DEFINE(HAVE_CURLOPT_TCP_KEEPALIVE, 1, [Define to 1 if libcurl has CURLOPT_TCP_KEEPALIVE CURLoption])
   AC_MSG_RESULT(yes)
  ],
  [AC_DEFINE(HAVE_CURLOPT_TCP_KEEPALIVE, 0, [Define to 1 if libcurl has CURLOPT_TCP_KEEPALIVE CURLoption])
   AC_MSG_RESULT(no)
  ]
)

dnl CURLOPT_SSL_ENABLE_ALPN (is supported by 7.36.0 and later)
AC_MSG_CHECKING([checking CURLOPT_SSL_ENABLE_ALPN])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([[#include <curl/curl.h>]],
                   [[CURLoption opt = CURLOPT_SSL_ENABLE_ALPN;]])
  ],
  [AC_DEFINE(HAVE_CURLOPT_SSL_ENABLE_ALPN, 1, [Define to 1 if libcurl has CURLOPT_SSL_ENABLE_ALPN CURLoption])
   AC_MSG_RESULT(yes)
  ],
  [AC_DEFINE(HAVE_CURLOPT_SSL_ENABLE_ALPN, 0, [Define to 1 if libcurl has CURLOPT_SSL_ENABLE_ALPN CURLoption])
   AC_MSG_RESULT(no)
  ]
)

dnl CURLOPT_KEEP_SENDING_ON_ERROR (is supported by 7.51.0 and later)
AC_MSG_CHECKING([checking CURLOPT_KEEP_SENDING_ON_ERROR])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([[#include <curl/curl.h>]],
                   [[CURLoption opt = CURLOPT_KEEP_SENDING_ON_ERROR;]])
  ],
  [AC_DEFINE(HAVE_CURLOPT_KEEP_SENDING_ON_ERROR, 1, [Define to 1 if libcurl has CURLOPT_KEEP_SENDING_ON_ERROR CURLoption])
   AC_MSG_RESULT(yes)
  ],
  [AC_DEFINE(HAVE_CURLOPT_KEEP_SENDING_ON_ERROR, 0, [Define to 1 if libcurl has CURLOPT_KEEP_SENDING_ON_ERROR CURLoption])
   AC_MSG_RESULT(no)
  ]
)

dnl ----------------------------------------------
dnl build date
dnl ----------------------------------------------
AC_SUBST([MAN_PAGE_DATE], [$(date +"%B %Y")])

dnl ----------------------------------------------
dnl output files
dnl ----------------------------------------------
AC_CONFIG_FILES(Makefile
                src/Makefile
                test/Makefile
                doc/Makefile
                doc/man/s3fs.1)

dnl ----------------------------------------------
dnl short commit hash
dnl ----------------------------------------------
AC_CHECK_PROG([GITCMD], [git --version], [yes], [no])
AS_IF([test -d .git], [DOTGITDIR=yes], [DOTGITDIR=no])

AC_MSG_CHECKING([github short commit hash])
if test "x${GITCMD}" = "xyes" -a "x${DOTGITDIR}" = "xyes"; then
    GITCOMMITHASH=`git rev-parse --short HEAD`
elif test -f default_commit_hash; then
    GITCOMMITHASH=`cat default_commit_hash`
else
    GITCOMMITHASH="unknown"
fi
AC_MSG_RESULT([${GITCOMMITHASH}])

AC_DEFINE_UNQUOTED([COMMIT_HASH_VAL], ["${GITCOMMITHASH}"], [short commit hash value on github])

dnl ----------------------------------------------
dnl put
dnl ----------------------------------------------
AC_OUTPUT

dnl ----------------------------------------------
dnl end configuration
dnl ----------------------------------------------

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
