bin_PROGRAMS=s3fs

AM_CPPFLAGS = $(DEPS_CFLAGS)
if USE_GNUTLS_NETTLE
  AM_CPPFLAGS += -DUSE_GNUTLS_NETTLE
endif

s3fs_SOURCES = s3fs.cpp s3fs.h curl.cpp curl.h cache.cpp cache.h string_util.cpp string_util.h s3fs_util.cpp s3fs_util.h fdcache.cpp fdcache.h common_auth.cpp s3fs_auth.h common.h
if USE_SSL_OPENSSL
  s3fs_SOURCES += openssl_auth.cpp
endif
if USE_SSL_GNUTLS
  s3fs_SOURCES += gnutls_auth.cpp
endif
if USE_SSL_NSS
  s3fs_SOURCES += nss_auth.cpp
endif

s3fs_LDADD = $(DEPS_LIBS)

