/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright 2007-2008 Randy Rizun <rrizun@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <gcrypt.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#ifdef	USE_GNUTLS_NETTLE
#include <nettle/md5.h>
#include <nettle/sha1.h>
#include <nettle/hmac.h>
#endif
#include <string>
#include <map>

#include "common.h"
#include "s3fs_auth.h"

using namespace std;

//-------------------------------------------------------------------
// Utility Function for version
//-------------------------------------------------------------------
#ifdef	USE_GNUTLS_NETTLE

const char* s3fs_crypt_lib_name(void)
{
  static const char version[] = "GnuTLS(nettle)";

  return version;
}

#else	// USE_GNUTLS_NETTLE

const char* s3fs_crypt_lib_name(void)
{
  static const char version[] = "GnuTLS(gcrypt)";

  return version;
}

#endif	// USE_GNUTLS_NETTLE

//-------------------------------------------------------------------
// Utility Function for global init
//-------------------------------------------------------------------
bool s3fs_init_global_ssl(void)
{
  if(GNUTLS_E_SUCCESS != gnutls_global_init()){
    return false;
  }
  return true;
}

bool s3fs_destroy_global_ssl(void)
{
  gnutls_global_deinit();
  return true;
}

//-------------------------------------------------------------------
// Utility Function for crypt lock
//-------------------------------------------------------------------
bool s3fs_init_crypt_mutex(void)
{
  return true;
}

bool s3fs_destroy_crypt_mutex(void)
{
  return true;
}

//-------------------------------------------------------------------
// Utility Function for HMAC
//-------------------------------------------------------------------
#ifdef	USE_GNUTLS_NETTLE

bool s3fs_HMAC(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen)
{
  if(!key || 0 >= keylen || !data || 0 >= datalen || !digest || !digestlen){
    return false;
  }

  if(NULL == (*digest = (unsigned char*)malloc(SHA1_DIGEST_SIZE))){
    return false;
  }

  struct hmac_sha1_ctx ctx_hmac;
  hmac_sha1_set_key(&ctx_hmac, keylen, reinterpret_cast<const uint8_t*>(key));
  hmac_sha1_update(&ctx_hmac, datalen, reinterpret_cast<const uint8_t*>(data));
  hmac_sha1_digest(&ctx_hmac, SHA1_DIGEST_SIZE, reinterpret_cast<uint8_t*>(*digest));
  *digestlen = SHA1_DIGEST_SIZE;

  return true;
}

bool s3fs_HMAC256(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen)
{
  if(!key || 0 >= keylen || !data || 0 >= datalen || !digest || !digestlen){
    return false;
  }

  if(NULL == (*digest = (unsigned char*)malloc(SHA256_DIGEST_SIZE))){
    return false;
  }

  struct hmac_sha256_ctx ctx_hmac;
  hmac_sha256_set_key(&ctx_hmac, keylen, reinterpret_cast<const uint8_t*>(key));
  hmac_sha256_update(&ctx_hmac, datalen, reinterpret_cast<const uint8_t*>(data));
  hmac_sha256_digest(&ctx_hmac, SHA256_DIGEST_SIZE, reinterpret_cast<uint8_t*>(*digest));
  *digestlen = SHA256_DIGEST_SIZE;

  return true;
}

#else	// USE_GNUTLS_NETTLE

bool s3fs_HMAC(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen)
{
  if(!key || 0 >= keylen || !data || 0 >= datalen || !digest || !digestlen){
    return false;
  }

  if(0 >= (*digestlen = gnutls_hmac_get_len(GNUTLS_MAC_SHA1))){
    return false;
  }
  if(NULL == (*digest = (unsigned char*)malloc(*digestlen + 1))){
    return false;
  }
  if(0 > gnutls_hmac_fast(GNUTLS_MAC_SHA1, key, keylen, data, datalen, *digest)){
    free(*digest);
    *digest = NULL;
    return false;
  }
  return true;
}

bool s3fs_HMAC256(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen)
{
  if(!key || 0 >= keylen || !data || 0 >= datalen || !digest || !digestlen){
    return false;
  }

  if(0 >= (*digestlen = gnutls_hmac_get_len(GNUTLS_MAC_SHA256))){
    return false;
  }
  if(NULL == (*digest = (unsigned char*)malloc(*digestlen + 1))){
    return false;
  }
  if(0 > gnutls_hmac_fast(GNUTLS_MAC_SHA256, key, keylen, data, datalen, *digest)){
    free(*digest);
    *digest = NULL;
    return false;
  }
  return true;
}

#endif	// USE_GNUTLS_NETTLE

//-------------------------------------------------------------------
// Utility Function for MD5
//-------------------------------------------------------------------
#define MD5_DIGEST_LENGTH     16

size_t get_md5_digest_length(void)
{
  return MD5_DIGEST_LENGTH;
}

#ifdef	USE_GNUTLS_NETTLE
unsigned char* s3fs_md5hexsum(int fd, off_t start, ssize_t size)
{
  struct md5_ctx ctx_md5;
  unsigned char  buf[512];
  ssize_t        bytes;
  unsigned char* result;

  // seek to top of file.
  if(-1 == lseek(fd, start, SEEK_SET)){
    return NULL;
  }

  memset(buf, 0, 512);
  md5_init(&ctx_md5);

  for(ssize_t total = 0; total < size; total += bytes){
    bytes = 512 < (size - total) ? 512 : (size - total);
    bytes = read(fd, buf, bytes);
    if(0 == bytes){
      // end of file
      break;
    }else if(-1 == bytes){
      // error
      S3FS_PRN_ERR("file read error(%d)", errno);
      return NULL;
    }
    md5_update(&ctx_md5, bytes, buf);
    memset(buf, 0, 512);
  }
  if(NULL == (result = (unsigned char*)malloc(get_md5_digest_length()))){
    return NULL;
  }
  md5_digest(&ctx_md5, get_md5_digest_length(), result);

  if(-1 == lseek(fd, start, SEEK_SET)){
    free(result);
    return NULL;
  }

  return result;
}

#else	// USE_GNUTLS_NETTLE

unsigned char* s3fs_md5hexsum(int fd, off_t start, ssize_t size)
{
  gcry_md_hd_t ctx_md5;
  gcry_error_t err;
  char    buf[512];
  ssize_t bytes;
  unsigned char* result;

  if(-1 == size){
    struct stat st;
    if(-1 == fstat(fd, &st)){
      return NULL;
    }
    size = static_cast<ssize_t>(st.st_size);
  }

  // seek to top of file.
  if(-1 == lseek(fd, start, SEEK_SET)){
    return NULL;
  }

  memset(buf, 0, 512);
  if(GPG_ERR_NO_ERROR != (err = gcry_md_open(&ctx_md5, GCRY_MD_MD5, 0))){
    S3FS_PRN_ERR("MD5 context creation failure: %s/%s", gcry_strsource(err), gcry_strerror(err));
    return NULL;
  }

  for(ssize_t total = 0; total < size; total += bytes){
    bytes = 512 < (size - total) ? 512 : (size - total);
    bytes = read(fd, buf, bytes);
    if(0 == bytes){
      // end of file
      break;
    }else if(-1 == bytes){
      // error
      S3FS_PRN_ERR("file read error(%d)", errno);
      return NULL;
    }
    gcry_md_write(ctx_md5, buf, bytes);
    memset(buf, 0, 512);
  }
  if(NULL == (result = (unsigned char*)malloc(get_md5_digest_length()))){
    return NULL;
  }
  memcpy(result, gcry_md_read(ctx_md5, 0), get_md5_digest_length());
  gcry_md_close(ctx_md5);

  if(-1 == lseek(fd, start, SEEK_SET)){
    free(result);
    return NULL;
  }

  return result;
}

#endif	// USE_GNUTLS_NETTLE

//-------------------------------------------------------------------
// Utility Function for SHA256
//-------------------------------------------------------------------
#define SHA256_DIGEST_LENGTH     32

size_t get_sha256_digest_length(void)
{
  return SHA256_DIGEST_LENGTH;
}

#ifdef	USE_GNUTLS_NETTLE
bool s3fs_sha256(const unsigned char* data, unsigned int datalen, unsigned char** digest, unsigned int* digestlen)
{
  (*digestlen) = static_cast<unsigned int>(get_sha256_digest_length());
  if(NULL == ((*digest) = reinterpret_cast<unsigned char*>(malloc(*digestlen)))){
    return false;
  }

  struct sha256_ctx ctx_sha256;
  sha256_init(&ctx_sha256);
  sha256_update(&ctx_sha256, datalen, data);
  sha256_digest(&ctx_sha256, *digestlen, *digest);

  return true;
}

unsigned char* s3fs_sha256hexsum(int fd, off_t start, ssize_t size)
{
  struct sha256_ctx ctx_sha256;
  unsigned char     buf[512];
  ssize_t           bytes;
  unsigned char*    result;

  // seek to top of file.
  if(-1 == lseek(fd, start, SEEK_SET)){
    return NULL;
  }

  memset(buf, 0, 512);
  sha256_init(&ctx_sha256);

  for(ssize_t total = 0; total < size; total += bytes){
    bytes = 512 < (size - total) ? 512 : (size - total);
    bytes = read(fd, buf, bytes);
    if(0 == bytes){
      // end of file
      break;
    }else if(-1 == bytes){
      // error
      S3FS_PRN_ERR("file read error(%d)", errno);
      return NULL;
    }
    sha256_update(&ctx_sha256, bytes, buf);
    memset(buf, 0, 512);
  }
  if(NULL == (result = (unsigned char*)malloc(get_sha256_digest_length()))){
    return NULL;
  }
  sha256_digest(&ctx_sha256, get_sha256_digest_length(), result);

  if(-1 == lseek(fd, start, SEEK_SET)){
    free(result);
    return NULL;
  }

  return result;
}

#else	// USE_GNUTLS_NETTLE

bool s3fs_sha256(const unsigned char* data, unsigned int datalen, unsigned char** digest, unsigned int* digestlen)
{
  (*digestlen) = static_cast<unsigned int>(get_sha256_digest_length());
  if(NULL == ((*digest) = reinterpret_cast<unsigned char*>(malloc(*digestlen)))){
    return false;
  }

  gcry_md_hd_t   ctx_sha256;
  gcry_error_t   err;
  if(GPG_ERR_NO_ERROR != (err = gcry_md_open(&ctx_sha256, GCRY_MD_SHA256, 0))){
    S3FS_PRN_ERR("SHA256 context creation failure: %s/%s", gcry_strsource(err), gcry_strerror(err));
    free(*digest);
    return false;
  }
  gcry_md_write(ctx_sha256, data, datalen);
  memcpy(*digest, gcry_md_read(ctx_sha256, 0), *digestlen);
  gcry_md_close(ctx_sha256);

  return true;
}

unsigned char* s3fs_sha256hexsum(int fd, off_t start, ssize_t size)
{
  gcry_md_hd_t   ctx_sha256;
  gcry_error_t   err;
  char           buf[512];
  ssize_t        bytes;
  unsigned char* result;

  if(-1 == size){
    struct stat st;
    if(-1 == fstat(fd, &st)){
      return NULL;
    }
    size = static_cast<ssize_t>(st.st_size);
  }

  // seek to top of file.
  if(-1 == lseek(fd, start, SEEK_SET)){
    return NULL;
  }

  memset(buf, 0, 512);
  if(GPG_ERR_NO_ERROR != (err = gcry_md_open(&ctx_sha256, GCRY_MD_SHA256, 0))){
    S3FS_PRN_ERR("SHA256 context creation failure: %s/%s", gcry_strsource(err), gcry_strerror(err));
    return NULL;
  }

  for(ssize_t total = 0; total < size; total += bytes){
    bytes = 512 < (size - total) ? 512 : (size - total);
    bytes = read(fd, buf, bytes);
    if(0 == bytes){
      // end of file
      break;
    }else if(-1 == bytes){
      // error
      S3FS_PRN_ERR("file read error(%d)", errno);
      return NULL;
    }
    gcry_md_write(ctx_sha256, buf, bytes);
    memset(buf, 0, 512);
  }
  if(NULL == (result = (unsigned char*)malloc(get_sha256_digest_length()))){
    return NULL;
  }
  memcpy(result, gcry_md_read(ctx_sha256, 0), get_sha256_digest_length());
  gcry_md_close(ctx_sha256);

  if(-1 == lseek(fd, start, SEEK_SET)){
    free(result);
    return NULL;
  }

  return result;
}

#endif	// USE_GNUTLS_NETTLE

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
