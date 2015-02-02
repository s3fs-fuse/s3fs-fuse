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
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <string>
#include <map>

#include "common.h"
#include "s3fs_auth.h"

using namespace std;

//-------------------------------------------------------------------
// Utility Function for version
//-------------------------------------------------------------------
const char* s3fs_crypt_lib_name(void)
{
  static const char version[] = "OpenSSL";

  return version;
}

//-------------------------------------------------------------------
// Utility Function for global init
//-------------------------------------------------------------------
bool s3fs_init_global_ssl(void)
{
  ERR_load_crypto_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  return true;
}

bool s3fs_destroy_global_ssl(void)
{
  EVP_cleanup();
  ERR_free_strings();
  return true;
}

//-------------------------------------------------------------------
// Utility Function for crypt lock
//-------------------------------------------------------------------
// internal use struct for openssl
struct CRYPTO_dynlock_value
{
  pthread_mutex_t dyn_mutex;
};

static pthread_mutex_t* s3fs_crypt_mutex = NULL;

static void s3fs_crypt_mutex_lock(int mode, int pos, const char* file, int line)
{
  if(s3fs_crypt_mutex){
    if(mode & CRYPTO_LOCK){
      pthread_mutex_lock(&s3fs_crypt_mutex[pos]);
    }else{
      pthread_mutex_unlock(&s3fs_crypt_mutex[pos]);
    }
  }
}

static unsigned long s3fs_crypt_get_threadid(void)
{
  // For FreeBSD etc, some system's pthread_t is structure pointer.
  // Then we use cast like C style(not C++) instead of ifdef.
  return (unsigned long)(pthread_self());
}

static struct CRYPTO_dynlock_value* s3fs_dyn_crypt_mutex(const char* file, int line)
{
  struct CRYPTO_dynlock_value* dyndata;

  if(NULL == (dyndata = static_cast<struct CRYPTO_dynlock_value*>(malloc(sizeof(struct CRYPTO_dynlock_value))))){
    DPRNCRIT("Could not allocate memory for CRYPTO_dynlock_value");
    return NULL;
  }
  pthread_mutex_init(&(dyndata->dyn_mutex), NULL);
  return dyndata;
}

static void s3fs_dyn_crypt_mutex_lock(int mode, struct CRYPTO_dynlock_value* dyndata, const char* file, int line)
{
  if(dyndata){
    if(mode & CRYPTO_LOCK){
      pthread_mutex_lock(&(dyndata->dyn_mutex));
    }else{
      pthread_mutex_unlock(&(dyndata->dyn_mutex));
    }
  }
}

static void s3fs_destroy_dyn_crypt_mutex(struct CRYPTO_dynlock_value* dyndata, const char* file, int line)
{
  if(dyndata){
    pthread_mutex_destroy(&(dyndata->dyn_mutex));
    free(dyndata);
  }
}

bool s3fs_init_crypt_mutex(void)
{
  if(s3fs_crypt_mutex){
    FPRNNN("s3fs_crypt_mutex is not NULL, destroy it.");
    if(!s3fs_destroy_crypt_mutex()){
      DPRN("Failed to s3fs_crypt_mutex");
      return false;
    }
  }
  if(NULL == (s3fs_crypt_mutex = static_cast<pthread_mutex_t*>(malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t))))){
    DPRNCRIT("Could not allocate memory for s3fs_crypt_mutex");
    return false;
  }
  for(int cnt = 0; cnt < CRYPTO_num_locks(); cnt++){
    pthread_mutex_init(&s3fs_crypt_mutex[cnt], NULL);
  }
  // static lock
  CRYPTO_set_locking_callback(s3fs_crypt_mutex_lock);
  CRYPTO_set_id_callback(s3fs_crypt_get_threadid);
  // dynamic lock
  CRYPTO_set_dynlock_create_callback(s3fs_dyn_crypt_mutex);
  CRYPTO_set_dynlock_lock_callback(s3fs_dyn_crypt_mutex_lock);
  CRYPTO_set_dynlock_destroy_callback(s3fs_destroy_dyn_crypt_mutex);

  return true;
}

bool s3fs_destroy_crypt_mutex(void)
{
  if(!s3fs_crypt_mutex){
    return true;
  }

  CRYPTO_set_dynlock_destroy_callback(NULL);
  CRYPTO_set_dynlock_lock_callback(NULL);
  CRYPTO_set_dynlock_create_callback(NULL);
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);

  for(int cnt = 0; cnt < CRYPTO_num_locks(); cnt++){
    pthread_mutex_destroy(&s3fs_crypt_mutex[cnt]);
  }
  CRYPTO_cleanup_all_ex_data();
  free(s3fs_crypt_mutex);
  s3fs_crypt_mutex = NULL;

  return true;
}

//-------------------------------------------------------------------
// Utility Function for HMAC
//-------------------------------------------------------------------
static bool s3fs_HMAC_RAW(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen, bool is_sha256)
{
  if(!key || 0 >= keylen || !data || 0 >= datalen || !digest || !digestlen){
    return false;
  }
  (*digestlen) = EVP_MAX_MD_SIZE * sizeof(unsigned char);
  if(NULL == ((*digest) = (unsigned char*)malloc(*digestlen))){
    return false;
  }
  if(is_sha256){
    HMAC(EVP_sha256(), key, keylen, data, datalen, *digest, digestlen);
  }else{
    HMAC(EVP_sha1(), key, keylen, data, datalen, *digest, digestlen);
  }

  return true;
}

bool s3fs_HMAC(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen)
{
  return s3fs_HMAC_RAW(key, keylen, data, datalen, digest, digestlen, false);
}

bool s3fs_HMAC256(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen)
{
  return s3fs_HMAC_RAW(key, keylen, data, datalen, digest, digestlen, true);
}

//-------------------------------------------------------------------
// Utility Function for MD5
//-------------------------------------------------------------------
size_t get_md5_digest_length(void)
{
  return MD5_DIGEST_LENGTH;
}

unsigned char* s3fs_md5hexsum(int fd, off_t start, ssize_t size)
{
  MD5_CTX md5ctx;
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
  MD5_Init(&md5ctx);

  for(ssize_t total = 0; total < size; total += bytes){
    bytes = 512 < (size - total) ? 512 : (size - total);
    bytes = read(fd, buf, bytes);
    if(0 == bytes){
      // end of file
      break;
    }else if(-1 == bytes){
      // error
      DPRNNN("file read error(%d)", errno);
      return NULL;
    }
    MD5_Update(&md5ctx, buf, bytes);
    memset(buf, 0, 512);
  }

  if(NULL == (result = (unsigned char*)malloc(get_md5_digest_length()))){
    return NULL;
  }
  MD5_Final(result, &md5ctx);

  if(-1 == lseek(fd, start, SEEK_SET)){
    free(result);
    return NULL;
  }

  return result;
}

//-------------------------------------------------------------------
// Utility Function for SHA256
//-------------------------------------------------------------------
size_t get_sha256_digest_length(void)
{
  return SHA256_DIGEST_LENGTH;
}

bool s3fs_sha256(const unsigned char* data, unsigned int datalen, unsigned char** digest, unsigned int* digestlen)
{
  (*digestlen) = EVP_MAX_MD_SIZE * sizeof(unsigned char);
  if(NULL == ((*digest) = reinterpret_cast<unsigned char*>(malloc(*digestlen)))){
    return false;
  }

  const EVP_MD* md    = EVP_get_digestbyname("sha256");
  EVP_MD_CTX*   mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, data, datalen);
  EVP_DigestFinal_ex(mdctx, *digest, digestlen);
  EVP_MD_CTX_destroy(mdctx);

  return true;
}

unsigned char* s3fs_sha256hexsum(int fd, off_t start, ssize_t size)
{
  const EVP_MD* md        = EVP_get_digestbyname("sha256");
  EVP_MD_CTX*   sha256ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(sha256ctx, md, NULL);

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
  for(ssize_t total = 0; total < size; total += bytes){
    bytes = 512 < (size - total) ? 512 : (size - total);
    bytes = read(fd, buf, bytes);
    if(0 == bytes){
      // end of file
      break;
    }else if(-1 == bytes){
      // error
      DPRNNN("file read error(%d)", errno);
      return NULL;
    }
    EVP_DigestUpdate(sha256ctx, buf, bytes);
    memset(buf, 0, 512);
  }
  if(NULL == (result = (unsigned char*)malloc(get_sha256_digest_length()))){
    return NULL;
  }
  EVP_DigestFinal_ex(sha256ctx, result, NULL);
  EVP_MD_CTX_destroy(sha256ctx);

  if(-1 == lseek(fd, start, SEEK_SET)){
    free(result);
    return NULL;
  }
  return result;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
