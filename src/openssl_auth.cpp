/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2007 Randy Rizun <rrizun@gmail.com>
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

#ifdef __clang__
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <string>

#include "s3fs_auth.h"
#include "s3fs_logger.h"

//-------------------------------------------------------------------
// Utility Function for version
//-------------------------------------------------------------------
const char* s3fs_crypt_lib_name()
{
    static constexpr char version[] = "OpenSSL";

    return version;
}

//-------------------------------------------------------------------
// Utility Function for global init
//-------------------------------------------------------------------
bool s3fs_init_global_ssl()
{
    ERR_load_crypto_strings();

    // [NOTE]
    // OpenSSL 3.0 loads error strings automatically so these functions are not needed.
    //
    #ifndef USE_OPENSSL_30
    ERR_load_BIO_strings();
    #endif

    OpenSSL_add_all_algorithms();
    return true;
}

bool s3fs_destroy_global_ssl()
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

static pthread_mutex_t* s3fs_crypt_mutex = nullptr;

static void s3fs_crypt_mutex_lock(int mode, int pos, const char* file, int line) __attribute__ ((unused));
static void s3fs_crypt_mutex_lock(int mode, int pos, const char* file, int line)
{
    if(s3fs_crypt_mutex){
        int result;
        if(mode & CRYPTO_LOCK){
            if(0 != (result = pthread_mutex_lock(&s3fs_crypt_mutex[pos]))){
                S3FS_PRN_CRIT("pthread_mutex_lock returned: %d", result);
                abort();
            }
        }else{
            if(0 != (result = pthread_mutex_unlock(&s3fs_crypt_mutex[pos]))){
                S3FS_PRN_CRIT("pthread_mutex_unlock returned: %d", result);
                abort();
            }
        }
    }
}

static unsigned long s3fs_crypt_get_threadid() __attribute__ ((unused));
static unsigned long s3fs_crypt_get_threadid()
{
    // For FreeBSD etc, some system's pthread_t is structure pointer.
    // Then we use cast like C style(not C++) instead of ifdef.
    return (unsigned long)(pthread_self());
}

static struct CRYPTO_dynlock_value* s3fs_dyn_crypt_mutex(const char* file, int line) __attribute__ ((unused));
static struct CRYPTO_dynlock_value* s3fs_dyn_crypt_mutex(const char* file, int line)
{
    struct CRYPTO_dynlock_value* dyndata = new CRYPTO_dynlock_value();
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
    int result;
    if(0 != (result = pthread_mutex_init(&(dyndata->dyn_mutex), &attr))){
        S3FS_PRN_CRIT("pthread_mutex_init returned: %d", result);
        return nullptr;
    }
    return dyndata;
}

static void s3fs_dyn_crypt_mutex_lock(int mode, struct CRYPTO_dynlock_value* dyndata, const char* file, int line) __attribute__ ((unused));
static void s3fs_dyn_crypt_mutex_lock(int mode, struct CRYPTO_dynlock_value* dyndata, const char* file, int line)
{
    if(dyndata){
        int result;
        if(mode & CRYPTO_LOCK){
            if(0 != (result = pthread_mutex_lock(&(dyndata->dyn_mutex)))){
                S3FS_PRN_CRIT("pthread_mutex_lock returned: %d", result);
                abort();
            }
        }else{
            if(0 != (result = pthread_mutex_unlock(&(dyndata->dyn_mutex)))){
                S3FS_PRN_CRIT("pthread_mutex_unlock returned: %d", result);
                abort();
            }
        }
    }
}

static void s3fs_destroy_dyn_crypt_mutex(struct CRYPTO_dynlock_value* dyndata, const char* file, int line) __attribute__ ((unused));
static void s3fs_destroy_dyn_crypt_mutex(struct CRYPTO_dynlock_value* dyndata, const char* file, int line)
{
    if(dyndata){
      int result = pthread_mutex_destroy(&(dyndata->dyn_mutex));
      if(result != 0){
          S3FS_PRN_CRIT("failed to destroy dyn_mutex");
          abort();
      }
      delete dyndata;
    }
}

bool s3fs_init_crypt_mutex()
{
    if(s3fs_crypt_mutex){
        S3FS_PRN_DBG("s3fs_crypt_mutex is not nullptr, destroy it.");

        // cppcheck-suppress unmatchedSuppression
        // cppcheck-suppress knownConditionTrueFalse
        if(!s3fs_destroy_crypt_mutex()){
            S3FS_PRN_ERR("Failed to s3fs_crypt_mutex");
            return false;
        }
    }
    s3fs_crypt_mutex = new pthread_mutex_t[CRYPTO_num_locks()];
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
    for(int cnt = 0; cnt < CRYPTO_num_locks(); cnt++){
        int result = pthread_mutex_init(&s3fs_crypt_mutex[cnt], &attr);
        if(result != 0){
            S3FS_PRN_CRIT("pthread_mutex_init returned: %d", result);
            return false;
        }
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

bool s3fs_destroy_crypt_mutex()
{
    if(!s3fs_crypt_mutex){
        return true;
    }

    CRYPTO_set_dynlock_destroy_callback(nullptr);
    CRYPTO_set_dynlock_lock_callback(nullptr);
    CRYPTO_set_dynlock_create_callback(nullptr);
    CRYPTO_set_id_callback(nullptr);
    CRYPTO_set_locking_callback(nullptr);

    for(int cnt = 0; cnt < CRYPTO_num_locks(); cnt++){
        int result = pthread_mutex_destroy(&s3fs_crypt_mutex[cnt]);
        if(result != 0){
            S3FS_PRN_CRIT("failed to destroy s3fs_crypt_mutex[%d]", cnt);
            abort();
        }
    }
    CRYPTO_cleanup_all_ex_data();
    delete[] s3fs_crypt_mutex;
    s3fs_crypt_mutex = nullptr;

    return true;
}

//-------------------------------------------------------------------
// Utility Function for HMAC
//-------------------------------------------------------------------
static std::unique_ptr<unsigned char[]> s3fs_HMAC_RAW(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned int* digestlen, bool is_sha256)
{
    if(!key || !data || !digestlen){
        return nullptr;
    }
    (*digestlen) = EVP_MAX_MD_SIZE * sizeof(unsigned char);
    std::unique_ptr<unsigned char[]> digest(new unsigned char[*digestlen]);
    if(is_sha256){
        HMAC(EVP_sha256(), key, static_cast<int>(keylen), data, datalen, digest.get(), digestlen);
    }else{
        HMAC(EVP_sha1(), key, static_cast<int>(keylen), data, datalen, digest.get(), digestlen);
    }

    return digest;
}

std::unique_ptr<unsigned char[]> s3fs_HMAC(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned int* digestlen)
{
    return s3fs_HMAC_RAW(key, keylen, data, datalen, digestlen, false);
}

std::unique_ptr<unsigned char[]> s3fs_HMAC256(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned int* digestlen)
{
    return s3fs_HMAC_RAW(key, keylen, data, datalen, digestlen, true);
}

#ifdef USE_OPENSSL_30
//-------------------------------------------------------------------
// Utility Function for MD5 (OpenSSL >= 3.0)
//-------------------------------------------------------------------
// [NOTE]
// OpenSSL 3.0 deprecated the MD5_*** low-level encryption functions,
// so we should use the high-level EVP API instead.
//

bool s3fs_md5(const unsigned char* data, size_t datalen, md5_t* digest)
{
    unsigned int digestlen = static_cast<unsigned int>(digest->size());

    const EVP_MD* md    = EVP_get_digestbyname("md5");
    EVP_MD_CTX*   mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, data, datalen);
    EVP_DigestFinal_ex(mdctx, digest->data(), &digestlen);
    EVP_MD_CTX_destroy(mdctx);

    return true;
}

bool s3fs_md5_fd(int fd, off_t start, off_t size, md5_t* result)
{
    EVP_MD_CTX*    mdctx;
    unsigned int   md5_digest_len = static_cast<unsigned int>(result->size());
    off_t          bytes;

    if(-1 == size){
        struct stat st;
        if(-1 == fstat(fd, &st)){
            return false;
        }
        size = st.st_size;
    }

    // instead of MD5_Init
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr);

    for(off_t total = 0; total < size; total += bytes){
        const off_t len = 512;
        char        buf[len];
        bytes = len < (size - total) ? len : (size - total);
        bytes = pread(fd, buf, bytes, start + total);
        if(0 == bytes){
            // end of file
            break;
        }else if(-1 == bytes){
            // error
            S3FS_PRN_ERR("file read error(%d)", errno);
            EVP_MD_CTX_free(mdctx);
            return false;
        }
        // instead of MD5_Update
        EVP_DigestUpdate(mdctx, buf, bytes);
    }

    // instead of MD5_Final
    EVP_DigestFinal_ex(mdctx, result->data(), &md5_digest_len);
    EVP_MD_CTX_free(mdctx);

    return true;
}

#else
//-------------------------------------------------------------------
// Utility Function for MD5 (OpenSSL < 3.0)
//-------------------------------------------------------------------

// TODO: Does this fail on OpenSSL < 3.0 and we need to use MD5_CTX functions?
bool s3fs_md5(const unsigned char* data, size_t datalen, md5_t* digest)
{
    unsigned int digestlen = digest->size();

    const EVP_MD* md    = EVP_get_digestbyname("md5");
    EVP_MD_CTX*   mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, data, datalen);
    EVP_DigestFinal_ex(mdctx, digest->data(), &digestlen);
    EVP_MD_CTX_destroy(mdctx);

    return true;
}

bool s3fs_md5_fd(int fd, off_t start, off_t size, md5_t* result)
{
    MD5_CTX md5ctx;
    off_t   bytes;

    if(-1 == size){
        struct stat st;
        if(-1 == fstat(fd, &st)){
            return false;
        }
        size = st.st_size;
    }

    MD5_Init(&md5ctx);

    for(off_t total = 0; total < size; total += bytes){
        const off_t len = 512;
        char buf[len];
        bytes = len < (size - total) ? len : (size - total);
        bytes = pread(fd, buf, bytes, start + total);
        if(0 == bytes){
            // end of file
            break;
        }else if(-1 == bytes){
            // error
            S3FS_PRN_ERR("file read error(%d)", errno);
            return false;
        }
        MD5_Update(&md5ctx, buf, bytes);
    }

    MD5_Final(result->data(), &md5ctx);

    return true;
}
#endif

//-------------------------------------------------------------------
// Utility Function for SHA256
//-------------------------------------------------------------------
bool s3fs_sha256(const unsigned char* data, size_t datalen, sha256_t* digest)
{
    const EVP_MD* md    = EVP_get_digestbyname("sha256");
    EVP_MD_CTX*   mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, data, datalen);
    unsigned int digestlen = static_cast<unsigned int>(digest->size());
    EVP_DigestFinal_ex(mdctx, digest->data(), &digestlen);
    EVP_MD_CTX_destroy(mdctx);

    return true;
}

bool s3fs_sha256_fd(int fd, off_t start, off_t size, sha256_t* result)
{
    const EVP_MD*  md = EVP_get_digestbyname("sha256");
    EVP_MD_CTX*    sha256ctx;
    off_t          bytes;

    if(-1 == fd){
        return false;
    }
    if(-1 == size){
        struct stat st;
        if(-1 == fstat(fd, &st)){
            S3FS_PRN_ERR("fstat error(%d)", errno);
            return false;
        }
        size = st.st_size;
    }

    sha256ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(sha256ctx, md, nullptr);

    for(off_t total = 0; total < size; total += bytes){
        const off_t len = 512;
        char buf[len];
        bytes = len < (size - total) ? len : (size - total);
        bytes = pread(fd, buf, bytes, start + total);
        if(0 == bytes){
            // end of file
            break;
        }else if(-1 == bytes){
            // error
            S3FS_PRN_ERR("file read error(%d)", errno);
            EVP_MD_CTX_destroy(sha256ctx);
            return false;
        }
        EVP_DigestUpdate(sha256ctx, buf, bytes);
    }
    EVP_DigestFinal_ex(sha256ctx, result->data(), nullptr);
    EVP_MD_CTX_destroy(sha256ctx);

    return true;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
