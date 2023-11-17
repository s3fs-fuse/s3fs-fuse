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

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <gcrypt.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#ifdef USE_GNUTLS_NETTLE
#include <nettle/md5.h>
#include <nettle/sha1.h>
#include <nettle/hmac.h>
#endif
#include <string>
#include <map>

#include "common.h"
#include "s3fs.h"
#include "s3fs_auth.h"
#include "s3fs_logger.h"

//-------------------------------------------------------------------
// Utility Function for version
//-------------------------------------------------------------------
#ifdef USE_GNUTLS_NETTLE

const char* s3fs_crypt_lib_name(void)
{
    static constexpr char version[] = "GnuTLS(nettle)";

    return version;
}

#else // USE_GNUTLS_NETTLE

const char* s3fs_crypt_lib_name()
{
    static constexpr char version[] = "GnuTLS(gcrypt)";

    return version;
}

#endif // USE_GNUTLS_NETTLE

//-------------------------------------------------------------------
// Utility Function for global init
//-------------------------------------------------------------------
bool s3fs_init_global_ssl()
{
    if(GNUTLS_E_SUCCESS != gnutls_global_init()){
        return false;
    }
#ifndef USE_GNUTLS_NETTLE
    if(nullptr == gcry_check_version(nullptr)){
        return false;
    }
#endif // USE_GNUTLS_NETTLE
    return true;
}

bool s3fs_destroy_global_ssl()
{
    gnutls_global_deinit();
    return true;
}

//-------------------------------------------------------------------
// Utility Function for crypt lock
//-------------------------------------------------------------------
bool s3fs_init_crypt_mutex()
{
    return true;
}

bool s3fs_destroy_crypt_mutex()
{
    return true;
}

//-------------------------------------------------------------------
// Utility Function for HMAC
//-------------------------------------------------------------------
#ifdef USE_GNUTLS_NETTLE

std::unique_ptr<unsigned char[]> s3fs_HMAC(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned int* digestlen)
{
    if(!key || !data || !digestlen){
        return nullptr;
    }

    std::unique_ptr<unsigned char[]> digest(new unsigned char[SHA1_DIGEST_SIZE]);

    struct hmac_sha1_ctx ctx_hmac;
    hmac_sha1_set_key(&ctx_hmac, keylen, reinterpret_cast<const uint8_t*>(key));
    hmac_sha1_update(&ctx_hmac, datalen, reinterpret_cast<const uint8_t*>(data));
    hmac_sha1_digest(&ctx_hmac, SHA1_DIGEST_SIZE, reinterpret_cast<uint8_t*>(digest.get()));
    *digestlen = SHA1_DIGEST_SIZE;

    return digest;
}

std::unique_ptr<unsigned char[]> s3fs_HMAC256(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned int* digestlen)
{
    if(!key || !data || !digestlen){
        return nullptr;
    }

    std::unique_ptr<unsigned char[]> digest(new unsigned char[SHA256_DIGEST_SIZE]);

    struct hmac_sha256_ctx ctx_hmac;
    hmac_sha256_set_key(&ctx_hmac, keylen, reinterpret_cast<const uint8_t*>(key));
    hmac_sha256_update(&ctx_hmac, datalen, reinterpret_cast<const uint8_t*>(data));
    hmac_sha256_digest(&ctx_hmac, SHA256_DIGEST_SIZE, reinterpret_cast<uint8_t*>(digest.get()));
    *digestlen = SHA256_DIGEST_SIZE;

    return digest;
}

#else // USE_GNUTLS_NETTLE

std::unique_ptr<unsigned char[]> s3fs_HMAC(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned int* digestlen)
{
    if(!key || !data || !digestlen){
        return nullptr;
    }

    if(0 == (*digestlen = gnutls_hmac_get_len(GNUTLS_MAC_SHA1))){
        return nullptr;
    }
    std::unique_ptr<unsigned char[]> digest(new unsigned char[*digestlen + 1]);
    if(0 > gnutls_hmac_fast(GNUTLS_MAC_SHA1, key, keylen, data, datalen, digest.get())){
        return nullptr;
    }
    return digest;
}

std::unique_ptr<unsigned char[]> s3fs_HMAC256(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned int* digestlen)
{
    if(!key || !data || !digestlen){
        return nullptr;
    }

    if(0 == (*digestlen = gnutls_hmac_get_len(GNUTLS_MAC_SHA256))){
        return nullptr;
    }
    std::unique_ptr<unsigned char[]> digest(new unsigned char[*digestlen + 1]);
    if(0 > gnutls_hmac_fast(GNUTLS_MAC_SHA256, key, keylen, data, datalen, digest.get())){
        return nullptr;
    }
    return digest;
}

#endif // USE_GNUTLS_NETTLE

//-------------------------------------------------------------------
// Utility Function for MD5
//-------------------------------------------------------------------
#ifdef USE_GNUTLS_NETTLE
bool s3fs_md5(const unsigned char* data, size_t datalen, md5_t* result)
{
    struct md5_ctx ctx_md5;
    md5_init(&ctx_md5);
    md5_update(&ctx_md5, datalen, data);
    md5_digest(&ctx_md5, result->size(), result->data());

    return true;
}

bool s3fs_md5_fd(int fd, off_t start, off_t size, md5_t* result)
{
    struct md5_ctx ctx_md5;
    off_t          bytes;

    if(-1 == size){
        struct stat st;
        if(-1 == fstat(fd, &st)){
            return false;
        }
        size = st.st_size;
    }

    md5_init(&ctx_md5);

    for(off_t total = 0; total < size; total += bytes){
        off_t len = 512;
        unsigned char buf[len];
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
        md5_update(&ctx_md5, bytes, buf);
    }
    md5_digest(&ctx_md5, result->size(), result->data());

    return true;
}

#else // USE_GNUTLS_NETTLE

bool s3fs_md5(const unsigned char* data, size_t datalen, md5_t* digest)
{
    gcry_md_hd_t   ctx_md5;
    gcry_error_t   err;
    if(GPG_ERR_NO_ERROR != (err = gcry_md_open(&ctx_md5, GCRY_MD_MD5, 0))){
        S3FS_PRN_ERR("MD5 context creation failure: %s/%s", gcry_strsource(err), gcry_strerror(err));
        return false;
    }
    gcry_md_write(ctx_md5, digest->data(), digest->size());
    gcry_md_close(ctx_md5);

    return true;
}

bool s3fs_md5_fd(int fd, off_t start, off_t size, md5_t* result)
{
    gcry_md_hd_t ctx_md5;
    gcry_error_t err;
    off_t bytes;

    if(-1 == size){
        struct stat st;
        if(-1 == fstat(fd, &st)){
            return false;
        }
        size = st.st_size;
    }

    if(GPG_ERR_NO_ERROR != (err = gcry_md_open(&ctx_md5, GCRY_MD_MD5, 0))){
        S3FS_PRN_ERR("MD5 context creation failure: %s/%s", gcry_strsource(err), gcry_strerror(err));
        return false;
    }

    for(off_t total = 0; total < size; total += bytes){
        off_t len = 512;
        char buf[len];
        bytes = len < (size - total) ? len : (size - total);
        bytes = pread(fd, buf, bytes, start + total);
        if(0 == bytes){
            // end of file
            break;
        }else if(-1 == bytes){
            // error
            S3FS_PRN_ERR("file read error(%d)", errno);
            gcry_md_close(ctx_md5);
            return false;
        }
        gcry_md_write(ctx_md5, buf, bytes);
    }
    memcpy(result->data(), gcry_md_read(ctx_md5, 0), result->size());
    gcry_md_close(ctx_md5);

    return true;
}

#endif // USE_GNUTLS_NETTLE

//-------------------------------------------------------------------
// Utility Function for SHA256
//-------------------------------------------------------------------
#ifdef USE_GNUTLS_NETTLE
bool s3fs_sha256(const unsigned char* data, size_t datalen, sha256_t* digest)
{
    struct sha256_ctx ctx_sha256;
    sha256_init(&ctx_sha256);
    sha256_update(&ctx_sha256, datalen, data);
    sha256_digest(&ctx_sha256, digest->size(), digest->data());

    return true;
}

bool s3fs_sha256_fd(int fd, off_t start, off_t size, sha256_t* result)
{
    struct sha256_ctx ctx_sha256;
    off_t             bytes;

    sha256_init(&ctx_sha256);

    for(off_t total = 0; total < size; total += bytes){
        off_t len = 512;
        unsigned char buf[len];
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
        sha256_update(&ctx_sha256, bytes, buf);
    }
    sha256_digest(&ctx_sha256, result->size(), result->data());

    return true;
}

#else // USE_GNUTLS_NETTLE

bool s3fs_sha256(const unsigned char* data, size_t datalen, sha256_t* digest)
{
    gcry_md_hd_t   ctx_sha256;
    gcry_error_t   err;
    if(GPG_ERR_NO_ERROR != (err = gcry_md_open(&ctx_sha256, GCRY_MD_SHA256, 0))){
        S3FS_PRN_ERR("SHA256 context creation failure: %s/%s", gcry_strsource(err), gcry_strerror(err));
        return false;
    }
    gcry_md_write(ctx_sha256, data, datalen);
    memcpy(digest->data(), gcry_md_read(ctx_sha256, 0), digest->size());
    gcry_md_close(ctx_sha256);

    return true;
}

bool s3fs_sha256_fd(int fd, off_t start, off_t size, sha256_t* result)
{
    gcry_md_hd_t   ctx_sha256;
    gcry_error_t   err;
    off_t          bytes;

    if(-1 == size){
        struct stat st;
        if(-1 == fstat(fd, &st)){
            return false;
        }
        size = st.st_size;
    }

    if(GPG_ERR_NO_ERROR != (err = gcry_md_open(&ctx_sha256, GCRY_MD_SHA256, 0))){
        S3FS_PRN_ERR("SHA256 context creation failure: %s/%s", gcry_strsource(err), gcry_strerror(err));
        return false;
    }

    for(off_t total = 0; total < size; total += bytes){
        off_t len = 512;
        char buf[len];
        bytes = len < (size - total) ? len : (size - total);
        bytes = pread(fd, buf, bytes, start + total);
        if(0 == bytes){
            // end of file
            break;
        }else if(-1 == bytes){
            // error
            S3FS_PRN_ERR("file read error(%d)", errno);
            gcry_md_close(ctx_sha256);
            return false;
        }
        gcry_md_write(ctx_sha256, buf, bytes);
    }
    memcpy(result->data(), gcry_md_read(ctx_sha256, 0), result->size());
    gcry_md_close(ctx_sha256);

    return true;
}

#endif // USE_GNUTLS_NETTLE

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
