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
#include <memory>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/err.h>

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
    return true;
}

bool s3fs_destroy_global_ssl()
{
    return true;
}

//-------------------------------------------------------------------
// Utility Function for crypt lock
//-------------------------------------------------------------------
// OpenSSL >= 1.1.0 manages threading internally, no application-level
// locking callbacks are needed.
//
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
static std::unique_ptr<unsigned char[]> s3fs_HMAC_RAW(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned int* digestlen, bool is_sha256)
{
    if(!key || !data || !digestlen){
        return nullptr;
    }
    (*digestlen) = EVP_MAX_MD_SIZE * sizeof(unsigned char);
    auto digest = std::make_unique<unsigned char[]>(*digestlen);
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

//-------------------------------------------------------------------
// Compute a message digest over a memory buffer using the EVP API.
// The algorithm (e.g. EVP_md5(), EVP_sha256()) is selected by the caller.
//-------------------------------------------------------------------
static bool s3fs_digest(const EVP_MD* md, const unsigned char* data, size_t datalen, unsigned char* out)
{
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if(!mdctx){
        S3FS_PRN_ERR("EVP_MD_CTX_new failed: %s", ERR_reason_error_string(ERR_get_error()));
        return false;
    }
    if(EVP_DigestInit_ex(mdctx.get(), md, nullptr) != 1){
        S3FS_PRN_ERR("EVP_DigestInit_ex failed: %s", ERR_reason_error_string(ERR_get_error()));
        return false;
    }
    if(EVP_DigestUpdate(mdctx.get(), data, datalen) != 1){
        S3FS_PRN_ERR("EVP_DigestUpdate failed: %s", ERR_reason_error_string(ERR_get_error()));
        return false;
    }
    if(EVP_DigestFinal_ex(mdctx.get(), out, nullptr) != 1){
        S3FS_PRN_ERR("EVP_DigestFinal_ex failed: %s", ERR_reason_error_string(ERR_get_error()));
        return false;
    }
    return true;
}

//-------------------------------------------------------------------
// Utility Function for MD5
//-------------------------------------------------------------------
bool s3fs_md5(const unsigned char* data, size_t datalen, md5_t* digest)
{
    return s3fs_digest(EVP_md5(), data, datalen, digest->data());
}

#ifdef USE_OPENSSL_30

bool s3fs_md5_fd(int fd, off_t start, off_t size, md5_t* result)
{
    auto           md5_digest_len = static_cast<unsigned int>(result->size());
    off_t          bytes;

    if(-1 == size){
        struct stat st;
        if(-1 == fstat(fd, &st)){
            return false;
        }
        size = st.st_size;
    }

    // instead of MD5_Init
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if(!mdctx){
        S3FS_PRN_ERR("EVP_MD_CTX_new failed\n");
        return false;
    }
    if(EVP_DigestInit_ex(mdctx.get(), EVP_md5(), nullptr) != 1){
        S3FS_PRN_ERR("EVP_DigestInit_ex failed\n");
        return false;
    }

    for(off_t total = 0; total < size; total += bytes){
        std::array<char, 512> buf;
        bytes = std::min(static_cast<off_t>(buf.size()), (size - total));
        bytes = pread(fd, buf.data(), bytes, start + total);
        if(0 == bytes){
            // end of file
            break;
        }else if(-1 == bytes){
            // error
            S3FS_PRN_ERR("file read error(%d)", errno);
            return false;
        }
        // instead of MD5_Update
        if(EVP_DigestUpdate(mdctx.get(), buf.data(), bytes) != 1){
            S3FS_PRN_ERR("Digest computation failed\n");
            return false;
        }
    }

    // instead of MD5_Final
    if(EVP_DigestFinal_ex(mdctx.get(), result->data(), &md5_digest_len) != 1){
        S3FS_PRN_ERR("Digest computation failed\n");
        return false;
    }

    return true;
}

#else

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
        std::array<char, 512> buf;
        bytes = std::min(static_cast<off_t>(buf.size()), (size - total));
        bytes = pread(fd, buf.data(), bytes, start + total);
        if(0 == bytes){
            // end of file
            break;
        }else if(-1 == bytes){
            // error
            S3FS_PRN_ERR("file read error(%d)", errno);
            return false;
        }
        MD5_Update(&md5ctx, buf.data(), bytes);
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
    return s3fs_digest(EVP_sha256(), data, datalen, digest->data());
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
        std::array<char, 512> buf;
        bytes = std::min(static_cast<off_t>(buf.size()), (size - total));
        bytes = pread(fd, buf.data(), bytes, start + total);
        if(0 == bytes){
            // end of file
            break;
        }else if(-1 == bytes){
            // error
            S3FS_PRN_ERR("file read error(%d)", errno);
            EVP_MD_CTX_destroy(sha256ctx);
            return false;
        }
        EVP_DigestUpdate(sha256ctx, buf.data(), bytes);
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
