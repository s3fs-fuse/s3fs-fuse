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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <nss.h>
#include <pk11pub.h>
#include <hasht.h>
#include <prinit.h>
#include <string>
#include <map>

#include "common.h"
#include "s3fs.h"
#include "s3fs_auth.h"
#include "s3fs_logger.h"

//-------------------------------------------------------------------
// Utility Function for version
//-------------------------------------------------------------------
const char* s3fs_crypt_lib_name()
{
    static const char version[] = "NSS";

    return version;
}

//-------------------------------------------------------------------
// Utility Function for global init
//-------------------------------------------------------------------
bool s3fs_init_global_ssl()
{
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);

    if(SECSuccess != NSS_NoDB_Init(NULL)){
        S3FS_PRN_ERR("Failed NSS_NoDB_Init call.");
        return false;
    }
    return true;
}

bool s3fs_destroy_global_ssl()
{
    NSS_Shutdown();
    PL_ArenaFinish();
    PR_Cleanup();
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
static bool s3fs_HMAC_RAW(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen, bool is_sha256)
{
    if(!key || !data || !digest || !digestlen){
        return false;
    }

    PK11SlotInfo* Slot;
    PK11SymKey*   pKey;
    PK11Context*  Context;
    unsigned char tmpdigest[64];
    SECItem       KeySecItem   = {siBuffer, reinterpret_cast<unsigned char*>(const_cast<void*>(key)), static_cast<unsigned int>(keylen)};
    SECItem       NullSecItem  = {siBuffer, NULL, 0};

    if(NULL == (Slot = PK11_GetInternalKeySlot())){
        return false;
    }
    if(NULL == (pKey = PK11_ImportSymKey(Slot, (is_sha256 ? CKM_SHA256_HMAC : CKM_SHA_1_HMAC), PK11_OriginUnwrap, CKA_SIGN, &KeySecItem, NULL))){
        PK11_FreeSlot(Slot);
        return false;
    }
    if(NULL == (Context = PK11_CreateContextBySymKey((is_sha256 ? CKM_SHA256_HMAC : CKM_SHA_1_HMAC), CKA_SIGN, pKey, &NullSecItem))){
        PK11_FreeSymKey(pKey);
        PK11_FreeSlot(Slot);
        return false;
    }

    *digestlen = 0;
    if(SECSuccess != PK11_DigestBegin(Context) ||
       SECSuccess != PK11_DigestOp(Context, data, datalen) ||
       SECSuccess != PK11_DigestFinal(Context, tmpdigest, digestlen, sizeof(tmpdigest)) )
    {
        PK11_DestroyContext(Context, PR_TRUE);
        PK11_FreeSymKey(pKey);
        PK11_FreeSlot(Slot);
        return false;
    }
    PK11_DestroyContext(Context, PR_TRUE);
    PK11_FreeSymKey(pKey);
    PK11_FreeSlot(Slot);

    *digest = new unsigned char[*digestlen];
    memcpy(*digest, tmpdigest, *digestlen);

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
size_t get_md5_digest_length()
{
    return MD5_LENGTH;
}

unsigned char* s3fs_md5_fd(int fd, off_t start, off_t size)
{
    PK11Context*   md5ctx;
    off_t          bytes;
    unsigned char* result;
    unsigned int   md5outlen;

    if(-1 == size){
        struct stat st;
        if(-1 == fstat(fd, &st)){
            return NULL;
        }
        size = st.st_size;
    }

    md5ctx = PK11_CreateDigestContext(SEC_OID_MD5);

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
            PK11_DestroyContext(md5ctx, PR_TRUE);
            return NULL;
        }
        PK11_DigestOp(md5ctx, buf, bytes);
    }
    result = new unsigned char[get_md5_digest_length()];
    PK11_DigestFinal(md5ctx, result, &md5outlen, get_md5_digest_length());
    PK11_DestroyContext(md5ctx, PR_TRUE);

    return result;
}

//-------------------------------------------------------------------
// Utility Function for SHA256
//-------------------------------------------------------------------
size_t get_sha256_digest_length()
{
    return SHA256_LENGTH;
}

bool s3fs_sha256(const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen)
{
    (*digestlen) = static_cast<unsigned int>(get_sha256_digest_length());
    *digest      = new unsigned char[*digestlen];

    PK11Context*   sha256ctx;
    unsigned int   sha256outlen;
    sha256ctx = PK11_CreateDigestContext(SEC_OID_SHA256);

    PK11_DigestOp(sha256ctx, data, datalen);
    PK11_DigestFinal(sha256ctx, *digest, &sha256outlen, *digestlen);
    PK11_DestroyContext(sha256ctx, PR_TRUE);
    *digestlen = sha256outlen;

    return true;
}

unsigned char* s3fs_sha256_fd(int fd, off_t start, off_t size)
{
    PK11Context*   sha256ctx;
    off_t          bytes;
    unsigned char* result;
    unsigned int   sha256outlen;

    if(-1 == size){
        struct stat st;
        if(-1 == fstat(fd, &st)){
            return NULL;
        }
        size = st.st_size;
    }

    sha256ctx = PK11_CreateDigestContext(SEC_OID_SHA256);

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
            PK11_DestroyContext(sha256ctx, PR_TRUE);
            return NULL;
        }
        PK11_DigestOp(sha256ctx, buf, bytes);
    }
    result = new unsigned char[get_sha256_digest_length()];
    PK11_DigestFinal(sha256ctx, result, &sha256outlen, get_sha256_digest_length());
    PK11_DestroyContext(sha256ctx, PR_TRUE);

    return result;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
