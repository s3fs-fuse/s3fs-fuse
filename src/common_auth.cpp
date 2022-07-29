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

#include <cstdio>
#include <string>

#include "s3fs_auth.h"
#include "string_util.h"

//-------------------------------------------------------------------
// Utility Function
//-------------------------------------------------------------------
std::string s3fs_get_content_md5(int fd)
{
    unsigned char* md5;
    char* base64;
    std::string Signature;

    if(NULL == (md5 = s3fs_md5_fd(fd, 0, -1))){
        return std::string("");
    }
    if(NULL == (base64 = s3fs_base64(md5, get_md5_digest_length()))){
        delete[] md5;
        return std::string("");  // ENOMEM
    }
    delete[] md5;

    Signature = base64;
    delete[] base64;

    return Signature;
}

std::string s3fs_sha256_hex_fd(int fd, off_t start, off_t size)
{
    size_t digestlen = get_sha256_digest_length();
    unsigned char* sha256;

    if(NULL == (sha256 = s3fs_sha256_fd(fd, start, size))){
        return std::string("");
    }

    std::string sha256hex = s3fs_hex_lower(sha256, digestlen);
    delete[] sha256;

    return sha256hex;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
