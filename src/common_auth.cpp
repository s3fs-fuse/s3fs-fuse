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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

#include "s3fs_auth.h"
#include "string_util.h"

using namespace std;

//-------------------------------------------------------------------
// Utility Function
//-------------------------------------------------------------------
string s3fs_get_content_md5(int fd)
{
  unsigned char* md5hex;
  char* base64;
  string Signature;

  if(NULL == (md5hex = s3fs_md5hexsum(fd, 0, -1))){
    return string("");
  }
  if(NULL == (base64 = s3fs_base64(md5hex, get_md5_digest_length()))){
    return string("");  // ENOMEM
  }
  free(md5hex);

  Signature = base64;
  free(base64);

  return Signature;
}

string s3fs_md5sum(int fd, off_t start, ssize_t size)
{
  size_t digestlen = get_md5_digest_length();
  unsigned char* md5hex;

  if(NULL == (md5hex = s3fs_md5hexsum(fd, start, size))){
    return string("");
  }

  std::string md5 = s3fs_hex(md5hex, digestlen);
  free(md5hex);

  return md5;
}

string s3fs_sha256sum(int fd, off_t start, ssize_t size)
{
  size_t digestlen = get_sha256_digest_length();
  char sha256[2 * digestlen + 1];
  char hexbuf[3];
  unsigned char* sha256hex;

  if(NULL == (sha256hex = s3fs_sha256hexsum(fd, start, size))){
    return string("");
  }

  memset(sha256, 0, 2 * digestlen + 1);
  for(size_t pos = 0; pos < digestlen; pos++){
    snprintf(hexbuf, 3, "%02x", sha256hex[pos]);
    strncat(sha256, hexbuf, 2);
  }
  free(sha256hex);

  return string(sha256);
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
