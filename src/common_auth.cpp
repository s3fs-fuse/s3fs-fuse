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
#include <string.h>
#include <string>

#include "s3fs_auth.h"

using namespace std;

//-------------------------------------------------------------------
// Utility Function
//-------------------------------------------------------------------
char* s3fs_base64(unsigned char* input, size_t length)
{
  static const char* base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  char* result;

  if(!input || 0 >= length){
    return NULL;
  }
  if(NULL == (result = (char*)malloc((((length / 3) + 1) * 4 + 1) * sizeof(char)))){
    return NULL; // ENOMEM
  }

  unsigned char parts[4];
  size_t rpos;
  size_t wpos;
  for(rpos = 0, wpos = 0; rpos < length; rpos += 3){
    parts[0] = (input[rpos] & 0xfc) >> 2;
    parts[1] = ((input[rpos] & 0x03) << 4) | ((((rpos + 1) < length ? input[rpos + 1] : 0x00) & 0xf0) >> 4);
    parts[2] = (rpos + 1) < length ? (((input[rpos + 1] & 0x0f) << 2) | ((((rpos + 2) < length ? input[rpos + 2] : 0x00) & 0xc0) >> 6)) : 0x40;
    parts[3] = (rpos + 2) < length ? (input[rpos + 2] & 0x3f) : 0x40;

    result[wpos++] = base[parts[0]];
    result[wpos++] = base[parts[1]];
    result[wpos++] = base[parts[2]];
    result[wpos++] = base[parts[3]];
  }
  result[wpos] = '\0';

  return result;
}

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
  char md5[2 * digestlen + 1];
  char hexbuf[3];
  unsigned char* md5hex;

  if(NULL == (md5hex = s3fs_md5hexsum(fd, start, size))){
    return string("");
  }

  memset(md5, 0, 2 * digestlen + 1);
  for(size_t pos = 0; pos < digestlen; pos++){
    snprintf(hexbuf, 3, "%02x", md5hex[pos]);
    strncat(md5, hexbuf, 2);
  }
  free(md5hex);

  return string(md5);
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
/// END
