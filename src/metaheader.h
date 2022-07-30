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

#ifndef S3FS_METAHEADER_H_
#define S3FS_METAHEADER_H_

#include <string>
#include <strings.h>
#include <map>

//-------------------------------------------------------------------
// headers_t
//-------------------------------------------------------------------
struct header_nocase_cmp
{
    bool operator()(const std::string &strleft, const std::string &strright) const
    {
        return (strcasecmp(strleft.c_str(), strright.c_str()) < 0);
    }
};
typedef std::map<std::string, std::string, header_nocase_cmp> headers_t;

//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
struct timespec get_mtime(const headers_t& meta, bool overcheck = true);
struct timespec get_ctime(const headers_t& meta, bool overcheck = true);
struct timespec get_atime(const headers_t& meta, bool overcheck = true);
off_t get_size(const char *s);
off_t get_size(const headers_t& meta);
mode_t get_mode(const char *s, int base = 0);
mode_t get_mode(const headers_t& meta, const char* path = NULL, bool checkdir = false, bool forcedir = false);
uid_t get_uid(const char *s);
uid_t get_uid(const headers_t& meta);
gid_t get_gid(const char *s);
gid_t get_gid(const headers_t& meta);
blkcnt_t get_blocks(off_t size);
time_t cvtIAMExpireStringToTime(const char* s);
time_t get_lastmodified(const char* s);
time_t get_lastmodified(const headers_t& meta);
bool is_need_check_obj_detail(const headers_t& meta);
bool merge_headers(headers_t& base, const headers_t& additional, bool add_noexist);
bool simple_parse_xml(const char* data, size_t len, const char* key, std::string& value);

#endif // S3FS_METAHEADER_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
