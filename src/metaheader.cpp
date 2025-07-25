/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2007 Takeshi Nakatani <ggtakec.com>
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

#include <ctime>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "metaheader.h"
#include "string_util.h"
#include "s3fs_util.h"

static constexpr struct timespec DEFAULT_TIMESPEC = {-1, 0};

//-------------------------------------------------------------------
// Utility functions for convert
//-------------------------------------------------------------------
static struct timespec cvt_string_to_time(const char *str)
{
    // [NOTE]
    // In rclone, there are cases where ns is set to x-amz-meta-mtime
    // with floating point number. s3fs uses x-amz-meta-mtime by
    // truncating the floating point or less (in seconds or less) to
    // correspond to this.
    //
    std::string strmtime;
    long nsec = 0;
    if(str && '\0' != *str){
        strmtime = str;
        std::string::size_type pos = strmtime.find('.', 0);
        if(std::string::npos != pos){
            nsec = cvt_strtoofft(strmtime.substr(pos + 1).c_str(), /*base=*/ 10);
            strmtime.erase(pos);
        }
    }
    struct timespec ts = {static_cast<time_t>(cvt_strtoofft(strmtime.c_str(), /*base=*/ 10)), nsec};
    return ts;
}

static struct timespec get_time(const headers_t& meta, const char *header)
{
    headers_t::const_iterator iter;
    if(meta.cend() == (iter = meta.find(header))){
        return DEFAULT_TIMESPEC;
    }
    return cvt_string_to_time((*iter).second.c_str());
}

struct timespec get_mtime(const headers_t& meta, bool overcheck)
{
    struct timespec t = get_time(meta, "x-amz-meta-mtime");
    if(0 < t.tv_sec){
        return t;
    }
    t = get_time(meta, "x-amz-meta-goog-reserved-file-mtime");
    if(0 < t.tv_sec){
        return t;
    }
    if(overcheck){
        struct timespec ts = {get_lastmodified(meta), 0};
        return ts;
    }
    return DEFAULT_TIMESPEC;
}

struct timespec get_ctime(const headers_t& meta, bool overcheck)
{
    struct timespec t = get_time(meta, "x-amz-meta-ctime");
    if(0 < t.tv_sec){
        return t;
    }
    if(overcheck){
        struct timespec ts = {get_lastmodified(meta), 0};
        return ts;
    }
    return DEFAULT_TIMESPEC;
}

struct timespec get_atime(const headers_t& meta, bool overcheck)
{
    struct timespec t = get_time(meta, "x-amz-meta-atime");
    if(0 < t.tv_sec){
        return t;
    }
    if(overcheck){
        struct timespec ts = {get_lastmodified(meta), 0};
        return ts;
    }
    return DEFAULT_TIMESPEC;
}

off_t get_size(const char *s)
{
    return cvt_strtoofft(s, /*base=*/ 10);
}

off_t get_size(const headers_t& meta)
{
    auto iter = meta.find("Content-Length");
    if(meta.cend() == iter){
        return 0;
    }
    return get_size((*iter).second.c_str());
}

mode_t get_mode(const char *s, int base)
{
    return static_cast<mode_t>(cvt_strtoofft(s, base));
}

mode_t get_mode(const headers_t& meta, const std::string& strpath, bool checkdir, bool forcedir)
{
    mode_t mode     = 0;
    bool   isS3sync = false;
    headers_t::const_iterator iter;

    if(meta.cend() != (iter = meta.find("x-amz-meta-mode"))){
        mode = get_mode((*iter).second.c_str());
    }else if(meta.cend() != (iter = meta.find("x-amz-meta-permissions"))){ // for s3sync
        mode = get_mode((*iter).second.c_str());
        isS3sync = true;
    }else if(meta.cend() != (iter = meta.find("x-amz-meta-goog-reserved-posix-mode"))){ // for GCS
        mode = get_mode((*iter).second.c_str(), 8);
    }else{
        // If another tool creates an object without permissions, default to owner
        // read-write and group readable.
        mode = (!strpath.empty() && '/' == *strpath.rbegin()) ? 0750 : 0640;
    }

    // Checking the bitmask, if the last 3 bits are all zero then process as a regular
    // file type (S_IFDIR or S_IFREG), otherwise return mode unmodified so that S_IFIFO,
    // S_IFSOCK, S_IFCHR, S_IFLNK and S_IFBLK devices can be processed properly by fuse.
    if(!(mode & S_IFMT)){
        if(!isS3sync){
            if(checkdir){
                if(forcedir){
                    mode |= S_IFDIR;
                }else{
                    if(meta.cend() != (iter = meta.find("Content-Type"))){
                        std::string strConType = (*iter).second;
                        // Leave just the mime type, remove any optional parameters (eg charset)
                        std::string::size_type pos = strConType.find(';');
                        if(std::string::npos != pos){
                            strConType.erase(pos);
                        }
                        if(strConType == "application/x-directory" || strConType == "httpd/unix-directory"){
                            // Nextcloud uses this MIME type for directory objects when mounting bucket as external Storage
                            mode |= S_IFDIR;
                        }else if(!strpath.empty() && '/' == *strpath.rbegin()){
                            if(strConType == "binary/octet-stream" || strConType == "application/octet-stream"){
                                mode |= S_IFDIR;
                            }else{
                                if(complement_stat){
                                    // If complement lack stat mode, when the object has '/' character at end of name
                                    // and content type is text/plain and the object's size is 0 or 1, it should be
                                    // directory.
                                    off_t size = get_size(meta);
                                    if(strConType == "text/plain" && (0 == size || 1 == size)){
                                        mode |= S_IFDIR;
                                    }else{
                                        mode |= S_IFREG;
                                    }
                                }else{
                                    mode |= S_IFREG;
                                }
                            }
                        }else{
                            mode |= S_IFREG;
                        }
                    }else{
                      mode |= S_IFREG;
                    }
                }
            }
            // If complement lack stat mode, when it's mode is not set any permission,
            // the object is added minimal mode only for read permission.
            if(complement_stat && 0 == (mode & (S_IRWXU | S_IRWXG | S_IRWXO))){
                mode |= (S_IRUSR | (0 == (mode & S_IFDIR) ? 0 : S_IXUSR));
            }
        }else{
            if(!checkdir){
                // cut dir/reg flag.
                mode &= ~S_IFDIR;
                mode &= ~S_IFREG;
            }
        }
    }
    return mode;
}

// [NOTE]
// Gets a only FMT bit in mode from meta headers.
// The processing is almost the same as get_mode().
// This function is intended to be used from get_object_attribute().
//
static mode_t convert_meta_to_mode_fmt(const headers_t& meta)
{
    mode_t mode = 0;
    bool   isS3sync = false;
    headers_t::const_iterator iter;

    if(meta.cend() != (iter = meta.find("x-amz-meta-mode"))){
        mode = get_mode((*iter).second.c_str());
    }else if(meta.cend() != (iter = meta.find("x-amz-meta-permissions"))){ // for s3sync
        mode = get_mode((*iter).second.c_str());
        isS3sync = true;
    }else if(meta.cend() != (iter = meta.find("x-amz-meta-goog-reserved-posix-mode"))){ // for GCS
        mode = get_mode((*iter).second.c_str(), 8);
    }

    if(!(mode & S_IFMT)){
        if(!isS3sync){
            if(meta.cend() != (iter = meta.find("Content-Type"))){
                std::string strConType = (*iter).second;
                // Leave just the mime type, remove any optional parameters (eg charset)
                std::string::size_type pos = strConType.find(';');
                if(std::string::npos != pos){
                    strConType.erase(pos);
                }
                if(strConType == "application/x-directory" || strConType == "httpd/unix-directory"){
                    // Nextcloud uses this MIME type for directory objects when mounting bucket as external Storage
                    mode |= S_IFDIR;
                }
            }
        }
    }
    return (mode & S_IFMT);
}

bool is_reg_fmt(const headers_t& meta)
{
    return S_ISREG(convert_meta_to_mode_fmt(meta));
}

bool is_symlink_fmt(const headers_t& meta)
{
    return S_ISLNK(convert_meta_to_mode_fmt(meta));
}

bool is_dir_fmt(const headers_t& meta)
{
    return S_ISDIR(convert_meta_to_mode_fmt(meta));
}

uid_t get_uid(const char *s)
{
    return static_cast<uid_t>(cvt_strtoofft(s, /*base=*/ 0));
}

uid_t get_uid(const headers_t& meta)
{
    headers_t::const_iterator iter;
    if(meta.cend() != (iter = meta.find("x-amz-meta-uid"))){
        return get_uid((*iter).second.c_str());
    }else if(meta.cend() != (iter = meta.find("x-amz-meta-owner"))){ // for s3sync
        return get_uid((*iter).second.c_str());
    }else if(meta.cend() != (iter = meta.find("x-amz-meta-goog-reserved-posix-uid"))){ // for GCS
        return get_uid((*iter).second.c_str());
    }else{
        return geteuid();
    }
}

gid_t get_gid(const char *s)
{
    return static_cast<gid_t>(cvt_strtoofft(s, /*base=*/ 0));
}

gid_t get_gid(const headers_t& meta)
{
    headers_t::const_iterator iter;
    if(meta.cend() != (iter = meta.find("x-amz-meta-gid"))){
        return get_gid((*iter).second.c_str());
    }else if(meta.cend() != (iter = meta.find("x-amz-meta-group"))){ // for s3sync
        return get_gid((*iter).second.c_str());
    }else if(meta.cend() != (iter = meta.find("x-amz-meta-goog-reserved-posix-gid"))){ // for GCS
        return get_gid((*iter).second.c_str());
    }else{
        return getegid();
    }
}

blkcnt_t get_blocks(off_t size)
{
    return (size / 512) + (0 == (size % 512) ? 0 : 1);
}

time_t cvtIAMExpireStringToTime(const char* s)
{
    struct tm tm{};
    if(!s){
        return 0L;
    }
    s3fs_strptime(s, "%Y-%m-%dT%H:%M:%S", &tm);
    return timegm(&tm); // GMT
}

time_t get_lastmodified(const char* s)
{
    struct tm tm{};
    if(!s){
        return -1;
    }
    s3fs_strptime(s, "%a, %d %b %Y %H:%M:%S %Z", &tm);
    return timegm(&tm); // GMT
}

time_t get_lastmodified(const headers_t& meta)
{
    auto iter = meta.find("Last-Modified");
    if(meta.cend() == iter){
        return -1;
    }
    return get_lastmodified((*iter).second.c_str());
}

//
// Returns it whether it is an object with need checking in detail.
// If this function returns true, the object is possible to be directory
// and is needed checking detail(searching sub object).
//
bool is_need_check_obj_detail(const headers_t& meta)
{
    headers_t::const_iterator iter;

    // directory object is Content-Length as 0.
    if(0 != get_size(meta)){
        return false;
    }
    // if the object has x-amz-meta information, checking is no more.
    if(meta.cend() != meta.find("x-amz-meta-mode")  ||
       meta.cend() != meta.find("x-amz-meta-mtime") ||
       meta.cend() != meta.find("x-amz-meta-ctime") ||
       meta.cend() != meta.find("x-amz-meta-atime") ||
       meta.cend() != meta.find("x-amz-meta-uid")   ||
       meta.cend() != meta.find("x-amz-meta-gid")   ||
       meta.cend() != meta.find("x-amz-meta-owner") ||
       meta.cend() != meta.find("x-amz-meta-group") ||
       meta.cend() != meta.find("x-amz-meta-permissions") )
    {
        return false;
    }
    // if there is not Content-Type, or Content-Type is "x-directory",
    // checking is no more.
    if(meta.cend() == (iter = meta.find("Content-Type"))){
        return false;
    }
    if("application/x-directory" == (*iter).second){
        return false;
    }
    return true;
}

// [NOTE]
// If add_noexist is false and the key does not exist, it will not be added.
//
bool merge_headers(headers_t& base, const headers_t& additional, bool add_noexist)
{
    bool added = false;
    for(auto iter = additional.cbegin(); iter != additional.cend(); ++iter){
        if(add_noexist || base.find(iter->first) != base.cend()){
            base[iter->first] = iter->second;
            added             = true;
        }
    }
    return added;
}

bool convert_header_to_stat(const std::string& strpath, const headers_t& meta, struct stat& stbuf, bool forcedir)
{
    stbuf = {};

    // set hard link count always 1
    stbuf.st_nlink = 1; // see fuse FAQ

    // mode
    stbuf.st_mode = get_mode(meta, strpath, true, forcedir);

    // blocks
    if(S_ISREG(stbuf.st_mode)){
        stbuf.st_blocks = get_blocks(stbuf.st_size);
    }
    stbuf.st_blksize = 4096;

    // mtime
    struct timespec mtime = get_mtime(meta);
    if(stbuf.st_mtime < 0){
        stbuf.st_mtime = 0L;
    }else{
        if(mtime.tv_sec < 0){
            mtime.tv_sec  = 0;
            mtime.tv_nsec = 0;
        }
        set_timespec_to_stat(stbuf, stat_time_type::MTIME, mtime);
    }

    // ctime
    struct timespec ctime = get_ctime(meta);
    if(stbuf.st_ctime < 0){
        stbuf.st_ctime = 0L;
    }else{
        if(ctime.tv_sec < 0){
            ctime.tv_sec  = 0;
            ctime.tv_nsec = 0;
        }
        set_timespec_to_stat(stbuf, stat_time_type::CTIME, ctime);
    }

    // atime
    struct timespec atime = get_atime(meta);
    if(stbuf.st_atime < 0){
        stbuf.st_atime = 0L;
    }else{
        if(atime.tv_sec < 0){
            atime.tv_sec  = 0;
            atime.tv_nsec = 0;
        }
        set_timespec_to_stat(stbuf, stat_time_type::ATIME, atime);
    }

    // size
    if(S_ISDIR(stbuf.st_mode)){
        stbuf.st_size = 4096;
    }else{
        stbuf.st_size = get_size(meta);
    }

    // uid/gid
    stbuf.st_uid = get_uid(meta);
    stbuf.st_gid = get_gid(meta);

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
