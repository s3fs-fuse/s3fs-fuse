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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <cerrno>
#include <climits>  // NOLINT(misc-include-cleaner)
#include <grp.h>
#include <memory>
#include <mutex>
#include <pwd.h>
#include <libgen.h>
#include <dirent.h>
#include <sys/stat.h>

#include <string>
#include <sstream>

#include "s3fs_logger.h"
#include "s3fs_util.h"
#include "string_util.h"
#include "s3fs_help.h"
#include "curl.h"

using namespace std::string_literals;

//-------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------
std::string mount_prefix;

static size_t max_password_size;
static size_t max_group_name_length;

//-------------------------------------------------------------------
// Utilities
//-------------------------------------------------------------------
std::string get_realpath(const char *path)
{
    std::string realpath = mount_prefix;
    realpath += path;

    return realpath;
}

void init_sysconf_vars()
{
    // SUSv4tc1 says the following about _SC_GETGR_R_SIZE_MAX and
    // _SC_GETPW_R_SIZE_MAX:
    // Note that sysconf(_SC_GETGR_R_SIZE_MAX) may return -1 if
    // there is no hard limit on the size of the buffer needed to
    // store all the groups returned.

    errno = 0;
    long res = sysconf(_SC_GETPW_R_SIZE_MAX);
    if(0 > res){
        if (errno != 0){
            S3FS_PRN_ERR("could not get max password length.");
            abort();
        }
        res = 1024; // default initial length
    }
    max_password_size = res;

    errno = 0;
    res = sysconf(_SC_GETGR_R_SIZE_MAX);
    if(0 > res) {
        if (errno != 0) {
            S3FS_PRN_ERR("could not get max group name length.");
            abort();
        }
        res = 1024; // default initial length
    }
    max_group_name_length = res;
}

//-------------------------------------------------------------------
// Utility for UID/GID
//-------------------------------------------------------------------
// get user name from uid
std::string get_username(uid_t uid)
{
    size_t maxlen = max_password_size;
    int result;
    struct passwd pwinfo;
    struct passwd* ppwinfo = nullptr;

    // make buffer
    auto pbuf = std::make_unique<char[]>(maxlen);
    // get pw information
    while(ERANGE == (result = getpwuid_r(uid, &pwinfo, pbuf.get(), maxlen, &ppwinfo))){
        maxlen *= 2;
        pbuf = std::make_unique<char[]>(maxlen);
    }

    if(0 != result){
        S3FS_PRN_ERR("could not get pw information(%d).", result);
        return "";
    }

    // check pw
    if(nullptr == ppwinfo){
        return "";
    }
    std::string name = SAFESTRPTR(ppwinfo->pw_name);
    return name;
}

int is_uid_include_group(uid_t uid, gid_t gid)
{
    size_t maxlen = max_group_name_length;
    int result;
    struct group ginfo;
    struct group* pginfo = nullptr;

    // make buffer
    auto pbuf = std::make_unique<char[]>(maxlen);
    // get group information
    while(ERANGE == (result = getgrgid_r(gid, &ginfo, pbuf.get(), maxlen, &pginfo))){
        maxlen *= 2;
        pbuf = std::make_unique<char[]>(maxlen);
    }

    if(0 != result){
        S3FS_PRN_ERR("could not get group information(%d).", result);
        return -result;
    }

    // check group
    if(nullptr == pginfo){
        // there is not gid in group.
        return -EINVAL;
    }

    std::string username = get_username(uid);

    char** ppgr_mem;
    for(ppgr_mem = pginfo->gr_mem; ppgr_mem && *ppgr_mem; ppgr_mem++){
        if(username == *ppgr_mem){
            // Found username in group.
            return 1;
        }
    }
    return 0;
}

//-------------------------------------------------------------------
// Utility for file and directory
//-------------------------------------------------------------------
// [NOTE]
// basename/dirname returns a static variable pointer as the return value.
// Normally this shouldn't be a problem, but in macos10 we found a case
// where dirname didn't receive its return value correctly due to thread
// conflicts.
// To avoid this, exclusive control is performed by mutex.
//
static std::mutex basename_lock;

// safe variant of dirname
// dirname clobbers path so let it operate on a tmp copy
std::string mydirname(std::string path)
{
    const std::lock_guard<std::mutex> lock(basename_lock);

    if(path.empty()){
        return "";
    }

    path.push_back('\0');     // terminate with a null character and allocate space for it.
    return dirname(path.data());
}

// safe variant of basename
// basename clobbers path so let it operate on a tmp copy
std::string mybasename(std::string path)
{
    const std::lock_guard<std::mutex> data_lock(basename_lock);

    if(path.empty()){
        return "";
    }

    path.push_back('\0');      // terminate with a null character and allocate space for it.
    return basename(path.data());
}

// mkdir --parents
int mkdirp(const std::string& path, mode_t mode)
{
    std::string        base;
    std::string        component;
    std::istringstream ss(path);
    while (getline(ss, component, '/')) {
        base += component + "/";

        if(0 != mkdir(base.c_str(), mode)){
            if(errno == EEXIST){
                struct stat st;
                if(0 != lstat(base.c_str(), &st) || !S_ISDIR(st.st_mode)){
                    return -EPERM;
                }
            }else{
                return -errno;
            }
        }
    }
    return 0;
}

// get existed directory path
std::string get_exist_directory_path(const std::string& path)
{
    std::string        existed = "/"s;    // "/" is existed.
    std::string        base;
    std::string        component;
    std::istringstream ss(path);
    while (getline(ss, component, '/')) {
        if(base != "/"){
            base += "/";
        }
        base += component;
        struct stat st;
        if(0 == stat(base.c_str(), &st) && S_ISDIR(st.st_mode)){
            existed = base;
        }else{
            break;
        }
    }
    return existed;
}

bool check_exist_dir_permission(const char* dirpath)
{
    if(!dirpath || '\0' == dirpath[0]){
        return false;
    }

    // exists
    struct stat st;
    if(0 != stat(dirpath, &st)){
        if(ENOENT == errno){
            // dir does not exist
            return true;
        }
        if(EACCES == errno){
            // could not access directory
            return false;
        }
        // something error occurred
        return false;
    }

    // check type
    if(!S_ISDIR(st.st_mode)){
        // path is not directory
        return false;
    }

    // check permission
    uid_t myuid = geteuid();
    if(myuid == st.st_uid){
        if(S_IRWXU != (st.st_mode & S_IRWXU)){
            return false;
        }
    }else{
        if(1 == is_uid_include_group(myuid, st.st_gid)){
            if(S_IRWXG != (st.st_mode & S_IRWXG)){
                return false;
            }
        }else{
            if(S_IRWXO != (st.st_mode & S_IRWXO)){
                return false;
            }
        }
    }
    return true;
}

// Whether users other than the owner, and other than the members of the
// effective group, can write to the directory.
static bool is_writable_by_others(const struct stat& st, gid_t egid)
{
    return 0 != (st.st_mode & S_IWOTH) || (0 != (st.st_mode & S_IWGRP) && egid != st.st_gid);
}

// [NOTE]
// s3fs makes, opens and removes the files in its cache directories by
// name, so no user other than root and the effective user may be able to
// replace the directory or anything on the path to it.  A user can rename
// the entries of a directory which that user owns or can write to, unless
// the directory has the sticky bit, like /tmp, which leaves each entry to
// its owner.  So every directory and symbolic link on the path must be
// owned by root or the effective user, and no directory may be writable by
// others, or by a group other than the effective group, unless it has the
// sticky bit.  The directory itself may not have even that, since s3fs
// makes all the files in it.
//
// Returns 0 if the directory is safe, -ENOENT if it does not exist and
// nothing on the path to it is unsafe, -EPERM if something is, or another
// negative errno if the path could not be checked.
//
int check_safe_dir_path(const std::string& dirpath)
{
    static constexpr int MAX_SYMLINKS = 40;

    if(dirpath.empty()){
        return -EINVAL;
    }

    std::string rest(dirpath);                  // the part of the path which is not checked yet
    if('/' != rest[0]){
        char cwd[PATH_MAX];
        if(nullptr == getcwd(cwd, sizeof(cwd))){
            int result = -errno;
            S3FS_PRN_ERR("could not get the current directory to check %s - errno(%d)", dirpath.c_str(), result);
            return result;
        }
        rest.insert(0, "/");
        rest.insert(0, cwd);
    }

    const uid_t euid     = geteuid();
    const gid_t egid     = getegid();
    std::string current("/");                   // the checked part of the path, without symbolic links
    int         symlinks = 0;
    struct stat st;
    while(true){
        if(0 != lstat(current.c_str(), &st)){
            int result = -errno;
            S3FS_PRN_ERR("could not get stats of %s on the path to %s - errno(%d)", current.c_str(), dirpath.c_str(), result);
            return result;
        }
        if(!S_ISDIR(st.st_mode)){
            S3FS_PRN_ERR("%s on the path to %s is not a directory.", current.c_str(), dirpath.c_str());
            return -ENOTDIR;
        }
        if(0 != st.st_uid && euid != st.st_uid){
            S3FS_PRN_ERR("%s on the path to %s is owned by another user(uid=%u).", current.c_str(), dirpath.c_str(), static_cast<unsigned int>(st.st_uid));
            return -EPERM;
        }
        if(is_writable_by_others(st, egid) && 0 == (st.st_mode & S_ISVTX)){
            S3FS_PRN_ERR("%s on the path to %s is writable by other users, and has no sticky bit.", current.c_str(), dirpath.c_str());
            return -EPERM;
        }

        // next component
        std::string::size_type start = rest.find_first_not_of('/');
        if(std::string::npos == start){
            break;
        }
        std::string::size_type end = rest.find('/', start);
        std::string component      = rest.substr(start, (std::string::npos == end ? end : end - start));
        rest.erase(0, end);
        if("." == component){
            continue;
        }
        if(".." == component){
            current = mydirname(current);
            continue;
        }

        std::string next(("/" == current ? "" : current) + "/" + component);
        if(0 != lstat(next.c_str(), &st)){
            int result = -errno;
            if(-ENOENT == result){
                S3FS_PRN_DBG("%s on the path to %s does not exist.", next.c_str(), dirpath.c_str());
            }else{
                S3FS_PRN_ERR("could not get stats of %s on the path to %s - errno(%d)", next.c_str(), dirpath.c_str(), result);
            }
            return result;
        }
        if(!S_ISLNK(st.st_mode)){
            current = next;
            continue;
        }

        // follow the symbolic link
        if(0 != st.st_uid && euid != st.st_uid){
            S3FS_PRN_ERR("symbolic link %s on the path to %s is owned by another user(uid=%u).", next.c_str(), dirpath.c_str(), static_cast<unsigned int>(st.st_uid));
            return -EPERM;
        }
        if(MAX_SYMLINKS < ++symlinks){
            S3FS_PRN_ERR("too many symbolic links on the path to %s.", dirpath.c_str());
            return -ELOOP;
        }
        char    target[PATH_MAX];
        ssize_t length = readlink(next.c_str(), target, sizeof(target));
        if(-1 == length){
            int result = -errno;
            S3FS_PRN_ERR("could not read symbolic link %s on the path to %s - errno(%d)", next.c_str(), dirpath.c_str(), result);
            return result;
        }
        if(sizeof(target) <= static_cast<size_t>(length)){
            S3FS_PRN_ERR("symbolic link %s on the path to %s is too long.", next.c_str(), dirpath.c_str());
            return -ENAMETOOLONG;
        }
        if('/' == target[0]){
            current = "/";
        }
        rest.insert(0, "/");
        rest.insert(0, target, static_cast<size_t>(length));
    }

    // the directory itself
    if(is_writable_by_others(st, egid)){
        S3FS_PRN_ERR("%s is writable by other users.", dirpath.c_str());
        return -EPERM;
    }
    return 0;
}

bool delete_files_in_dir(const char* dir, bool is_remove_own)
{
    DIR*                 dp;
    const struct dirent* dent;

    if(nullptr == (dp = opendir(dir))){
        S3FS_PRN_ERR("could not open dir(%s) - errno(%d)", dir, errno);
        return false;
    }
    scope_guard dir_guard([dp, dir]() {
        if(-1 == closedir(dp)){
            S3FS_PRN_ERR("closedir() failed for %s - errno(%d)", dir, errno);
        }
    });

    for(dent = readdir(dp); dent; dent = readdir(dp)){
        if(0 == strcmp(dent->d_name, "..") || 0 == strcmp(dent->d_name, ".")){
            continue;
        }
        std::string fullpath = dir;
        fullpath += "/";
        fullpath += dent->d_name;
        struct stat st;
        if(0 != lstat(fullpath.c_str(), &st)){
            S3FS_PRN_ERR("could not get stats of file(%s) - errno(%d)", fullpath.c_str(), errno);
            return false;
        }
        if(S_ISDIR(st.st_mode)){
            // dir -> Reentrant
            if(!delete_files_in_dir(fullpath.c_str(), true)){
                S3FS_PRN_ERR("could not remove sub dir(%s) - errno(%d)", fullpath.c_str(), errno);
                return false;
            }
        }else{
            if(0 != unlink(fullpath.c_str())){
                S3FS_PRN_ERR("could not remove file(%s) - errno(%d)", fullpath.c_str(), errno);
                return false;
            }
        }
    }

    if(is_remove_own && 0 != rmdir(dir)){
        S3FS_PRN_ERR("could not remove dir(%s) - errno(%d)", dir, errno);
        return false;
    }
    return true;
}

//-------------------------------------------------------------------
// Utility for print message at launching
//-------------------------------------------------------------------
void print_launch_message(int argc, char** argv)
{
    std::string  message = short_version();

    if(argv){
        message += " :";
        for(int cnt = 0; cnt < argc; ++cnt){
            if(argv[cnt]){
                message += " ";
                if(0 == cnt){
                    message += basename(argv[cnt]);
                }else{
                    if(!insecure_logging){
                        message += mask_sensitive_arg(argv[cnt]);
                    }else{
                        message += argv[cnt];
                    }
                }
            }
        }
    }
    S3FS_PRN_LAUNCH_INFO("%s", message.c_str());

    // Special message when insecure logging is enabled
    if(insecure_logging){
        S3FS_PRN_LAUNCH_INFO("%s", "[INSECURE] Deprecated option(insecure_logging) is specified. Authentication information such as tokens and credentials is output to the log.");
    }

    // Warn about disabled SSL verification (MITM vulnerability)
    if(0 == S3fsCurl::GetSslVerifyHostname()){
        S3FS_PRN_LAUNCH_INFO("%s", "SSL hostname verification is DISABLED (ssl_verify_hostname=0). Connections are vulnerable to MITM attacks.");
    }
    if(!S3fsCurl::IsCertCheck()){
        S3FS_PRN_LAUNCH_INFO("%s", "SSL certificate verification is DISABLED (no_check_certificate). Connections are vulnerable to MITM attacks.");
    }
}

int s3fs_fclose(FILE* fp)
{
    if(fp == nullptr){
        return 0;
    }
    return fclose(fp);
}

//-------------------------------------------------------------------
// Utilities for secure credential strings
//-------------------------------------------------------------------
const char* mask_sensitive_string(const char* sensitive)
{
    return mask_sensitive_string_with_flag(sensitive, insecure_logging);
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
