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
#include <unistd.h>
#include <cerrno>
#include <grp.h>
#include <memory>
#include <mutex>
#include <pwd.h>
#include <libgen.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/utsname.h>

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

    // [TODO]
    // Currently, use "&str[pos]" to make it possible to build with C++14.
    // Once we support C++17 or later, we will use "str.data()".
    //
    path.push_back('\0');     // terminate with a null character and allocate space for it.
    return dirname(&path[0]); // NOLINT(readability-container-data-pointer)
}

// safe variant of basename
// basename clobbers path so let it operate on a tmp copy
std::string mybasename(std::string path)
{
    const std::lock_guard<std::mutex> data_lock(basename_lock);

    if(path.empty()){
        return "";
    }

    // [TODO]
    // Currently, use "&str[pos]" to make it possible to build with C++14.
    // Once we support C++17 or later, we will use "str.data()".
    //
    path.push_back('\0');      // terminate with a null character and allocate space for it.
    return basename(&path[0]); // NOLINT(readability-container-data-pointer)
}

// mkdir --parents
int mkdirp(const std::string& path, mode_t mode)
{
    std::string        base;
    std::string        component;
    std::istringstream ss(path);
    while (getline(ss, component, '/')) {
        base += component + "/";

        struct stat st;
        if(0 == stat(base.c_str(), &st)){
            if(!S_ISDIR(st.st_mode)){
                return EPERM;
            }
        }else{
            if(0 != mkdir(base.c_str(), mode) && errno != EEXIST){
                return errno;
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
// Utility for system information
//-------------------------------------------------------------------
bool compare_sysname(const char* target)
{
    // [NOTE]
    // The buffer size of sysname member in struct utsname is
    // OS dependent, but 512 bytes is sufficient for now.
    //
    static const char* psysname = nullptr;
    static char  sysname[512];
    if(!psysname){
        struct utsname sysinfo;
        if(0 != uname(&sysinfo)){
            S3FS_PRN_ERR("could not initialize system name to internal buffer(errno:%d), thus use \"Linux\".", errno);
            strcpy(sysname, "Linux");
        }else{
            S3FS_PRN_INFO("system name is %s", sysinfo.sysname);
            sysname[sizeof(sysname) - 1] = '\0';
            strncpy(sysname, sysinfo.sysname, sizeof(sysname) - 1);
        }
        psysname = &sysname[0];
    }

    if(!target || 0 != strcmp(psysname, target)){
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
