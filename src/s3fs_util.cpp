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
#include <pwd.h>
#include <libgen.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <string>
#include <sstream>

#include "common.h"
#include "s3fs.h"
#include "s3fs_util.h"
#include "string_util.h"
#include "s3fs_help.h"

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

    long res = sysconf(_SC_GETPW_R_SIZE_MAX);
    if(0 > res){
        if (errno != 0){
            S3FS_PRN_WARN("could not get max pw length.");
            abort();
        }
        res = 1024; // default initial length
    }
    max_password_size = res;

    res = sysconf(_SC_GETGR_R_SIZE_MAX);
    if(0 > res) {
        if (errno != 0) {
            S3FS_PRN_ERR("could not get max name length.");
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
    char* pbuf;
    struct passwd pwinfo;
    struct passwd* ppwinfo = NULL;

    // make buffer
    pbuf = new char[maxlen];
    // get pw information
    while(ERANGE == (result = getpwuid_r(uid, &pwinfo, pbuf, maxlen, &ppwinfo))){
        delete[] pbuf;
        maxlen *= 2;
        pbuf = new char[maxlen];
    }

    if(0 != result){
        S3FS_PRN_ERR("could not get pw information(%d).", result);
        delete[] pbuf;
        return std::string("");
    }

    // check pw
    if(NULL == ppwinfo){
        delete[] pbuf;
        return std::string("");
    }
    std::string name = SAFESTRPTR(ppwinfo->pw_name);
    delete[] pbuf;
    return name;
}

int is_uid_include_group(uid_t uid, gid_t gid)
{
    size_t maxlen = max_group_name_length;
    int result;
    char* pbuf;
    struct group ginfo;
    struct group* pginfo = NULL;

    // make buffer
    pbuf = new char[maxlen];
    // get group information
    while(ERANGE == (result = getgrgid_r(gid, &ginfo, pbuf, maxlen, &pginfo))){
        delete[] pbuf;
        maxlen *= 2;
        pbuf = new char[maxlen];
    }

    if(0 != result){
        S3FS_PRN_ERR("could not get group information(%d).", result);
        delete[] pbuf;
        return -result;
    }

    // check group
    if(NULL == pginfo){
        // there is not gid in group.
        delete[] pbuf;
        return -EINVAL;
    }

    std::string username = get_username(uid);

    char** ppgr_mem;
    for(ppgr_mem = pginfo->gr_mem; ppgr_mem && *ppgr_mem; ppgr_mem++){
        if(username == *ppgr_mem){
            // Found username in group.
            delete[] pbuf;
            return 1;
        }
    }
    delete[] pbuf;
    return 0;
}

//-------------------------------------------------------------------
// Utility for file and directory
//-------------------------------------------------------------------
std::string mydirname(const std::string& path)
{
    return std::string(dirname((char*)path.c_str()));
}

// safe variant of dirname
// dirname clobbers path so let it operate on a tmp copy
std::string mydirname(const char* path)
{
    if(!path || '\0' == path[0]){
        return std::string("");
    }
    return mydirname(std::string(path));
}

std::string mybasename(const std::string& path)
{
    return std::string(basename((char*)path.c_str()));
}

// safe variant of basename
// basename clobbers path so let it operate on a tmp copy
std::string mybasename(const char* path)
{
    if(!path || '\0' == path[0]){
        return std::string("");
    }
    return mybasename(std::string(path));
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
    std::string        existed("/");    // "/" is existed.
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
    DIR*           dp;
    struct dirent* dent;

    if(NULL == (dp = opendir(dir))){
        S3FS_PRN_ERR("could not open dir(%s) - errno(%d)", dir, errno);
        return false;
    }

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
            closedir(dp);
            return false;
        }
        if(S_ISDIR(st.st_mode)){
            // dir -> Reentrant
            if(!delete_files_in_dir(fullpath.c_str(), true)){
                S3FS_PRN_ERR("could not remove sub dir(%s) - errno(%d)", fullpath.c_str(), errno);
                closedir(dp);
                return false;
            }
        }else{
            if(0 != unlink(fullpath.c_str())){
                S3FS_PRN_ERR("could not remove file(%s) - errno(%d)", fullpath.c_str(), errno);
                closedir(dp);
                return false;
            }
        }
    }
    closedir(dp);

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
    static char* psysname = NULL;
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
                    message += argv[cnt];
                }
            }
        }
    }
    S3FS_PRN_LAUNCH_INFO("%s", message.c_str());
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
