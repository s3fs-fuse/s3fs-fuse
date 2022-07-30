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
#include <sys/stat.h>
#include <sys/utsname.h>

#include <string>
#include <sstream>

#include "s3fs_logger.h"
#include "s3fs_util.h"
#include "string_util.h"
#include "s3fs_help.h"
#include "autolock.h"

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
// [NOTE]
// basename/dirname returns a static variable pointer as the return value.
// Normally this shouldn't be a problem, but in macos10 we found a case
// where dirname didn't receive its return value correctly due to thread
// conflicts.
// To avoid this, exclusive control is performed by mutex.
//
static pthread_mutex_t* pbasename_lock = NULL;

bool init_basename_lock()
{
    if(pbasename_lock){
        S3FS_PRN_ERR("already initialized mutex for posix dirname/basename function.");
        return false;
    }
    pbasename_lock = new pthread_mutex_t;

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);

#if S3FS_PTHREAD_ERRORCHECK
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
    int result;
    if(0 != (result = pthread_mutex_init(pbasename_lock, &attr))){
        S3FS_PRN_ERR("failed to init pbasename_lock: %d.", result);
        delete pbasename_lock;
        pbasename_lock = NULL;
        return false;
    }
    return true;
}

bool destroy_basename_lock()
{
    if(!pbasename_lock){
        S3FS_PRN_ERR("the mutex for posix dirname/basename function is not initialized.");
        return false;
    }
    int result;
    if(0 != (result = pthread_mutex_destroy(pbasename_lock))){
        S3FS_PRN_ERR("failed to destroy pbasename_lock: %d", result);
        return false;
    }
    delete pbasename_lock;
    pbasename_lock = NULL;

    return true;
}

std::string mydirname(const std::string& path)
{
    AutoLock auto_lock(pbasename_lock);

    return mydirname(path.c_str());
}

// safe variant of dirname
// dirname clobbers path so let it operate on a tmp copy
std::string mydirname(const char* path)
{
    if(!path || '\0' == path[0]){
        return std::string("");
    }

    char *buf = strdup(path);
    std::string result = dirname(buf);
    free(buf);
    return result;
}

std::string mybasename(const std::string& path)
{
    AutoLock auto_lock(pbasename_lock);

    return mybasename(path.c_str());
}

// safe variant of basename
// basename clobbers path so let it operate on a tmp copy
std::string mybasename(const char* path)
{
    if(!path || '\0' == path[0]){
        return std::string("");
    }

    char *buf = strdup(path);
    std::string result = basename(buf);
    free(buf);
    return result;
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

//-------------------------------------------------------------------
// Utility for nanosecond time(timespec)
//-------------------------------------------------------------------
const struct timespec S3FS_OMIT_TS = {0, UTIME_OMIT};

//
// result: -1  ts1 <  ts2
//          0  ts1 == ts2
//          1  ts1 >  ts2
//
int compare_timespec(const struct timespec& ts1, const struct timespec& ts2)
{
    if(ts1.tv_sec < ts2.tv_sec){
        return -1;
    }else if(ts1.tv_sec > ts2.tv_sec){
        return 1;
    }else{
        if(ts1.tv_nsec < ts2.tv_nsec){
            return -1;
        }else if(ts1.tv_nsec > ts2.tv_nsec){
            return 1;
        }
    }
    return 0;
}

//
// result: -1  st <  ts
//          0  st == ts
//          1  st >  ts
//
int compare_timespec(const struct stat& st, stat_time_type type, const struct timespec& ts)
{
    struct timespec st_ts;
    set_stat_to_timespec(st, type, st_ts);

    return compare_timespec(st_ts, ts);
}

void set_timespec_to_stat(struct stat& st, stat_time_type type, const struct timespec& ts)
{
    if(ST_TYPE_ATIME == type){
        #if defined(__APPLE__)
            st.st_atime             = ts.tv_sec;
            st.st_atimespec.tv_nsec = ts.tv_nsec;
        #else
            st.st_atim.tv_sec       = ts.tv_sec;
            st.st_atim.tv_nsec      = ts.tv_nsec;
        #endif
    }else if(ST_TYPE_MTIME == type){
        #if defined(__APPLE__)
            st.st_mtime             = ts.tv_sec;
            st.st_mtimespec.tv_nsec = ts.tv_nsec;
        #else
            st.st_mtim.tv_sec       = ts.tv_sec;
            st.st_mtim.tv_nsec      = ts.tv_nsec;
        #endif
    }else if(ST_TYPE_CTIME == type){
        #if defined(__APPLE__)
            st.st_ctime             = ts.tv_sec;
            st.st_ctimespec.tv_nsec = ts.tv_nsec;
        #else
            st.st_ctim.tv_sec       = ts.tv_sec;
            st.st_ctim.tv_nsec      = ts.tv_nsec;
        #endif
    }else{
        S3FS_PRN_ERR("unknown type(%d), so skip to set value.", type);
    }
}

struct timespec* set_stat_to_timespec(const struct stat& st, stat_time_type type, struct timespec& ts)
{
    if(ST_TYPE_ATIME == type){
        #if defined(__APPLE__)
           ts.tv_sec  = st.st_atime;
           ts.tv_nsec = st.st_atimespec.tv_nsec;
        #else
           ts         = st.st_atim;
        #endif
    }else if(ST_TYPE_MTIME == type){
        #if defined(__APPLE__)
           ts.tv_sec  = st.st_mtime;
           ts.tv_nsec = st.st_mtimespec.tv_nsec;
        #else
           ts         = st.st_mtim;
        #endif
    }else if(ST_TYPE_CTIME == type){
        #if defined(__APPLE__)
           ts.tv_sec  = st.st_ctime;
           ts.tv_nsec = st.st_ctimespec.tv_nsec;
        #else
           ts         = st.st_ctim;
        #endif
    }else{
        S3FS_PRN_ERR("unknown type(%d), so use 0 as timespec.", type);
        ts.tv_sec     = 0;
        ts.tv_nsec    = 0;
    }
    return &ts;
}

std::string str_stat_time(const struct stat& st, stat_time_type type)
{
    struct timespec ts;
    return str(*set_stat_to_timespec(st, type, ts));
}

struct timespec* s3fs_realtime(struct timespec& ts)
{
    if(-1 == clock_gettime(static_cast<clockid_t>(CLOCK_REALTIME), &ts)){
        S3FS_PRN_WARN("failed to clock_gettime by errno(%d)", errno);
        ts.tv_sec  = time(NULL);
        ts.tv_nsec = 0;
    }
    return &ts;
}

std::string s3fs_str_realtime()
{
    struct timespec ts;
    return str(*(s3fs_realtime(ts)));
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
