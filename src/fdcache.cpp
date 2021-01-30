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
#include <cerrno>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#include "common.h"
#include "s3fs.h"
#include "fdcache.h"
#include "s3fs_util.h"
#include "s3fs_logger.h"
#include "string_util.h"
#include "autolock.h"

//------------------------------------------------
// Symbols
//------------------------------------------------
#define TMPFILE_FOR_CHECK_HOLE  "/tmp/.s3fs_hole_check.tmp"

//
// For cache directory top path
//
#if defined(P_tmpdir)
#define TMPFILE_DIR_0PATH   P_tmpdir
#else
#define TMPFILE_DIR_0PATH   "/tmp"
#endif

//
// The following symbols are used by FdManager::RawCheckAllCache().
//
#define CACHEDBG_FMT_DIR_PROB   "Directory: %s"
#define CACHEDBG_FMT_HEAD       "---------------------------------------------------------------------------\n" \
                                "Check cache file and its stats file consistency at %s\n"                       \
                                "---------------------------------------------------------------------------"
#define CACHEDBG_FMT_FOOT       "---------------------------------------------------------------------------\n" \
                                "Summary - Total files:                %d\n" \
                                "          Detected error files:       %d\n" \
                                "          Detected error directories: %d\n" \
                                "---------------------------------------------------------------------------"
#define CACHEDBG_FMT_FILE_OK    "File:      %s%s    -> [OK] no problem"
#define CACHEDBG_FMT_FILE_PROB  "File:      %s%s"
#define CACHEDBG_FMT_DIR_PROB   "Directory: %s"
#define CACHEDBG_FMT_ERR_HEAD   "           -> [E] there is a mark that data exists in stats, but there is no data in the cache file."
#define CACHEDBG_FMT_WARN_HEAD  "           -> [W] These show no data in stats, but there is evidence of data in the cache file(no problem)."
#define CACHEDBG_FMT_WARN_OPEN  "\n           -> [W] This file is currently open and may not provide accurate analysis results."
#define CACHEDBG_FMT_CRIT_HEAD  "           -> [C] %s"
#define CACHEDBG_FMT_CRIT_HEAD2 "           -> [C] "
#define CACHEDBG_FMT_PROB_BLOCK "                  0x%016zx(0x%016zx bytes)"

// [NOTE]
// NOCACHE_PATH_PREFIX symbol needs for not using cache mode.
// Now s3fs I/F functions in s3fs.cpp has left the processing
// to FdManager and FdEntity class. FdManager class manages
// the list of local file stat and file descriptor in conjunction
// with the FdEntity class.
// When s3fs is not using local cache, it means FdManager must
// return new temporary file descriptor at each opening it.
// Then FdManager caches fd by key which is dummy file path
// instead of real file path.
// This process may not be complete, but it is easy way can
// be realized.
//
#define NOCACHE_PATH_PREFIX_FORM    " __S3FS_UNEXISTED_PATH_%lx__ / "      // important space words for simply

//------------------------------------------------
// FdManager class variable
//------------------------------------------------
FdManager       FdManager::singleton;
pthread_mutex_t FdManager::fd_manager_lock;
pthread_mutex_t FdManager::cache_cleanup_lock;
pthread_mutex_t FdManager::reserved_diskspace_lock;
bool            FdManager::is_lock_init(false);
std::string     FdManager::cache_dir;
bool            FdManager::check_cache_dir_exist(false);
off_t           FdManager::free_disk_space = 0;
std::string     FdManager::check_cache_output;
bool            FdManager::checked_lseek(false);
bool            FdManager::have_lseek_hole(false);

//------------------------------------------------
// FdManager class methods
//------------------------------------------------
bool FdManager::SetCacheDir(const char* dir)
{
    if(!dir || '\0' == dir[0]){
        cache_dir = "";
    }else{
        cache_dir = dir;
    }
    return true;
}

bool FdManager::SetCacheCheckOutput(const char* path)
{
    if(!path || '\0' == path[0]){
        check_cache_output.erase();
    }else{
        check_cache_output = path;
    }
    return true;
}

bool FdManager::DeleteCacheDirectory()
{
    if(FdManager::cache_dir.empty()){
        return true;
    }

    std::string cache_path;
    if(!FdManager::MakeCachePath(NULL, cache_path, false)){
        return false;
    }
    if(!delete_files_in_dir(cache_path.c_str(), true)){
        return false;
    }

    std::string mirror_path = FdManager::cache_dir + "/." + bucket + ".mirror";
    if(!delete_files_in_dir(mirror_path.c_str(), true)){
        return false;
    }

    return true;
}

int FdManager::DeleteCacheFile(const char* path)
{
    S3FS_PRN_INFO3("[path=%s]", SAFESTRPTR(path));

    if(!path){
        return -EIO;
    }
    if(FdManager::cache_dir.empty()){
        return 0;
    }
    std::string cache_path;
    if(!FdManager::MakeCachePath(path, cache_path, false)){
        return 0;
    }
    int result = 0;
    if(0 != unlink(cache_path.c_str())){
        if(ENOENT == errno){
            S3FS_PRN_DBG("failed to delete file(%s): errno=%d", path, errno);
        }else{
            S3FS_PRN_ERR("failed to delete file(%s): errno=%d", path, errno);
        }
        result = -errno;
    }
    if(!CacheFileStat::DeleteCacheFileStat(path)){
        if(ENOENT == errno){
            S3FS_PRN_DBG("failed to delete stat file(%s): errno=%d", path, errno);
        }else{
            S3FS_PRN_ERR("failed to delete stat file(%s): errno=%d", path, errno);
        }
        if(0 != errno){
            result = -errno;
        }else{
            result = -EIO;
        }
    }
    return result;
}

bool FdManager::MakeCachePath(const char* path, std::string& cache_path, bool is_create_dir, bool is_mirror_path)
{
    if(FdManager::cache_dir.empty()){
        cache_path = "";
        return true;
    }

    std::string resolved_path(FdManager::cache_dir);
    if(!is_mirror_path){
        resolved_path += "/";
        resolved_path += bucket;
    }else{
        resolved_path += "/.";
        resolved_path += bucket;
        resolved_path += ".mirror";
    }

    if(is_create_dir){
        int result;
        if(0 != (result = mkdirp(resolved_path + mydirname(path), 0777))){
            S3FS_PRN_ERR("failed to create dir(%s) by errno(%d).", path, result);
            return false;
        }
    }
    if(!path || '\0' == path[0]){
        cache_path = resolved_path;
    }else{
        cache_path = resolved_path + SAFESTRPTR(path);
    }
    return true;
}

bool FdManager::CheckCacheTopDir()
{
    if(FdManager::cache_dir.empty()){
        return true;
    }
    std::string toppath(FdManager::cache_dir + "/" + bucket);

    return check_exist_dir_permission(toppath.c_str());
}

bool FdManager::MakeRandomTempPath(const char* path, std::string& tmppath)
{
    char szBuff[64];

    sprintf(szBuff, NOCACHE_PATH_PREFIX_FORM, random());     // worry for performance, but maybe don't worry.
    tmppath  = szBuff;
    tmppath += path ? path : "";
    return true;
}

bool FdManager::SetCheckCacheDirExist(bool is_check)
{
    bool old = FdManager::check_cache_dir_exist;
    FdManager::check_cache_dir_exist = is_check;
    return old;
}

bool FdManager::CheckCacheDirExist()
{
    if(!FdManager::check_cache_dir_exist){
        return true;
    }
    if(FdManager::cache_dir.empty()){
        return true;
    }
    // check the directory
    struct stat st;
    if(0 != stat(cache_dir.c_str(), &st)){
        S3FS_PRN_ERR("could not access to cache directory(%s) by errno(%d).", cache_dir.c_str(), errno);
        return false;
    }
    if(!S_ISDIR(st.st_mode)){
        S3FS_PRN_ERR("the cache directory(%s) is not directory.", cache_dir.c_str());
        return false;
    }
    return true;
}

off_t FdManager::GetEnsureFreeDiskSpace()
{
    AutoLock auto_lock(&FdManager::reserved_diskspace_lock);
    return FdManager::free_disk_space;
}

off_t FdManager::SetEnsureFreeDiskSpace(off_t size)
{
    AutoLock auto_lock(&FdManager::reserved_diskspace_lock);
    off_t old = FdManager::free_disk_space;
    FdManager::free_disk_space = size;
    return old;
}

off_t FdManager::GetFreeDiskSpace(const char* path)
{
    struct statvfs vfsbuf;
    std::string ctoppath;
    if(!FdManager::cache_dir.empty()){
        ctoppath = FdManager::cache_dir + "/";
        ctoppath = get_exist_directory_path(ctoppath);    // existed directory
        if(ctoppath != "/"){
            ctoppath += "/";
        }
    }else{
        ctoppath = TMPFILE_DIR_0PATH "/";
    }
    if(path && '\0' != *path){
        ctoppath += path;
    }else{
        ctoppath += ".";
    }
    if(-1 == statvfs(ctoppath.c_str(), &vfsbuf)){
        S3FS_PRN_ERR("could not get vfs stat by errno(%d)", errno);
        return 0;
    }
    return (vfsbuf.f_bavail * vfsbuf.f_frsize);
}

bool FdManager::IsSafeDiskSpace(const char* path, off_t size)
{
    off_t fsize = FdManager::GetFreeDiskSpace(path);
    return size + FdManager::GetEnsureFreeDiskSpace() <= fsize;
}

bool FdManager::HaveLseekHole()
{
    if(FdManager::checked_lseek){
        return FdManager::have_lseek_hole;
    }

    // create tempolary file
    int fd;
    if(-1 == (fd = open(TMPFILE_FOR_CHECK_HOLE, O_CREAT|O_RDWR, 0600))){
        S3FS_PRN_ERR("failed to open tempolary file(%s) - errno(%d)", TMPFILE_FOR_CHECK_HOLE, errno);
        FdManager::checked_lseek   = true;
        FdManager::have_lseek_hole = false;
        return FdManager::have_lseek_hole;
    }

    // check SEEK_DATA/SEEK_HOLE options
    bool result = true;
    if(-1 == lseek(fd, 0, SEEK_DATA)){
        if(EINVAL == errno){
            S3FS_PRN_ERR("lseek does not support SEEK_DATA");
            result = false;
        }
    }
    if(result && -1 == lseek(fd, 0, SEEK_HOLE)){
        if(EINVAL == errno){
            S3FS_PRN_ERR("lseek does not support SEEK_HOLE");
            result = false;
        }
    }
    close(fd);
    unlink(TMPFILE_FOR_CHECK_HOLE);

    FdManager::checked_lseek   = true;
    FdManager::have_lseek_hole = result;
    return FdManager::have_lseek_hole;
}

//------------------------------------------------
// FdManager methods
//------------------------------------------------
FdManager::FdManager()
{
    if(this == FdManager::get()){
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
        int result;
        if(0 != (result = pthread_mutex_init(&FdManager::fd_manager_lock, &attr))){
            S3FS_PRN_CRIT("failed to init fd_manager_lock: %d", result);
            abort();
        }
        if(0 != (result = pthread_mutex_init(&FdManager::cache_cleanup_lock, &attr))){
            S3FS_PRN_CRIT("failed to init cache_cleanup_lock: %d", result);
            abort();
        }
        if(0 != (result = pthread_mutex_init(&FdManager::reserved_diskspace_lock, &attr))){
            S3FS_PRN_CRIT("failed to init reserved_diskspace_lock: %d", result);
            abort();
        }
        FdManager::is_lock_init = true;
    }else{
        abort();
    }
}

FdManager::~FdManager()
{
    if(this == FdManager::get()){
        for(fdent_map_t::iterator iter = fent.begin(); fent.end() != iter; ++iter){
            FdEntity* ent = (*iter).second;
            S3FS_PRN_WARN("To exit with the cache file opened: path=%s, refcnt=%d", ent->GetPath(), ent->GetRefCnt());
            delete ent;
        }
        fent.clear();

        if(FdManager::is_lock_init){
            int result;
            if(0 != (result = pthread_mutex_destroy(&FdManager::fd_manager_lock))){
                S3FS_PRN_CRIT("failed to destroy fd_manager_lock: %d", result);
                abort();
            }
            if(0 != (result = pthread_mutex_destroy(&FdManager::cache_cleanup_lock))){
                S3FS_PRN_CRIT("failed to destroy cache_cleanup_lock: %d", result);
                abort();
            }
            if(0 != (result = pthread_mutex_destroy(&FdManager::reserved_diskspace_lock))){
                S3FS_PRN_CRIT("failed to destroy reserved_diskspace_lock: %d", result);
                abort();
            }
            FdManager::is_lock_init = false;
        }
    }else{
        abort();
    }
}

FdEntity* FdManager::GetFdEntity(const char* path, int existfd, bool increase_ref)
{
    S3FS_PRN_INFO3("[path=%s][fd=%d]", SAFESTRPTR(path), existfd);

    if(!path || '\0' == path[0]){
        return NULL;
    }
    AutoLock auto_lock(&FdManager::fd_manager_lock);

    fdent_map_t::iterator iter = fent.find(std::string(path));
    if(fent.end() != iter && (-1 == existfd || (*iter).second->GetFd() == existfd)){
        if(increase_ref){
            iter->second->Dup();
        }
        return (*iter).second;
    }

    if(-1 != existfd){
        for(iter = fent.begin(); iter != fent.end(); ++iter){
            if((*iter).second && (*iter).second->GetFd() == existfd){
                // found opened fd in map
                if(0 == strcmp((*iter).second->GetPath(), path)){
                    if(increase_ref){
                        iter->second->Dup();
                    }
                    return (*iter).second;
                }
                // found fd, but it is used another file(file descriptor is recycled)
                // so returns NULL.
                break;
            }
        }
    }
    return NULL;
}

FdEntity* FdManager::Open(const char* path, headers_t* pmeta, off_t size, time_t time, bool force_tmpfile, bool is_create, bool no_fd_lock_wait)
{
    S3FS_PRN_DBG("[path=%s][size=%lld][time=%lld]", SAFESTRPTR(path), static_cast<long long>(size), static_cast<long long>(time));

    if(!path || '\0' == path[0]){
        return NULL;
    }
    bool close = false;
    FdEntity* ent;

    AutoLock auto_lock(&FdManager::fd_manager_lock);

    // search in mapping by key(path)
    fdent_map_t::iterator iter = fent.find(std::string(path));

    if(fent.end() == iter && !force_tmpfile && !FdManager::IsCacheDir()){
        // If the cache directory is not specified, s3fs opens a temporary file
        // when the file is opened.
        // Then if it could not find a entity in map for the file, s3fs should
        // search a entity in all which opened the temporary file.
        //
        for(iter = fent.begin(); iter != fent.end(); ++iter){
            if((*iter).second && (*iter).second->IsOpen() && 0 == strcmp((*iter).second->GetPath(), path)){
                break;      // found opened fd in mapping
            }
        }
    }

    if(fent.end() != iter){
        // found
        ent = (*iter).second;
        ent->Dup();
        if(ent->IsModified()){
            // If the file is being modified, it will not be resized.
            size = -1;
        }
        close = true;

    }else if(is_create){
        // not found
        std::string cache_path;
        if(!force_tmpfile && !FdManager::MakeCachePath(path, cache_path, true)){
            S3FS_PRN_ERR("failed to make cache path for object(%s).", path);
            return NULL;
        }
        // make new obj
        ent = new FdEntity(path, cache_path.c_str());

        if(!cache_path.empty()){
            // using cache
            fent[std::string(path)] = ent;
        }else{
            // not using cache, so the key of fdentity is set not really existing path.
            // (but not strictly unexisting path.)
            //
            // [NOTE]
            // The reason why this process here, please look at the definition of the
            // comments of NOCACHE_PATH_PREFIX_FORM symbol.
            //
            std::string tmppath;
            FdManager::MakeRandomTempPath(path, tmppath);
            fent[tmppath] = ent;
        }
    }else{
        return NULL;
    }

    // open
    if(0 != ent->Open(pmeta, size, time, no_fd_lock_wait)){
        if(close){
            ent->Close();
        }
        return NULL;
    }
    if(close){
        ent->Close();
    }
    return ent;
}

FdEntity* FdManager::ExistOpen(const char* path, int existfd, bool ignore_existfd)
{
    S3FS_PRN_DBG("[path=%s][fd=%d][ignore_existfd=%s]", SAFESTRPTR(path), existfd, ignore_existfd ? "true" : "false");

    // search by real path
    FdEntity* ent = Open(path, NULL, -1, -1, false, false);

    if(!ent && (ignore_existfd || (-1 != existfd))){
        // search from all fdentity because of not using cache.
        AutoLock auto_lock(&FdManager::fd_manager_lock);

        for(fdent_map_t::iterator iter = fent.begin(); iter != fent.end(); ++iter){
            if((*iter).second && (*iter).second->IsOpen() && (ignore_existfd || ((*iter).second->GetFd() == existfd))){
                // found opened fd in map
                if(0 == strcmp((*iter).second->GetPath(), path)){
                    ent = (*iter).second;
                    ent->Dup();
                }else{
                    // found fd, but it is used another file(file descriptor is recycled)
                    // so returns NULL.
                }
                break;
            }
        }
    }
    return ent;
}

void FdManager::Rename(const std::string &from, const std::string &to)
{
    AutoLock auto_lock(&FdManager::fd_manager_lock);

    fdent_map_t::iterator iter = fent.find(from);
    if(fent.end() == iter && !FdManager::IsCacheDir()){
        // If the cache directory is not specified, s3fs opens a temporary file
        // when the file is opened.
        // Then if it could not find a entity in map for the file, s3fs should
        // search a entity in all which opened the temporary file.
        //
        for(iter = fent.begin(); iter != fent.end(); ++iter){
            if((*iter).second && (*iter).second->IsOpen() && 0 == strcmp((*iter).second->GetPath(), from.c_str())){
                break;              // found opened fd in mapping
            }
        }
    }

    if(fent.end() != iter){
        // found
        S3FS_PRN_DBG("[from=%s][to=%s]", from.c_str(), to.c_str());

        FdEntity* ent = (*iter).second;

        // retrieve old fd entity from map
        fent.erase(iter);

        // rename path and caches in fd entity
        std::string fentmapkey;
        if(!ent->RenamePath(to, fentmapkey)){
            S3FS_PRN_ERR("Failed to rename FdEntity object for %s to %s", from.c_str(), to.c_str());
            return;
        }

        // set new fd entity to map
        fent[fentmapkey] = ent;
    }
}

bool FdManager::Close(FdEntity* ent)
{
    S3FS_PRN_DBG("[ent->file=%s][ent->fd=%d]", ent ? ent->GetPath() : "", ent ? ent->GetFd() : -1);

    if(!ent){
        return true;  // returns success
    }

    AutoLock auto_lock(&FdManager::fd_manager_lock);

    for(fdent_map_t::iterator iter = fent.begin(); iter != fent.end(); ++iter){
        if((*iter).second == ent){
            ent->Close();
            if(!ent->IsOpen()){
                // remove found entity from map.
                fent.erase(iter++);

                // check another key name for entity value to be on the safe side
                for(; iter != fent.end(); ){
                    if((*iter).second == ent){
                        fent.erase(iter++);
                    }else{
                        ++iter;
                    }
                }
                delete ent;
          }
          return true;
        }
    }
    return false;
}

bool FdManager::ChangeEntityToTempPath(FdEntity* ent, const char* path)
{
    AutoLock auto_lock(&FdManager::fd_manager_lock);

    for(fdent_map_t::iterator iter = fent.begin(); iter != fent.end(); ){
        if((*iter).second == ent){
            fent.erase(iter++);

            std::string tmppath;
            FdManager::MakeRandomTempPath(path, tmppath);
            fent[tmppath] = ent;
        }else{
            ++iter;
        }
    }
    return false;
}

void FdManager::CleanupCacheDir()
{
    //S3FS_PRN_DBG("cache cleanup requested");

    if(!FdManager::IsCacheDir()){
        return;
    }

    AutoLock auto_lock_no_wait(&FdManager::cache_cleanup_lock, AutoLock::NO_WAIT);

    if(auto_lock_no_wait.isLockAcquired()){
        //S3FS_PRN_DBG("cache cleanup started");
        CleanupCacheDirInternal("");
        //S3FS_PRN_DBG("cache cleanup ended");
    }else{
        // wait for other thread to finish cache cleanup
        AutoLock auto_lock(&FdManager::cache_cleanup_lock);
    }
}

void FdManager::CleanupCacheDirInternal(const std::string &path)
{
    DIR*           dp;
    struct dirent* dent;
    std::string    abs_path = cache_dir + "/" + bucket + path;

    if(NULL == (dp = opendir(abs_path.c_str()))){
        S3FS_PRN_ERR("could not open cache dir(%s) - errno(%d)", abs_path.c_str(), errno);
        return;
    }

    for(dent = readdir(dp); dent; dent = readdir(dp)){
        if(0 == strcmp(dent->d_name, "..") || 0 == strcmp(dent->d_name, ".")){
            continue;
        }
        std::string fullpath = abs_path;
        fullpath         += "/";
        fullpath         += dent->d_name;
        struct stat st;
        if(0 != lstat(fullpath.c_str(), &st)){
            S3FS_PRN_ERR("could not get stats of file(%s) - errno(%d)", fullpath.c_str(), errno);
            closedir(dp);
            return;
        }
        std::string next_path = path + "/" + dent->d_name;
        if(S_ISDIR(st.st_mode)){
            CleanupCacheDirInternal(next_path);
        }else{
            AutoLock auto_lock(&FdManager::fd_manager_lock, AutoLock::NO_WAIT);
            if (!auto_lock.isLockAcquired()) {
                S3FS_PRN_ERR("could not get fd_manager_lock when clean up file(%s)", next_path.c_str());
                continue;
            }
            fdent_map_t::iterator iter = fent.find(next_path);
            if(fent.end() == iter) {
                S3FS_PRN_DBG("cleaned up: %s", next_path.c_str());
                FdManager::DeleteCacheFile(next_path.c_str());
            }
        }
    }
    closedir(dp);
}

bool FdManager::ReserveDiskSpace(off_t size)
{
    if(IsSafeDiskSpace(NULL, size)){
        AutoLock auto_lock(&FdManager::reserved_diskspace_lock);
        free_disk_space += size;
        return true;
    }
    return false;
}

void FdManager::FreeReservedDiskSpace(off_t size)
{
    AutoLock auto_lock(&FdManager::reserved_diskspace_lock);
    free_disk_space -= size;
}

//
// Inspect all files for stats file for cache file
// 
// [NOTE]
// The minimum sub_path parameter is "/".
// The sub_path is a directory path starting from "/" and ending with "/".
//
// This method produces the following output.
//
// * Header
//    ------------------------------------------------------------
//    Check cache file and its stats file consistency
//    ------------------------------------------------------------
// * When the cache file and its stats information match
//    File path: <file path> -> [OK] no problem
//
// * If there is a problem with the cache file and its stats information
//    File path: <file path>
//      -> [P] <If the problem is that parsing is not possible in the first place, the message is output here with this prefix.>
//      -> [E] there is a mark that data exists in stats, but there is no data in the cache file.
//             <offset address>(bytes)
//                 ...
//                 ...
//      -> [W] These show no data in stats, but there is evidence of data in the cache file.(no problem.)
//             <offset address>(bytes)
//                 ...
//                 ...
//
bool FdManager::RawCheckAllCache(FILE* fp, const char* cache_stat_top_dir, const char* sub_path, int& total_file_cnt, int& err_file_cnt, int& err_dir_cnt)
{
    if(!cache_stat_top_dir || '\0' == cache_stat_top_dir[0] || !sub_path || '\0' == sub_path[0]){
        S3FS_PRN_ERR("Parameter cache_stat_top_dir is empty.");
        return false;
    }

    // open directory of cache file's stats
    DIR*   statsdir;
    std::string target_dir = cache_stat_top_dir;
    target_dir       += sub_path;
    if(NULL == (statsdir = opendir(target_dir.c_str()))){
        S3FS_PRN_ERR("Could not open directory(%s) by errno(%d)", target_dir.c_str(), errno);
        return false;
    }

    // loop in directory of cache file's stats
    struct dirent* pdirent = NULL;
    while(NULL != (pdirent = readdir(statsdir))){
        if(DT_DIR == pdirent->d_type){
            // found directory
            if(0 == strcmp(pdirent->d_name, ".") || 0 == strcmp(pdirent->d_name, "..")){
                continue;
            }

            // reentrant for sub directory
            std::string subdir_path = sub_path;
            subdir_path       += pdirent->d_name;
            subdir_path       += '/';
            if(!RawCheckAllCache(fp, cache_stat_top_dir, subdir_path.c_str(), total_file_cnt, err_file_cnt, err_dir_cnt)){
                // put error message for this dir.
                ++err_dir_cnt;
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_DIR_PROB, subdir_path.c_str());
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_CRIT_HEAD, "Something error is occurred in checking this directory");
            }

        }else{
            ++total_file_cnt;

            // make cache file path
            std::string strOpenedWarn;
            std::string cache_path;
            std::string object_file_path = sub_path;
            object_file_path       += pdirent->d_name;
            if(!FdManager::MakeCachePath(object_file_path.c_str(), cache_path, false, false) || cache_path.empty()){
                ++err_file_cnt;
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_FILE_PROB, object_file_path.c_str(), strOpenedWarn.c_str());
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_CRIT_HEAD, "Could not make cache file path");
                continue;
            }

            // check if the target file is currently in operation.
            {
                AutoLock auto_lock(&FdManager::fd_manager_lock);

                fdent_map_t::iterator iter = fent.find(object_file_path);
                if(fent.end() != iter){
                    // This file is opened now, then we need to put warning message.
                    strOpenedWarn = CACHEDBG_FMT_WARN_OPEN;
                }
            }

            // open cache file
            int cache_file_fd;
            if(-1 == (cache_file_fd = open(cache_path.c_str(), O_RDONLY))){
                ++err_file_cnt;
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_FILE_PROB, object_file_path.c_str(), strOpenedWarn.c_str());
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_CRIT_HEAD, "Could not open cache file");
                continue;
            }

            // get inode number for cache file
            struct stat st;
            if(0 != fstat(cache_file_fd, &st)){
                ++err_file_cnt;
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_FILE_PROB, object_file_path.c_str(), strOpenedWarn.c_str());
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_CRIT_HEAD, "Could not get file inode number for cache file");

                close(cache_file_fd);
                continue;
            }
            ino_t cache_file_inode = st.st_ino;

            // open cache stat file and load page info.
            PageList      pagelist;
            CacheFileStat cfstat(object_file_path.c_str());
            if(!cfstat.ReadOnlyOpen() || !pagelist.Serialize(cfstat, false, cache_file_inode)){
                ++err_file_cnt;
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_FILE_PROB, object_file_path.c_str(), strOpenedWarn.c_str());
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_CRIT_HEAD, "Could not load cache file stats information");

                close(cache_file_fd);
                continue;
            }
            cfstat.Release();

            // compare cache file size and stats information
            if(st.st_size != pagelist.Size()){
                ++err_file_cnt;
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_FILE_PROB, object_file_path.c_str(), strOpenedWarn.c_str());
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_CRIT_HEAD2 "The cache file size(%lld) and the value(%lld) from cache file stats are different", static_cast<long long int>(st.st_size), static_cast<long long int>(pagelist.Size()));

                close(cache_file_fd);
                continue;
            }

            // compare cache file stats and cache file blocks
            fdpage_list_t err_area_list;
            fdpage_list_t warn_area_list;
            if(!pagelist.CompareSparseFile(cache_file_fd, st.st_size, err_area_list, warn_area_list)){
                // Found some error or warning
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_FILE_PROB, object_file_path.c_str(), strOpenedWarn.c_str());
                if(!warn_area_list.empty()){
                    S3FS_PRN_CACHE(fp, CACHEDBG_FMT_WARN_HEAD);
                    for(fdpage_list_t::const_iterator witer = warn_area_list.begin(); witer != warn_area_list.end(); ++witer){
                        S3FS_PRN_CACHE(fp, CACHEDBG_FMT_PROB_BLOCK, static_cast<size_t>(witer->offset), static_cast<size_t>(witer->bytes));
                    }
                }
                if(!err_area_list.empty()){
                    ++err_file_cnt;
                    S3FS_PRN_CACHE(fp, CACHEDBG_FMT_ERR_HEAD);
                    for(fdpage_list_t::const_iterator eiter = err_area_list.begin(); eiter != err_area_list.end(); ++eiter){
                        S3FS_PRN_CACHE(fp, CACHEDBG_FMT_PROB_BLOCK, static_cast<size_t>(eiter->offset), static_cast<size_t>(eiter->bytes));
                    }
                }
            }else{
                // There is no problem!
                if(!strOpenedWarn.empty()){
                    strOpenedWarn += "\n ";
                }
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_FILE_OK, object_file_path.c_str(), strOpenedWarn.c_str());
            }
            err_area_list.clear();
            warn_area_list.clear();
            close(cache_file_fd);
        }
    }
    closedir(statsdir);

    return true;
}

bool FdManager::CheckAllCache()
{
    if(!FdManager::HaveLseekHole()){
        S3FS_PRN_ERR("lseek does not support SEEK_DATA/SEEK_HOLE, then could not check cache.");
        return false;
    }

    FILE* fp;
    if(FdManager::check_cache_output.empty()){
        fp = stdout;
    }else{
        if(NULL == (fp = fopen(FdManager::check_cache_output.c_str(), "a+"))){
            S3FS_PRN_ERR("Could not open(create) output file(%s) for checking all cache by errno(%d)", FdManager::check_cache_output.c_str(), errno);
            return false;
        }
    }

    // print head message
    S3FS_PRN_CACHE(fp, CACHEDBG_FMT_HEAD, S3fsLog::GetCurrentTime());

    // Loop in directory of cache file's stats
    std::string top_path  = CacheFileStat::GetCacheFileStatTopDir();
    int    total_file_cnt = 0;
    int    err_file_cnt   = 0;
    int    err_dir_cnt    = 0;
    bool   result         = RawCheckAllCache(fp, top_path.c_str(), "/", total_file_cnt, err_file_cnt, err_dir_cnt);
    if(!result){
        S3FS_PRN_ERR("Processing failed due to some problem.");
    }

    // print foot message
    S3FS_PRN_CACHE(fp, CACHEDBG_FMT_FOOT, total_file_cnt, err_file_cnt, err_dir_cnt);

    if(stdout != fp){
        fclose(fp);
    }

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
