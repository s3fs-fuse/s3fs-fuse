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
#include <climits>
#include <unistd.h>
#include <dirent.h>
#include <string>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <utility>

#include "fdcache.h"
#include "fdcache_stat.h"
#include "s3fs_util.h"
#include "s3fs_logger.h"
#include "s3fs_cred.h"
#include "string_util.h"

//
// The following symbols are used by FdManager::RawCheckAllCache().
//
// These must be #defines due to string literal concatenation.
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
static constexpr char NOCACHE_PATH_PREFIX_FORM[] = " __S3FS_UNEXISTED_PATH_%lx__ / ";  // important space words for simply

//------------------------------------------------
// FdManager class variable
//------------------------------------------------
FdManager       FdManager::singleton;
std::mutex      FdManager::fd_manager_lock;
std::mutex      FdManager::cache_cleanup_lock;
std::mutex      FdManager::reserved_diskspace_lock;
std::mutex      FdManager::except_entmap_lock;
std::string     FdManager::cache_dir;
bool            FdManager::check_cache_dir_exist(false);
off_t           FdManager::free_disk_space = 0;
off_t           FdManager::fake_used_disk_space = 0;
std::string     FdManager::check_cache_output;
bool            FdManager::checked_lseek(false);
bool            FdManager::have_lseek_hole(false);
std::string     FdManager::tmp_dir = "/tmp";

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
        check_cache_output.clear();
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
    if(!FdManager::MakeCachePath(nullptr, cache_path, false)){
        return false;
    }
    if(!delete_files_in_dir(cache_path.c_str(), true)){
        return false;
    }

    std::string mirror_path = FdManager::cache_dir + "/." + S3fsCred::GetBucket() + ".mirror";
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
        return -errno;
    }
    if(0 != (result = CacheFileStat::DeleteCacheFileStat(path))){
        if(-ENOENT == result){
            S3FS_PRN_DBG("failed to delete stat file(%s): errno=%d", path, result);
        }else{
            S3FS_PRN_ERR("failed to delete stat file(%s): errno=%d", path, result);
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
        resolved_path += S3fsCred::GetBucket();
    }else{
        resolved_path += "/.";
        resolved_path += S3fsCred::GetBucket();
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
    std::string toppath(FdManager::cache_dir + "/" + S3fsCred::GetBucket());

    return check_exist_dir_permission(toppath.c_str());
}

bool FdManager::MakeRandomTempPath(const char* path, std::string& tmppath)
{
    char szBuff[64];

    snprintf(szBuff, sizeof(szBuff), NOCACHE_PATH_PREFIX_FORM, random());   // worry for performance, but maybe don't worry.
    szBuff[sizeof(szBuff) - 1] = '\0';                                      // for safety
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
    return IsDir(cache_dir);
}

off_t FdManager::GetEnsureFreeDiskSpaceHasLock()
{
    return FdManager::free_disk_space;
}

off_t FdManager::SetEnsureFreeDiskSpace(off_t size)
{
    const std::lock_guard<std::mutex> lock(FdManager::reserved_diskspace_lock);
    off_t old = FdManager::free_disk_space;
    FdManager::free_disk_space = size;
    return old;
}

bool FdManager::InitFakeUsedDiskSize(off_t fake_freesize)
{
    const std::lock_guard<std::mutex> lock(FdManager::reserved_diskspace_lock);

    FdManager::fake_used_disk_space = 0;    // At first, clear this value because this value is used in GetFreeDiskSpaceHasLock.

    off_t actual_freesize = FdManager::GetFreeDiskSpaceHasLock(nullptr);

    if(fake_freesize < actual_freesize){
        FdManager::fake_used_disk_space = actual_freesize - fake_freesize;
    }else{
        FdManager::fake_used_disk_space = 0;
    }
    return true;
}

off_t FdManager::GetTotalDiskSpaceByRatio(int ratio)
{
    return FdManager::GetTotalDiskSpace(nullptr) * ratio / 100;
}

off_t FdManager::GetTotalDiskSpace(const char* path)
{
    struct statvfs vfsbuf;
    int result = FdManager::GetVfsStat(path, &vfsbuf);
    if(result == -1){
        return 0;
    }

    off_t actual_totalsize = vfsbuf.f_blocks * vfsbuf.f_frsize;

    return actual_totalsize;
}

off_t FdManager::GetFreeDiskSpaceHasLock(const char* path)
{
    struct statvfs vfsbuf;
    int result = FdManager::GetVfsStat(path, &vfsbuf);
    if(result == -1){
        return 0;
    }

    off_t actual_freesize = vfsbuf.f_bavail * vfsbuf.f_frsize;

    return (FdManager::fake_used_disk_space < actual_freesize ? (actual_freesize - FdManager::fake_used_disk_space) : 0);
}

int FdManager::GetVfsStat(const char* path, struct statvfs* vfsbuf){
    std::string ctoppath;
    if(!FdManager::cache_dir.empty()){
        ctoppath = FdManager::cache_dir + "/";
        ctoppath = get_exist_directory_path(ctoppath);    // existed directory
        if(ctoppath != "/"){
            ctoppath += "/";
        }
    }else{
        ctoppath = tmp_dir + "/";
    }
    if(path && '\0' != *path){
        ctoppath += path;
    }else{
        ctoppath += ".";
    }
    if(-1 == statvfs(ctoppath.c_str(), vfsbuf)){
        S3FS_PRN_ERR("could not get vfs stat by errno(%d)", errno);
        return -1;
    }

    return 0;
}

bool FdManager::IsSafeDiskSpace(const char* path, off_t size, bool withmsg)
{
    const std::lock_guard<std::mutex> lock(FdManager::reserved_diskspace_lock);

    off_t fsize = FdManager::GetFreeDiskSpaceHasLock(path);
    off_t needsize = size + FdManager::GetEnsureFreeDiskSpaceHasLock();

    if(fsize < needsize){
        if(withmsg){
            S3FS_PRN_EXIT("There is no enough disk space for used as cache(or temporary) directory by s3fs. Requires %.3f MB, already has %.3f MB.", static_cast<double>(needsize) / 1024 / 1024, static_cast<double>(fsize) / 1024 / 1024);
        }
        return false;
    }
    return true;
}

bool FdManager::HaveLseekHole()
{
    if(FdManager::checked_lseek){
        return FdManager::have_lseek_hole;
    }

    // create temporary file
    int fd;
    auto ptmpfp = MakeTempFile();
    if(nullptr == ptmpfp || -1 == (fd = fileno(ptmpfp.get()))){
        S3FS_PRN_ERR("failed to open temporary file by errno(%d)", errno);
        FdManager::checked_lseek   = true;
        FdManager::have_lseek_hole = false;
        return false;
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

    FdManager::checked_lseek   = true;
    FdManager::have_lseek_hole = result;
    return FdManager::have_lseek_hole;
}

bool FdManager::SetTmpDir(const char *dir)
{
    if(!dir || '\0' == dir[0]){
        tmp_dir = "/tmp";
    }else{
        tmp_dir = dir;
    }
    return true;
}

bool FdManager::IsDir(const std::string& dir)
{
    // check the directory
    struct stat st;
    if(0 != stat(dir.c_str(), &st)){
        S3FS_PRN_ERR("could not stat() directory %s by errno(%d).", dir.c_str(), errno);
        return false;
    }
    if(!S_ISDIR(st.st_mode)){
        S3FS_PRN_ERR("the directory %s is not a directory.", dir.c_str());
        return false;
    }
    return true;
}

bool FdManager::CheckTmpDirExist()
{
    if(FdManager::tmp_dir.empty()){
        return true;
    }
    return IsDir(tmp_dir);
}

std::unique_ptr<FILE, decltype(&s3fs_fclose)> FdManager::MakeTempFile() {
    int fd;
    char cfn[PATH_MAX];
    std::string fn = tmp_dir + "/s3fstmp.XXXXXX";
    strncpy(cfn, fn.c_str(), sizeof(cfn) - 1);
    cfn[sizeof(cfn) - 1] = '\0';

    fd = mkstemp(cfn);
    if (-1 == fd) {
        S3FS_PRN_ERR("failed to create tmp file. errno(%d)", errno);
        return {nullptr, &s3fs_fclose};
    }
    if (-1 == unlink(cfn)) {
        S3FS_PRN_ERR("failed to delete tmp file. errno(%d)", errno);
        return {nullptr, &s3fs_fclose};
    }
    return {fdopen(fd, "rb+"), &s3fs_fclose};
}

bool FdManager::HasOpenEntityFd(const char* path)
{
    const std::lock_guard<std::mutex> lock(FdManager::fd_manager_lock);

    const FdEntity* ent;
    int         fd = -1;
    if(nullptr == (ent = FdManager::singleton.GetFdEntityHasLock(path, fd, false))){
        return false;
    }
    return (0 < ent->GetOpenCount());
}

// [NOTE]
// Returns the number of open pseudo fd.
//
int FdManager::GetOpenFdCount(const char* path)
{
    const std::lock_guard<std::mutex> lock(FdManager::fd_manager_lock);

    return FdManager::singleton.GetPseudoFdCount(path);
}

//------------------------------------------------
// FdManager methods
//------------------------------------------------
FdManager::FdManager()
{
    if(this != FdManager::get()){
        abort();
    }
}

FdManager::~FdManager()
{
    if(this == FdManager::get()){
        for(auto iter = fent.cbegin(); fent.cend() != iter; ++iter){
            FdEntity* ent = (*iter).second.get();
            S3FS_PRN_WARN("To exit with the cache file opened: path=%s, refcnt=%d", ent->GetPath().c_str(), ent->GetOpenCount());
        }
        fent.clear();
        except_fent.clear();
    }else{
        abort();
    }
}

FdEntity* FdManager::GetFdEntityHasLock(const char* path, int& existfd, bool newfd)
{
    S3FS_PRN_INFO3("[path=%s][pseudo_fd=%d]", SAFESTRPTR(path), existfd);

    if(!path || '\0' == path[0]){
        return nullptr;
    }

    UpdateEntityToTempPath();

    auto fiter = fent.find(path);
    if(fent.cend() != fiter && fiter->second){
        if(-1 == existfd){
            if(newfd){
                existfd = fiter->second->OpenPseudoFd(O_RDWR);    // [NOTE] O_RDWR flags
            }
            return fiter->second.get();
        }else{
            if(fiter->second->FindPseudoFd(existfd)){
                if(newfd){
                    existfd = fiter->second->Dup(existfd);
                }
                return fiter->second.get();
            }
        }
    }

    if(-1 != existfd){
        for(auto iter = fent.cbegin(); iter != fent.cend(); ++iter){
            if(iter->second && iter->second->FindPseudoFd(existfd)){
                // found opened fd in map
                if(iter->second->GetPath() == path){
                    if(newfd){
                        existfd = iter->second->Dup(existfd);
                    }
                    return iter->second.get();
                }
                // found fd, but it is used another file(file descriptor is recycled)
                // so returns nullptr.
                break;
            }
        }
    }

    // If the cache directory is not specified, s3fs opens a temporary file
    // when the file is opened.
    if(!FdManager::IsCacheDir()){
        for(auto iter = fent.cbegin(); iter != fent.cend(); ++iter){
            if(iter->second && iter->second->IsOpen() && iter->second->GetPath() == path){
                return iter->second.get();
            }
        }
    }
    return nullptr;
}

FdEntity* FdManager::Open(int& fd, const char* path, const headers_t* pmeta, off_t size, const struct timespec& ts_mctime, int flags, bool force_tmpfile, bool is_create, bool ignore_modify)
{
    S3FS_PRN_DBG("[path=%s][size=%lld][ts_mctime=%s][flags=0x%x][force_tmpfile=%s][create=%s][ignore_modify=%s]", SAFESTRPTR(path), static_cast<long long>(size), str(ts_mctime).c_str(), flags, (force_tmpfile ? "yes" : "no"), (is_create ? "yes" : "no"), (ignore_modify ? "yes" : "no"));

    if(!path || '\0' == path[0]){
        return nullptr;
    }

    const std::lock_guard<std::mutex> lock(FdManager::fd_manager_lock);

    UpdateEntityToTempPath();

    // search in mapping by key(path)
    auto iter = fent.find(path);
    if(fent.end() == iter && !force_tmpfile && !FdManager::IsCacheDir()){
        // If the cache directory is not specified, s3fs opens a temporary file
        // when the file is opened.
        // Then if it could not find a entity in map for the file, s3fs should
        // search a entity in all which opened the temporary file.
        //
        for(iter = fent.begin(); iter != fent.end(); ++iter){
            if(iter->second && iter->second->IsOpen() && iter->second->GetPath() == path){
                break;      // found opened fd in mapping
            }
        }
    }

    if(fent.end() != iter){
        // found
        FdEntity* ent = iter->second.get();

        // [NOTE]
        // If the file is being modified and ignore_modify flag is false,
        // the file size will not be changed even if there is a request
        // to reduce the size of the modified file.
        // If you do, the "test_open_second_fd" test will fail.
        //
        if(!ignore_modify && ent->IsModified()){
            // If the file is being modified and it's size is larger than size parameter, it will not be resized.
            off_t cur_size = 0;
            if(ent->GetSize(cur_size) && size <= cur_size){
                size = -1;
            }
        }

        // (re)open
        if(0 > (fd = ent->Open(pmeta, size, ts_mctime, flags))){
            S3FS_PRN_ERR("failed to (re)open and create new pseudo fd for path(%s).", path);
            return nullptr;
        }

        return ent;
    }else if(is_create){
        // not found
        std::string cache_path;
        if(!force_tmpfile && !FdManager::MakeCachePath(path, cache_path, true)){
            S3FS_PRN_ERR("failed to make cache path for object(%s).", path);
            return nullptr;
        }
        // make new obj
        auto ent = std::make_shared<FdEntity>(path, cache_path.c_str());

        // open
        if(0 > (fd = ent->Open(pmeta, size, ts_mctime, flags))){
            S3FS_PRN_ERR("failed to open and create new pseudo fd for path(%s) errno:%d.", path, fd);
            return nullptr;
        }

        if(!cache_path.empty()){
            // using cache
            return (fent[path] = std::move(ent)).get();
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
            return (fent[tmppath] = std::move(ent)).get();
        }
    }else{
        return nullptr;
    }
}

// [NOTE]
// This method does not create a new pseudo fd.
// It just finds existfd and returns the corresponding entity.
//
FdEntity* FdManager::GetExistFdEntity(const char* path, int existfd)
{
    S3FS_PRN_DBG("[path=%s][pseudo_fd=%d]", SAFESTRPTR(path), existfd);

    const std::lock_guard<std::mutex> lock(FdManager::fd_manager_lock);

    UpdateEntityToTempPath();

    // search from all entity.
    for(auto iter = fent.cbegin(); iter != fent.cend(); ++iter){
        if(iter->second && iter->second->FindPseudoFd(existfd)){
            // found existfd in entity
            return iter->second.get();
        }
    }
    // not found entity
    return nullptr;
}

FdEntity* FdManager::OpenExistFdEntity(const char* path, int& fd, int flags)
{
    S3FS_PRN_DBG("[path=%s][flags=0x%x]", SAFESTRPTR(path), flags);

    // search entity by path, and create pseudo fd
    FdEntity* ent = Open(fd, path, nullptr, -1, S3FS_OMIT_TS, flags, false, false, false);
    if(!ent){
        // Not found entity
        return nullptr;
    }
    return ent;
}

int FdManager::GetPseudoFdCount(const char* path)
{
    S3FS_PRN_DBG("[path=%s]", SAFESTRPTR(path));

    if(!path || '\0' == path[0]){
        return 0;
    }

    UpdateEntityToTempPath();

    // search from all entity.
    for(auto iter = fent.cbegin(); iter != fent.cend(); ++iter){
        if(iter->second && iter->second->GetPath() == path){
            // found the entity for the path
            return iter->second->GetOpenCount();
        }
    }
    // not found entity
    return 0;
}

void FdManager::Rename(const std::string &from, const std::string &to)
{
    const std::lock_guard<std::mutex> lock(FdManager::fd_manager_lock);

    UpdateEntityToTempPath();

    auto iter = fent.find(from);
    if(fent.end() == iter && !FdManager::IsCacheDir()){
        // If the cache directory is not specified, s3fs opens a temporary file
        // when the file is opened.
        // Then if it could not find a entity in map for the file, s3fs should
        // search a entity in all which opened the temporary file.
        //
        for(iter = fent.begin(); iter != fent.end(); ++iter){
            if(iter->second && iter->second->IsOpen() && iter->second->GetPath() == from){
                break;              // found opened fd in mapping
            }
        }
    }

    if(fent.end() != iter){
        // found
        S3FS_PRN_DBG("[from=%s][to=%s]", from.c_str(), to.c_str());

        auto ent(std::move(iter->second));

        // retrieve old fd entity from map
        fent.erase(iter);

        // rename path and caches in fd entity
        std::string fentmapkey;
        if(!ent->RenamePath(to, fentmapkey)){
            S3FS_PRN_ERR("Failed to rename FdEntity object for %s to %s", from.c_str(), to.c_str());
            return;
        }

        // set new fd entity to map
        fent[fentmapkey] = std::move(ent);
    }
}

bool FdManager::Close(FdEntity* ent, int fd)
{
    S3FS_PRN_DBG("[ent->file=%s][pseudo_fd=%d]", ent ? ent->GetPath().c_str() : "", fd);

    if(!ent || -1 == fd){
        return true;  // returns success
    }
    const std::lock_guard<std::mutex> lock(FdManager::fd_manager_lock);

    UpdateEntityToTempPath();

    for(auto iter = fent.cbegin(); iter != fent.cend(); ++iter){
        if(iter->second.get() == ent){
            ent->Close(fd);
            if(!ent->IsOpen()){
                // remove found entity from map.
                iter = fent.erase(iter);

                // check another key name for entity value to be on the safe side
                for(; iter != fent.cend(); ){
                    if(iter->second.get() == ent){
                        iter = fent.erase(iter);
                    }else{
                        ++iter;
                    }
                }
            }
            return true;
        }
    }
    return false;
}

bool FdManager::ChangeEntityToTempPath(std::shared_ptr<FdEntity> ent, const char* path)
{
    const std::lock_guard<std::mutex> lock(FdManager::except_entmap_lock);
    except_fent[path] = std::move(ent);
    return true;
}

bool FdManager::UpdateEntityToTempPath()
{
    const std::lock_guard<std::mutex> lock(FdManager::except_entmap_lock);

    for(auto except_iter = except_fent.cbegin(); except_iter != except_fent.cend(); ){
        std::string tmppath;
        FdManager::MakeRandomTempPath(except_iter->first.c_str(), tmppath);

        auto iter = fent.find(except_iter->first);
        if(fent.cend() != iter && iter->second.get() == except_iter->second.get()){
            // Move the entry to the new key
            fent[tmppath] = std::move(iter->second);
            fent.erase(iter);
            except_iter   = except_fent.erase(except_iter);
        }else{
            // [NOTE]
            // ChangeEntityToTempPath method is called and the FdEntity pointer
            // set into except_fent is mapped into fent.
            // And since this method is always called before manipulating fent,
            // it will not enter here.
            // Thus, if it enters here, a warning is output.
            //
            S3FS_PRN_WARN("For some reason the FdEntity pointer(for %s) is not found in the fent map. Recovery procedures are being performed, but the cause needs to be identified.", except_iter->first.c_str());

            // Add the entry for recovery procedures
            fent[tmppath] = except_iter->second;
            except_iter   = except_fent.erase(except_iter);
        }
    }
    return true;
}

void FdManager::CleanupCacheDir()
{
    //S3FS_PRN_DBG("cache cleanup requested");

    if(!FdManager::IsCacheDir()){
        return;
    }

    if(FdManager::cache_cleanup_lock.try_lock()){
        //S3FS_PRN_DBG("cache cleanup started");
        CleanupCacheDirInternal("");
        //S3FS_PRN_DBG("cache cleanup ended");
    }else{
        // wait for other thread to finish cache cleanup
        FdManager::cache_cleanup_lock.lock();
    }
    FdManager::cache_cleanup_lock.unlock();
}

void FdManager::CleanupCacheDirInternal(const std::string &path)
{
    DIR*           dp;
    struct dirent* dent;
    std::string    abs_path = cache_dir + "/" + S3fsCred::GetBucket() + path;

    if(nullptr == (dp = opendir(abs_path.c_str()))){
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
            if(!FdManager::fd_manager_lock.try_lock()){
                S3FS_PRN_INFO("could not get fd_manager_lock when clean up file(%s), then skip it.", next_path.c_str());
                continue;
            }
            UpdateEntityToTempPath();

            auto iter = fent.find(next_path);
            if(fent.cend() == iter) {
                S3FS_PRN_DBG("cleaned up: %s", next_path.c_str());
                FdManager::DeleteCacheFile(next_path.c_str());
            }
            FdManager::fd_manager_lock.unlock();
        }
    }
    closedir(dp);
}

bool FdManager::ReserveDiskSpace(off_t size)
{
    if(IsSafeDiskSpace(nullptr, size)){
        const std::lock_guard<std::mutex> lock(FdManager::reserved_diskspace_lock);
        FdManager::free_disk_space += size;
        return true;
    }
    return false;
}

void FdManager::FreeReservedDiskSpace(off_t size)
{
    const std::lock_guard<std::mutex> lock(FdManager::reserved_diskspace_lock);
    FdManager::free_disk_space -= size;
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
    if(nullptr == (statsdir = opendir(target_dir.c_str()))){
        S3FS_PRN_ERR("Could not open directory(%s) by errno(%d)", target_dir.c_str(), errno);
        return false;
    }

    // loop in directory of cache file's stats
    const struct dirent* pdirent = nullptr;
    while(nullptr != (pdirent = readdir(statsdir))){
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
                const std::lock_guard<std::mutex> lock(FdManager::fd_manager_lock);

                UpdateEntityToTempPath();

                auto iter = fent.find(object_file_path);
                if(fent.cend() != iter){
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
            scope_guard guard([&]() { close(cache_file_fd); });

            // get inode number for cache file
            struct stat st;
            if(0 != fstat(cache_file_fd, &st)){
                ++err_file_cnt;
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_FILE_PROB, object_file_path.c_str(), strOpenedWarn.c_str());
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_CRIT_HEAD, "Could not get file inode number for cache file");

                continue;
            }
            ino_t cache_file_inode = st.st_ino;

            // open cache stat file and load page info.
            PageList      pagelist;
            CacheFileStat cfstat(object_file_path.c_str());
            if(!cfstat.ReadOnlyOpen() || !pagelist.Deserialize(cfstat, cache_file_inode)){
                ++err_file_cnt;
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_FILE_PROB, object_file_path.c_str(), strOpenedWarn.c_str());
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_CRIT_HEAD, "Could not load cache file stats information");

                continue;
            }
            cfstat.Release();

            // compare cache file size and stats information
            if(st.st_size != pagelist.Size()){
                ++err_file_cnt;
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_FILE_PROB, object_file_path.c_str(), strOpenedWarn.c_str());
                S3FS_PRN_CACHE(fp, CACHEDBG_FMT_CRIT_HEAD2 "The cache file size(%lld) and the value(%lld) from cache file stats are different", static_cast<long long int>(st.st_size), static_cast<long long int>(pagelist.Size()));

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
                    for(auto witer = warn_area_list.cbegin(); witer != warn_area_list.cend(); ++witer){
                        S3FS_PRN_CACHE(fp, CACHEDBG_FMT_PROB_BLOCK, static_cast<size_t>(witer->offset), static_cast<size_t>(witer->bytes));
                    }
                }
                if(!err_area_list.empty()){
                    ++err_file_cnt;
                    S3FS_PRN_CACHE(fp, CACHEDBG_FMT_ERR_HEAD);
                    for(auto eiter = err_area_list.cbegin(); eiter != err_area_list.cend(); ++eiter){
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

    std::unique_ptr<FILE, decltype(&s3fs_fclose)> pfp(nullptr, &s3fs_fclose);
    FILE* fp;
    if(FdManager::check_cache_output.empty()){
        fp = stdout;
    }else{
        pfp.reset(fp = fopen(FdManager::check_cache_output.c_str(), "a+"));
        if(nullptr == pfp){
            S3FS_PRN_ERR("Could not open(create) output file(%s) for checking all cache by errno(%d)", FdManager::check_cache_output.c_str(), errno);
            return false;
        }
    }

    // print head message
    S3FS_PRN_CACHE(fp, CACHEDBG_FMT_HEAD, S3fsLog::GetCurrentTime().c_str());

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
