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

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <climits>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

#include "common.h"
#include "s3fs.h"
#include "fdcache_entity.h"
#include "fdcache_fdinfo.h"
#include "fdcache_stat.h"
#include "fdcache_untreated.h"
#include "fdcache.h"
#include "string_util.h"
#include "s3fs_logger.h"
#include "s3fs_util.h"
#include "curl.h"
#include "curl_util.h"
#include "s3fs_cred.h"
#include "threadpoolman.h"
#include "s3fs_threadreqs.h"

//------------------------------------------------
// Symbols
//------------------------------------------------
static constexpr int MAX_MULTIPART_CNT         = 10'000; // S3 multipart max count

//------------------------------------------------
// FdEntity class variables
//------------------------------------------------
bool FdEntity::mixmultipart = true;
bool FdEntity::streamupload = false;

//------------------------------------------------
// FdEntity class methods
//------------------------------------------------
bool FdEntity::SetNoMixMultipart()
{
    bool old = mixmultipart;
    mixmultipart = false;
    return old;
}

bool FdEntity::SetStreamUpload(bool isstream)
{
    bool old = streamupload;
    streamupload = isstream;
    return old;
}

int FdEntity::FillFile(int fd, unsigned char byte, off_t size, off_t start)
{
    unsigned char bytes[1024 * 32];         // 32kb
    memset(bytes, byte, std::min(static_cast<off_t>(sizeof(bytes)), size));

    for(off_t total = 0, onewrote = 0; total < size; total += onewrote){
        if(-1 == (onewrote = pwrite(fd, bytes, std::min(static_cast<off_t>(sizeof(bytes)), size - total), start + total))){
            S3FS_PRN_ERR("pwrite failed. errno(%d)", errno);
            return -errno;
        }
    }
    return 0;
}

// [NOTE]
// If fd is wrong or something error is occurred, return 0.
// The ino_t is allowed zero, but inode 0 is not realistic.
// So this method returns 0 on error assuming the correct
// inode is never 0.
// The caller must have exclusive control.
//
ino_t FdEntity::GetInode(int fd)
{
    if(-1 == fd){
        S3FS_PRN_ERR("file descriptor is wrong.");
        return 0;
    }

    struct stat st;
    if(0 != fstat(fd, &st)){
        S3FS_PRN_ERR("could not get stat for physical file descriptor(%d) by errno(%d).", fd, errno);
        return 0;
    }
    return st.st_ino;
}

//------------------------------------------------
// FdEntity methods
//------------------------------------------------
FdEntity::FdEntity(const char* tpath, const char* cpath) :
    path(SAFESTRPTR(tpath)),
    physical_fd(-1), inode(0), size_orgmeta(0),
    cachepath(SAFESTRPTR(cpath)), pending_status(pending_status_t::NO_UPDATE_PENDING),
    ro_path(SAFESTRPTR(tpath))
{
    holding_mtime.tv_sec = -1;
    holding_mtime.tv_nsec = 0;
}

FdEntity::~FdEntity()
{
    Clear();
}

void FdEntity::Clear()
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);

    pseudo_fd_map.clear();

    if(-1 != physical_fd){
        if(!cachepath.empty()){
            // [NOTE]
            // Compare the inode of the existing cache file with the inode of
            // the cache file output by this object, and if they are the same,
            // serialize the pagelist.
            //
            ino_t cur_inode = GetInode();
            if(0 != cur_inode && cur_inode == inode){
                CacheFileStat cfstat(path.c_str());
                if(!pagelist.Serialize(cfstat, inode)){
                    S3FS_PRN_WARN("failed to save cache stat file(%s).", path.c_str());
                }
            }
        }
        pfile.reset();
        physical_fd = -1;
        inode       = 0;

        if(!mirrorpath.empty()){
            if(-1 == unlink(mirrorpath.c_str())){
                S3FS_PRN_WARN("failed to remove mirror cache file(%s) by errno(%d).", mirrorpath.c_str(), errno);
            }
            mirrorpath.clear();
        }
    }
    pagelist.Init(0, false, false);
    path      = "";
    cachepath = "";

    // set backup(read only) variable
    const std::lock_guard<std::mutex> ro_lock(ro_path_lock);
    ro_path   = path;
}

// [NOTE]
// This method returns the inode of the file in cachepath.
// The return value is the same as the class method GetInode().
// The caller must have exclusive control.
//
ino_t FdEntity::GetInode() const
{
    if(cachepath.empty()){
        S3FS_PRN_INFO("cache file path is empty, then return inode as 0.");
        return 0;
    }

    struct stat st;
    if(0 != stat(cachepath.c_str(), &st)){
        S3FS_PRN_INFO("could not get stat for file(%s) by errno(%d).", cachepath.c_str(), errno);
        return 0;
    }
    return st.st_ino;
}

void FdEntity::Close(int fd)
{
    const std::lock_guard<std::mutex> lock(fdent_lock);

    S3FS_PRN_DBG("[path=%s][pseudo_fd=%d][physical_fd=%d]", path.c_str(), fd, physical_fd);

    // search pseudo fd and close it.
    auto iter = pseudo_fd_map.find(fd);
    if(pseudo_fd_map.cend() != iter){
        pseudo_fd_map.erase(iter);
    }else{
        S3FS_PRN_WARN("Not found pseudo_fd(%d) in entity object(%s)", fd, path.c_str());
    }

    // check pseudo fd count
    if(-1 != physical_fd && 0 == GetOpenCountHasLock()){
        const std::lock_guard<std::mutex> data_lock(fdent_data_lock);
        if(!cachepath.empty()){
            // [NOTE]
            // Compare the inode of the existing cache file with the inode of
            // the cache file output by this object, and if they are the same,
            // serialize the pagelist.
            //
            ino_t cur_inode = GetInode();
            if(0 != cur_inode && cur_inode == inode){
                CacheFileStat cfstat(path.c_str());
                if(!pagelist.Serialize(cfstat, inode)){
                    S3FS_PRN_WARN("failed to save cache stat file(%s).", path.c_str());
                }
            }
        }
        pfile.reset();
        physical_fd = -1;
        inode       = 0;

        if(!mirrorpath.empty()){
            if(-1 == unlink(mirrorpath.c_str())){
                S3FS_PRN_WARN("failed to remove mirror cache file(%s) by errno(%d).", mirrorpath.c_str(), errno);
            }
            mirrorpath.clear();
        }
    }
}

int FdEntity::DupWithLock(int fd)
{
    S3FS_PRN_DBG("[path=%s][pseudo_fd=%d][physical_fd=%d][pseudo fd count=%zu]", path.c_str(), fd, physical_fd, pseudo_fd_map.size());

    if(-1 == physical_fd){
        return -1;
    }
    auto iter = pseudo_fd_map.find(fd);
    if(pseudo_fd_map.cend() == iter){
        S3FS_PRN_ERR("Not found pseudo_fd(%d) in entity object(%s) for physical_fd(%d)", fd, path.c_str(), physical_fd);
        return -1;
    }
    const PseudoFdInfo* org_pseudoinfo = iter->second.get();
    auto ppseudoinfo = std::make_unique<PseudoFdInfo>(physical_fd, (org_pseudoinfo ? org_pseudoinfo->GetFlags() : 0));
    int             pseudo_fd      = ppseudoinfo->GetPseudoFd();
    pseudo_fd_map[pseudo_fd]       = std::move(ppseudoinfo);

    return pseudo_fd;
}

int FdEntity::OpenPseudoFd(int flags)
{
    const std::lock_guard<std::mutex> lock(fdent_lock);

    S3FS_PRN_DBG("[path=%s][physical_fd=%d][pseudo fd count=%zu]", path.c_str(), physical_fd, pseudo_fd_map.size());

    if(-1 == physical_fd){
        return -1;
    }
    auto ppseudoinfo = std::make_unique<PseudoFdInfo>(physical_fd, flags);
    int             pseudo_fd   = ppseudoinfo->GetPseudoFd();
    pseudo_fd_map[pseudo_fd]    = std::move(ppseudoinfo);

    return pseudo_fd;
}

int FdEntity::GetOpenCountHasLock() const
{
    return static_cast<int>(pseudo_fd_map.size());
}

//
// Open mirror file which is linked cache file.
//
int FdEntity::OpenMirrorFile()
{
    if(cachepath.empty()){
        S3FS_PRN_ERR("cache path is empty, why come here");
        return -EIO;
    }

    // make temporary directory
    std::string bupdir;
    if(!FdManager::MakeCachePath(nullptr, bupdir, true, true)){
        S3FS_PRN_ERR("could not make bup cache directory path or create it.");
        return -EIO;
    }

    // create seed generating mirror file name
    auto seed = static_cast<unsigned int>(time(nullptr));
    int urandom_fd;
    if(-1 != (urandom_fd = open("/dev/urandom", O_RDONLY))){
        unsigned int rand_data;
        if(sizeof(rand_data) == read(urandom_fd, &rand_data, sizeof(rand_data))){
            seed ^= rand_data;
        }
        close(urandom_fd);
    }

    // try to link mirror file
    while(true){
        // make random(temp) file path
        // (do not care for threading, because allowed any value returned.)
        //
        char         szfile[NAME_MAX + 1];
        snprintf(szfile, sizeof(szfile), "%x.tmp", rand_r(&seed));
        szfile[NAME_MAX] = '\0';                            // for safety
        mirrorpath = bupdir + "/" + szfile;

        // link mirror file to cache file
        if(0 == link(cachepath.c_str(), mirrorpath.c_str())){
            break;
        }
        if(EEXIST != errno){
            S3FS_PRN_ERR("could not link mirror file(%s) to cache file(%s) by errno(%d).", mirrorpath.c_str(), cachepath.c_str(), errno);
            return -errno;
        }
        ++seed;
    }

    // open mirror file
    int mirrorfd;
    if(-1 == (mirrorfd = open(mirrorpath.c_str(), O_RDWR))){
        S3FS_PRN_ERR("could not open mirror file(%s) by errno(%d).", mirrorpath.c_str(), errno);
        return -errno;
    }
    return mirrorfd;
}

bool FdEntity::FindPseudoFdWithLock(int fd) const
{
    if(-1 == fd){
        return false;
    }
    if(pseudo_fd_map.cend() == pseudo_fd_map.find(fd)){
        return false;
    }
    return true;
}

PseudoFdInfo* FdEntity::CheckPseudoFdFlags(int fd, bool writable)
{
    if(-1 == fd){
        return nullptr;
    }
    auto iter = pseudo_fd_map.find(fd);
    if(pseudo_fd_map.cend() == iter || nullptr == iter->second){
        return nullptr;
    }
    if(writable){
        if(!iter->second->Writable()){
            return nullptr;
        }
    }else{
        if(!iter->second->Readable()){
            return nullptr;
        }
    }
    return iter->second.get();
}

bool FdEntity::IsUploading()
{
    for(auto iter = pseudo_fd_map.cbegin(); iter != pseudo_fd_map.cend(); ++iter){
        const PseudoFdInfo* ppseudoinfo = iter->second.get();
        if(ppseudoinfo && ppseudoinfo->IsUploading()){
            return true;
        }
    }
    return false;
}

// [NOTE]
// If the open is successful, returns pseudo fd.
// If it fails, it returns an error code with a negative value.
//
// ts_mctime argument is a variable for mtime/ctime.
// If you want to disable this variable, specify UTIME_OMIT for
// tv_nsec in timespec member(in this case tv_sec member is ignored).
// This is similar to utimens operation.
// You can use "S3FS_OMIT_TS" global variable for UTIME_OMIT.
//
int FdEntity::Open(const headers_t* pmeta, off_t size, const struct timespec& ts_mctime, int flags)
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);

    S3FS_PRN_DBG("[path=%s][physical_fd=%d][size=%lld][ts_mctime=%s][flags=0x%x]", path.c_str(), physical_fd, static_cast<long long>(size), str(ts_mctime).c_str(), flags);

    // [NOTE]
    // When the file size is incremental by truncating, it must be keeped
    // as an untreated area, and this area is set to these variables.
    //
    off_t truncated_start = 0;
    off_t truncated_size  = 0;

    if(-1 != physical_fd){
        //
        // already open file
        //

        // check only file size(do not need to save cfs and time.
        if(0 <= size && pagelist.Size() != size){
            // truncate temporary file size
            if(-1 == ftruncate(physical_fd, size) || -1 == fsync(physical_fd)){
                S3FS_PRN_ERR("failed to truncate temporary file(physical_fd=%d) by errno(%d).", physical_fd, errno);
                return -errno;
            }
            // resize page list
            if(!pagelist.Resize(size, false, true)){      // Areas with increased size are modified
                S3FS_PRN_ERR("failed to truncate temporary file information(physical_fd=%d).", physical_fd);
                return -EIO;
            }
        }

        // set untreated area
        if(0 <= size && size_orgmeta < size){
            // set untreated area
            truncated_start = size_orgmeta;
            truncated_size  = size - size_orgmeta;
        }

        // set original headers and set size.
        off_t new_size = (0 <= size ? size : size_orgmeta);
        if(pmeta){
            orgmeta  = *pmeta;
            size_orgmeta = get_size(orgmeta);
        }
        size_orgmeta = std::min(new_size, size_orgmeta);

    }else{
        //
        // file is not opened yet
        //
        bool  need_save_csf = false;  // need to save(reset) cache stat file
        bool  is_truncate   = false;  // need to truncate

        std::unique_ptr<CacheFileStat> pcfstat;

        if(!cachepath.empty()){
            // using cache
            struct stat st;
            if(stat(cachepath.c_str(), &st) == 0){
                if(0 > compare_timespec(st, stat_time_type::MTIME, ts_mctime)){
                    S3FS_PRN_DBG("cache file stale, removing: %s", cachepath.c_str());
                    if(unlink(cachepath.c_str()) != 0){
                        return (0 == errno ? -EIO : -errno);
                    }
                }
            }

            // open cache and cache stat file, load page info.
            pcfstat = std::make_unique<CacheFileStat>(path.c_str());

            // try to open cache file
            if( -1 != (physical_fd = open(cachepath.c_str(), O_RDWR)) &&
                0 != (inode = FdEntity::GetInode(physical_fd))        &&
                pagelist.Deserialize(*pcfstat, inode))
            {
                // succeed to open cache file and to load stats data
                st = {};
                if(-1 == fstat(physical_fd, &st)){
                    S3FS_PRN_ERR("fstat is failed. errno(%d)", errno);
                    physical_fd = -1;
                    inode       = 0;
                    return (0 == errno ? -EIO : -errno);
                }
                // check size, st_size, loading stat file
                if(-1 == size){
                    if(st.st_size != pagelist.Size()){
                        pagelist.Resize(st.st_size, false, true); // Areas with increased size are modified
                        need_save_csf = true;                     // need to update page info
                    }
                    size = st.st_size;
                }else{
                    // First if the current cache file size and pagelist do not match, fix pagelist.
                    if(st.st_size != pagelist.Size()){
                        pagelist.Resize(st.st_size, false, true); // Areas with increased size are modified
                        need_save_csf = true;                     // need to update page info
                    }
                    if(size != pagelist.Size()){
                        pagelist.Resize(size, false, true);       // Areas with increased size are modified
                        need_save_csf = true;                     // need to update page info
                    }
                    if(size != st.st_size){
                        is_truncate = true;
                    }
                }

            }else{
                if(-1 != physical_fd){
                    close(physical_fd);
                }
                inode = 0;

                // could not open cache file or could not load stats data, so initialize it.
                if(-1 == (physical_fd = open(cachepath.c_str(), O_CREAT|O_RDWR|O_TRUNC, 0600))){
                    S3FS_PRN_ERR("failed to open file(%s). errno(%d)", cachepath.c_str(), errno);

                    // remove cache stat file if it is existed
                    int result;
                    if(0 != (result = CacheFileStat::DeleteCacheFileStat(path.c_str()))){
                        if(-ENOENT != result){
                            S3FS_PRN_WARN("failed to delete current cache stat file(%s) by errno(%d), but continue...", path.c_str(), result);
                        }
                    }
                    return result;
                }
                need_save_csf = true;       // need to update page info
                inode         = FdEntity::GetInode(physical_fd);
                if(-1 == size){
                    size = 0;
                    pagelist.Init(0, false, false);
                }else{
                    // [NOTE]
                    // The modify flag must not be set when opening a file,
                    // if the ts_mctime parameter(mtime) is specified(tv_nsec != UTIME_OMIT)
                    // and the cache file does not exist.
                    // If mtime is specified for the file and the cache file
                    // mtime is older than it, the cache file is removed and
                    // the processing comes here.
                    //
                    pagelist.Resize(size, false, (UTIME_OMIT == ts_mctime.tv_nsec ? true : false));

                    is_truncate = true;
                }
            }

            // open mirror file
            int mirrorfd;
            if(0 >= (mirrorfd = OpenMirrorFile())){
                S3FS_PRN_ERR("failed to open mirror file linked cache file(%s).", cachepath.c_str());
                return (0 == mirrorfd ? -EIO : mirrorfd);
            }
            // switch fd
            close(physical_fd);
            physical_fd = mirrorfd;

            // make file pointer(for being same tmpfile)
            if(nullptr == (pfile = {fdopen(physical_fd, "wb"), &s3fs_fclose})){
                int saved_errno = errno;
                S3FS_PRN_ERR("failed to get fileno(%s). errno(%d)", cachepath.c_str(), errno);
                close(physical_fd);
                errno = saved_errno;
                physical_fd = -1;
                inode       = 0;
                return (0 == errno ? -EIO : -errno);
            }

        }else{
            // not using cache
            inode = 0;

            // open temporary file
            auto tmpfile = FdManager::MakeTempFile();
            if(nullptr == tmpfile || -1 ==(physical_fd = fileno(tmpfile.get()))){
                S3FS_PRN_ERR("failed to open temporary file by errno(%d)", errno);
                return (0 == errno ? -EIO : -errno);
            }
            pfile = std::move(tmpfile);
            if(-1 == size){
                size = 0;
                pagelist.Init(0, false, false);
            }else{
                // [NOTE]
                // The modify flag must not be set when opening a file,
                // if the ts_mctime parameter(mtime) is specified(tv_nsec != UTIME_OMIT)
                // and the cache file does not exist.
                // If mtime is specified for the file and the cache file
                // mtime is older than it, the cache file is removed and
                // the processing comes here.
                //
                pagelist.Resize(size, false, (UTIME_OMIT == ts_mctime.tv_nsec ? true : false));

                is_truncate = true;
            }
        }

        // truncate cache(tmp) file
        if(is_truncate){
            if(0 != ftruncate(physical_fd, size) || 0 != fsync(physical_fd)){
                S3FS_PRN_ERR("ftruncate(%s) or fsync returned err(%d)", cachepath.c_str(), errno);
                pfile.reset();
                physical_fd = -1;
                inode       = 0;
                return (0 == errno ? -EIO : -errno);
            }
        }

        // reset cache stat file
        if(need_save_csf && pcfstat.get()){
            if(!pagelist.Serialize(*pcfstat, inode)){
                S3FS_PRN_WARN("failed to save cache stat file(%s), but continue...", path.c_str());
            }
        }

        // set original headers and size in it.
        if(pmeta){
            orgmeta      = *pmeta;
            size_orgmeta = get_size(orgmeta);
        }else{
            orgmeta.clear();
            size_orgmeta = 0;
        }

        // set untreated area
        if(0 <= size && size_orgmeta < size){
            truncated_start = size_orgmeta;
            truncated_size  = size - size_orgmeta;
        }

        // set mtime and ctime(set "x-amz-meta-mtime" and "x-amz-meta-ctime" in orgmeta)
        if(UTIME_OMIT != ts_mctime.tv_nsec){
            if(0 != SetMCtimeHasLock(ts_mctime, ts_mctime)){
                S3FS_PRN_ERR("failed to set mtime/ctime. errno(%d)", errno);
                pfile.reset();
                physical_fd = -1;
                inode       = 0;
                return (0 == errno ? -EIO : -errno);
            }
        }
    }

    // create new pseudo fd, and set it to map
    auto ppseudoinfo = std::make_unique<PseudoFdInfo>(physical_fd, flags);
    int             pseudo_fd   = ppseudoinfo->GetPseudoFd();
    pseudo_fd_map[pseudo_fd]    = std::move(ppseudoinfo);

    // if there is untreated area, set it to pseudo object.
    if(0 < truncated_size){
        if(!AddUntreated(truncated_start, truncated_size)){
            pseudo_fd_map.erase(pseudo_fd);
            pfile.reset();
        }
    }

    return pseudo_fd;
}

// [NOTE]
// This method is called for only nocopyapi functions.
// So we do not check disk space for this option mode, if there is not enough
// disk space this method will be failed.
//
bool FdEntity::LoadAll(int fd, off_t* size, bool force_load)
{
    const std::lock_guard<std::mutex> lock(fdent_lock);

    S3FS_PRN_INFO3("[path=%s][pseudo_fd=%d][physical_fd=%d]", path.c_str(), fd, physical_fd);

    if(-1 == physical_fd || !FindPseudoFdWithLock(fd)){
        S3FS_PRN_ERR("pseudo_fd(%d) and physical_fd(%d) for path(%s) is not opened yet", fd, physical_fd, path.c_str());
        return false;
    }

    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);

    if(force_load){
        if(!SetAllStatusUnloaded()){
            return false;
        }
    }
    //
    // TODO: possibly do background for delay loading
    //
    int result;
    if(0 != (result = Load(/*start=*/ 0, /*size=*/ 0))){
        S3FS_PRN_ERR("could not download, result(%d)", result);
        return false;
    }
    if(size){
        *size = pagelist.Size();
    }
    return true;
}

//
// Rename file path.
//
// This method sets the FdManager::fent map registration key to fentmapkey.
//
// [NOTE]
// This method changes the file path of FdEntity.
// Old file is deleted after linking to the new file path, and this works
// without problem because the file descriptor is not affected even if the
// cache file is open.
// The mirror file descriptor is also the same. The mirror file path does
// not need to be changed and will remain as it is.
//
bool FdEntity::RenamePath(const std::string& newpath, std::string& fentmapkey)
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);

    if(!cachepath.empty()){
        // has cache path

        // make new cache path
        std::string newcachepath;
        if(!FdManager::MakeCachePath(newpath.c_str(), newcachepath, true)){
          S3FS_PRN_ERR("failed to make cache path for object(%s).", newpath.c_str());
          return false;
        }

        // rename cache file
        if(-1 == rename(cachepath.c_str(), newcachepath.c_str())){
          S3FS_PRN_ERR("failed to rename old cache path(%s) to new cache path(%s) by errno(%d).", cachepath.c_str(), newcachepath.c_str(), errno);
          return false;
        }

        // link and unlink cache file stat
        if(!CacheFileStat::RenameCacheFileStat(path.c_str(), newpath.c_str())){
          S3FS_PRN_ERR("failed to rename cache file stat(%s to %s).", path.c_str(), newpath.c_str());
          return false;
        }
        fentmapkey = newpath;
        cachepath  = newcachepath;

    }else{
        // does not have cache path
        fentmapkey.clear();
        FdManager::MakeRandomTempPath(newpath.c_str(), fentmapkey);
    }
    // set new path
    path = newpath;

    // set backup(read only) variable
    const std::lock_guard<std::mutex> ro_lock(ro_path_lock);
    ro_path = path;

    return true;
}

bool FdEntity::IsModified() const
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);
    return pagelist.IsModified();
}

bool FdEntity::GetStatsHasLock(struct stat& st) const
{
    if(-1 == physical_fd){
        return false;
    }

    st = {};
    if(-1 == fstat(physical_fd, &st)){
        S3FS_PRN_ERR("fstat failed. errno(%d)", errno);
        return false;
    }
    return true;
}

int FdEntity::SetCtimeHasLock(struct timespec time)
{
    S3FS_PRN_INFO3("[path=%s][physical_fd=%d][time=%s]", path.c_str(), physical_fd, str(time).c_str());

    if(-1 == time.tv_sec){
        return 0;
    }
    orgmeta["x-amz-meta-ctime"] = str(time);
    return 0;
}

int FdEntity::SetAtimeHasLock(struct timespec time)
{
    S3FS_PRN_INFO3("[path=%s][physical_fd=%d][time=%s]", path.c_str(), physical_fd, str(time).c_str());

    if(-1 == time.tv_sec){
        return 0;
    }
    orgmeta["x-amz-meta-atime"] = str(time);
    return 0;
}

// [NOTE]
// This method updates mtime as well as ctime.
//
int FdEntity::SetMCtimeHasLock(struct timespec mtime, struct timespec ctime)
{
    S3FS_PRN_INFO3("[path=%s][physical_fd=%d][mtime=%s][ctime=%s]", path.c_str(), physical_fd, str(mtime).c_str(), str(ctime).c_str());

    if(mtime.tv_sec < 0 || ctime.tv_sec < 0){
        return 0;
    }

    if(-1 != physical_fd){
        struct timespec ts[2];
        ts[0].tv_sec  = mtime.tv_sec;
        ts[0].tv_nsec = mtime.tv_nsec;
        ts[1].tv_sec  = ctime.tv_sec;
        ts[1].tv_nsec = ctime.tv_nsec;
        if(-1 == futimens(physical_fd, ts)){
            S3FS_PRN_ERR("futimens failed. errno(%d)", errno);
            return -errno;
        }
    }else if(!cachepath.empty()){
        // not opened file yet.
        struct timespec ts[2];
        ts[0].tv_sec  = ctime.tv_sec;
        ts[0].tv_nsec = ctime.tv_nsec;
        ts[1].tv_sec  = mtime.tv_sec;
        ts[1].tv_nsec = mtime.tv_nsec;
        if(-1 == utimensat(AT_FDCWD, cachepath.c_str(), ts, 0)){
            S3FS_PRN_ERR("utimensat failed. errno(%d)", errno);
            return -errno;
        }
    }

    orgmeta["x-amz-meta-mtime"] = str(mtime);
    orgmeta["x-amz-meta-ctime"] = str(ctime);

    return 0;
}

bool FdEntity::UpdateCtime()
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    struct stat st;
    if(!GetStatsHasLock(st)){
        return false;
    }

    orgmeta["x-amz-meta-ctime"] = str_stat_time(st, stat_time_type::CTIME);

    return true;
}

bool FdEntity::UpdateAtime()
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    struct stat st;
    if(!GetStatsHasLock(st)){
        return false;
    }

    orgmeta["x-amz-meta-atime"] = str_stat_time(st, stat_time_type::ATIME);

    return true;
}

bool FdEntity::UpdateMtime(bool clear_holding_mtime)
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);

    if(0 <= holding_mtime.tv_sec){
        // [NOTE]
        // This conditional statement is very special.
        // If you copy a file with "cp -p" etc., utimens or chown will be
        // called after opening the file, after that call to write, flush.
        // If normally utimens are not called(cases like "cp" only), mtime
        // should be updated at the file flush.
        // Here, check the holding_mtime value to prevent mtime from being
        // overwritten.
        //
        if(clear_holding_mtime){
            if(!ClearHoldingMtime()){
                return false;
            }
            // [NOTE]
            // If come here after fdatasync has been processed, the file
            // content update has already taken place. However, the metadata
            // update is necessary and needs to be flagged in order to
            // perform it with flush,
            //
            pending_status = pending_status_t::UPDATE_META_PENDING;
        }
    }else{
        struct stat st;
        if(!GetStatsHasLock(st)){
            return false;
        }
        orgmeta["x-amz-meta-mtime"] = str_stat_time(st, stat_time_type::MTIME);
    }
    return true;
}

bool FdEntity::SetHoldingMtime(struct timespec mtime)
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);

    S3FS_PRN_INFO3("[path=%s][physical_fd=%d][mtime=%s]", path.c_str(), physical_fd, str(mtime).c_str());

    if(mtime.tv_sec < 0){
        return false;
    }
    holding_mtime = mtime;
    return true;
}

bool FdEntity::ClearHoldingMtime()
{
    if(holding_mtime.tv_sec < 0){
        return false;
    }
    struct stat st;
    if(!GetStatsHasLock(st)){
        return false;
    }
    if(-1 != physical_fd){
        struct timespec ts[2];
        struct timespec ts_ctime;

        ts[0].tv_sec  = holding_mtime.tv_sec;
        ts[0].tv_nsec = holding_mtime.tv_nsec;

        set_stat_to_timespec(st, stat_time_type::CTIME, ts_ctime);
        ts[1].tv_sec  = ts_ctime.tv_sec;
        ts[1].tv_nsec = ts_ctime.tv_nsec;

        if(-1 == futimens(physical_fd, ts)){
            S3FS_PRN_ERR("futimens failed. errno(%d)", errno);
            return false;
        }
    }else if(!cachepath.empty()){
        // not opened file yet.
        struct timespec ts[2];
        struct timespec ts_ctime;

        set_stat_to_timespec(st, stat_time_type::CTIME, ts_ctime);
        ts[0].tv_sec  = ts_ctime.tv_sec;
        ts[0].tv_nsec = ts_ctime.tv_nsec;

        ts[1].tv_sec  = holding_mtime.tv_sec;
        ts[1].tv_nsec = holding_mtime.tv_nsec;
        if(-1 == utimensat(AT_FDCWD, cachepath.c_str(), ts, 0)){
            S3FS_PRN_ERR("utimensat failed. errno(%d)", errno);
            return false;
        }
    }
    holding_mtime.tv_sec = -1;
    holding_mtime.tv_nsec = 0;

    return true;
}

bool FdEntity::GetSize(off_t& size) const
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    if(-1 == physical_fd){
        return false;
    }

    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);
    size = pagelist.Size();
    return true;
}

bool FdEntity::GetXattr(std::string& xattr) const
{
    const std::lock_guard<std::mutex> lock(fdent_lock);

    auto iter = orgmeta.find("x-amz-meta-xattr");
    if(iter == orgmeta.cend()){
        return false;
    }
    xattr = iter->second;
    return true;
}

bool FdEntity::SetXattr(const std::string& xattr)
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    orgmeta["x-amz-meta-xattr"] = xattr;
    return true;
}

bool FdEntity::SetModeHasLock(mode_t mode)
{
    orgmeta["x-amz-meta-mode"] = std::to_string(mode);
    return true;
}

bool FdEntity::SetUIdHasLock(uid_t uid)
{
    orgmeta["x-amz-meta-uid"] = std::to_string(uid);
    return true;
}

bool FdEntity::SetGIdHasLock(gid_t gid)
{
    orgmeta["x-amz-meta-gid"] = std::to_string(gid);
    return true;
}

bool FdEntity::SetContentType(const char* path)
{
    if(!path){
        return false;
    }
    const std::lock_guard<std::mutex> lock(fdent_lock);
    orgmeta["Content-Type"] = S3fsCurl::LookupMimeType(path);
    return true;
}

bool FdEntity::SetAllStatus(bool is_loaded)
{
    S3FS_PRN_INFO3("[path=%s][physical_fd=%d][%s]", path.c_str(), physical_fd, is_loaded ? "loaded" : "unloaded");

    if(-1 == physical_fd){
        return false;
    }

    // get file size
    struct stat st{};
    if(-1 == fstat(physical_fd, &st)){
        S3FS_PRN_ERR("fstat is failed. errno(%d)", errno);
        return false;
    }
    // Reinit
    pagelist.Init(st.st_size, is_loaded, false);

    return true;
}

int FdEntity::Load(off_t start, off_t size, bool is_modified_flag)
{
    S3FS_PRN_DBG("[path=%s][physical_fd=%d][offset=%lld][size=%lld]", path.c_str(), physical_fd, static_cast<long long int>(start), static_cast<long long int>(size));

    if(-1 == physical_fd){
        return -EBADF;
    }

    int result = 0;

    // check loaded area & load
    fdpage_list_t unloaded_list;
    if(0 < pagelist.GetUnloadedPages(unloaded_list, start, size)){
        for(auto iter = unloaded_list.cbegin(); iter != unloaded_list.cend(); ++iter){
            if(0 != size && start + size <= iter->offset){
                // reached end
                break;
            }
            // check loading size
            off_t need_load_size = 0;
            if(iter->offset < size_orgmeta){
                // original file size(on S3) is smaller than request.
                need_load_size = (iter->next() <= size_orgmeta ? iter->bytes : (size_orgmeta - iter->offset));
            }

            // download
            if(S3fsCurl::GetMultipartSize() <= need_load_size && !nomultipart){
                // parallel request
                result = parallel_get_object_request(path, physical_fd, iter->offset, need_load_size);
            }else{
                // single request
                if(0 < need_load_size){
                    result = get_object_request(path, physical_fd, iter->offset, need_load_size);
                }else{
                    result = 0;
                }
          }
          if(0 != result){
              break;
          }
          // Set loaded flag
          pagelist.SetPageLoadedStatus(iter->offset, iter->bytes, (is_modified_flag ? PageList::page_status::LOAD_MODIFIED : PageList::page_status::LOADED));
        }
        PageList::FreeList(unloaded_list);
    }
    return result;
}

// [NOTE]
// At no disk space for caching object.
// This method is downloading by dividing an object of the specified range
// and uploading by multipart after finishing downloading it.
//
// [NOTICE]
// Need to lock before calling this method.
//
int FdEntity::NoCacheLoadAndPost(PseudoFdInfo* pseudo_obj, off_t start, off_t size)
{
    int result = 0;

    S3FS_PRN_INFO3("[path=%s][physical_fd=%d][offset=%lld][size=%lld]", path.c_str(), physical_fd, static_cast<long long int>(start), static_cast<long long int>(size));

    if(!pseudo_obj){
        S3FS_PRN_ERR("Pseudo object is nullptr.");
        return -EIO;
    }

    if(-1 == physical_fd){
        return -EBADF;
    }

    // [NOTE]
    // This method calling means that the cache file is never used no more.
    //
    if(!cachepath.empty()){
        // remove cache files(and cache stat file)
        FdManager::DeleteCacheFile(path.c_str());
        // cache file path does not use no more.
        cachepath.clear();
        mirrorpath.clear();
    }

    // Change entity key in manager mapping
    FdManager::get()->ChangeEntityToTempPath(get_shared_ptr(), path.c_str());

    // open temporary file
    int tmpfd;
    auto ptmpfp = FdManager::MakeTempFile();
    if(nullptr == ptmpfp || -1 == (tmpfd = fileno(ptmpfp.get()))){
        S3FS_PRN_ERR("failed to open temporary file by errno(%d)", errno);
        return (0 == errno ? -EIO : -errno);
    }

    // loop uploading by multipart
    for(auto iter = pagelist.pages.begin(); iter != pagelist.pages.end(); ++iter){
        if(iter->end() < start){
            continue;
        }
        if(0 != size && start + size <= iter->offset){
            break;
        }
        // download each multipart size(default 10MB) in unit
        for(off_t oneread = 0, totalread = (iter->offset < start ? start : 0); totalread < iter->bytes; totalread += oneread){
            int   upload_fd = physical_fd;
            off_t offset    = iter->offset + totalread;
            oneread         = std::min(iter->bytes - totalread, S3fsCurl::GetMultipartSize());

            // check rest size is over minimum part size
            //
            // [NOTE]
            // If the final part size is smaller than 5MB, it is not allowed by S3 API.
            // For this case, if the previous part of the final part is not over 5GB,
            // we incorporate the final part to the previous part. If the previous part
            // is over 5GB, we want to even out the last part and the previous part.
            //
            if((iter->bytes - totalread - oneread) < MIN_MULTIPART_SIZE){
                if(FIVE_GB < iter->bytes - totalread){
                    oneread = (iter->bytes - totalread) / 2;
                }else{
                    oneread = iter->bytes - totalread;
                }
            }

            if(!iter->loaded){
                //
                // loading or initializing
                //
                upload_fd = tmpfd;

                // load offset & size
                size_t need_load_size = 0;
                if(size_orgmeta <= offset){
                    // all area is over of original size
                    need_load_size      = 0;
                }else{
                    if(size_orgmeta < (offset + oneread)){
                        // original file size(on S3) is smaller than request.
                        need_load_size    = size_orgmeta - offset;
                    }else{
                        need_load_size    = oneread;
                    }
                }
                size_t over_size      = oneread - need_load_size;

                // [NOTE]
                // truncate file to zero and set length to part offset + size
                // after this, file length is (offset + size), but file does not use any disk space.
                //
                if(-1 == ftruncate(tmpfd, 0) || -1 == ftruncate(tmpfd, (offset + oneread))){
                    S3FS_PRN_ERR("failed to truncate temporary file(physical_fd=%d).", tmpfd);
                    result = -EIO;
                    break;
                }

                // single area get request
                if(0 < need_load_size){
                    if(0 != (result = get_object_request(path, tmpfd, offset, oneread))){
                        S3FS_PRN_ERR("failed to get object(start=%lld, size=%lld) for file(physical_fd=%d).", static_cast<long long int>(offset), static_cast<long long int>(oneread), tmpfd);
                        break;
                    }
                }
                // initialize fd without loading
                if(0 < over_size){
                    if(0 != (result = FdEntity::FillFile(tmpfd, 0, over_size, offset + need_load_size))){
                        S3FS_PRN_ERR("failed to fill rest bytes for physical_fd(%d). errno(%d)", tmpfd, result);
                        break;
                    }
                }
            }else{
                // already loaded area
            }
            // single area upload by multipart upload
            if(0 != (result = NoCacheMultipartUploadRequest(pseudo_obj, upload_fd, offset, oneread))){
                S3FS_PRN_ERR("failed to multipart upload(start=%lld, size=%lld) for file(physical_fd=%d).", static_cast<long long int>(offset), static_cast<long long int>(oneread), upload_fd);
                break;
            }
        }
        if(0 != result){
            break;
        }

        // set loaded flag
        if(!iter->loaded){
            if(iter->offset < start){
                fdpage page(iter->offset, start - iter->offset, iter->loaded, false);
                iter->bytes -= (start - iter->offset);
                iter->offset = start;
                iter = pagelist.pages.insert(iter, page);
            }
            if(0 != size && start + size < iter->next()){
                fdpage page(iter->offset, start + size - iter->offset, true, false);
                iter->bytes -= (start + size - iter->offset);
                iter->offset = start + size;
                iter = pagelist.pages.insert(iter, page);
            }else{
                iter->loaded   = true;
                iter->modified = false;
            }
        }
    }
    if(0 == result){
        // compress pagelist
        pagelist.Compress();

        // fd data do empty
        if(-1 == ftruncate(physical_fd, 0)){
            S3FS_PRN_ERR("failed to truncate file(physical_fd=%d), but continue...", physical_fd);
        }
    }

    return result;
}

// [NOTE]
// If the request is successful, initialize upload_id.
//
int FdEntity::PreMultipartUploadRequest(PseudoFdInfo* pseudo_obj)
{
    if(!pseudo_obj){
        S3FS_PRN_ERR("Internal error, pseudo fd object pointer is null.");
        return -EIO;
    }

    int result;
    if(0 != (result = pseudo_obj->PreMultipartUploadRequest(path, orgmeta))){
        return result;
    }

    // Clear the dirty flag, because the meta data is updated.
    pending_status = pending_status_t::NO_UPDATE_PENDING;

    return 0;
}

// [NOTE]
// At no disk space for caching object.
// This method is starting multipart uploading.
//
int FdEntity::NoCachePreMultipartUploadRequest(PseudoFdInfo* pseudo_obj)
{
    if(!pseudo_obj){
        S3FS_PRN_ERR("Internal error, pseudo fd object pointer is null.");
        return -EIO;
    }

    // initialize multipart upload values
    pseudo_obj->ClearUploadInfo(true);

    int result;
    if(0 != (result = PreMultipartUploadRequest(pseudo_obj))){
        return result;
    }

    return 0;
}

// [NOTE]
// At no disk space for caching object.
// This method is uploading one part of multipart.
//
int FdEntity::NoCacheMultipartUploadRequest(PseudoFdInfo* pseudo_obj, int tgfd, off_t start, off_t size)
{
    if(-1 == tgfd || !pseudo_obj || !pseudo_obj->IsUploading()){
        S3FS_PRN_ERR("Need to initialize for multipart upload.");
        return -EIO;
    }

    // get upload id
    std::string upload_id;
    if(!pseudo_obj->GetUploadId(upload_id)){
        return -EIO;
    }

    // append new part and get it's etag string pointer
    etagpair* petag = nullptr;
    if(!pseudo_obj->AppendUploadPart(start, size, false, &petag)){
        return -EIO;
    }

    // request to thread
    int result;
    if(0 != (result = await_multipart_upload_part_request(path, tgfd, start, size, petag->part_num, upload_id, petag, false))){
        S3FS_PRN_ERR("Failed No Cache Multipart Upload Part Request by error(%d) [path=%s][upload_id=%s][fd=%d][start=%lld][size=%lld]", result, path.c_str(), upload_id.c_str(), tgfd, static_cast<long long int>(start), static_cast<long long int>(size));
        return result;
    }
    return 0;
}

// [NOTE]
// At no disk space for caching object.
// This method is finishing multipart uploading.
//
int FdEntity::NoCacheMultipartUploadComplete(PseudoFdInfo* pseudo_obj)
{
    // get upload id and etag list
    std::string upload_id;
    etaglist_t  parts;
    if(!pseudo_obj->GetUploadId(upload_id) || !pseudo_obj->GetEtaglist(parts)){
        return -EIO;
    }

    int result;
    if(0 != (result = complete_multipart_upload_request(path, upload_id, parts))){
        S3FS_PRN_ERR("failed to complete multipart upload by errno(%d)", result);
        untreated_list.ClearAll();
        pseudo_obj->ClearUploadInfo(); // clear multipart upload info

        int result2;
        if(0 != (result2 = abort_multipart_upload_request(path, upload_id))){
            S3FS_PRN_ERR("failed to abort multipart upload by errno(%d)", result2);
        }
        return result;
    }

    // clear multipart upload info
    untreated_list.ClearAll();
    pseudo_obj->ClearUploadInfo();

    return 0;
}

off_t FdEntity::BytesModified()
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);
    return pagelist.BytesModified();
}

// [NOTE]
// There are conditions that allow you to perform multipart uploads.
// 
// According to the AWS spec:
//  - 1 to 10,000 parts are allowed
//  - minimum size of parts is 5MB (except for the last part)
// 
// For example, if you set the minimum part size to 5MB, you can upload
// a maximum (5 * 10,000)MB file.
// The part size can be changed in MB units, then the maximum file size
// that can be handled can be further increased.
// Files smaller than the minimum part size will not be multipart uploaded,
// but will be uploaded as single part(normally).
//
int FdEntity::RowFlushHasLock(int fd, const char* tpath, bool force_sync)
{
    S3FS_PRN_INFO3("[tpath=%s][path=%s][pseudo_fd=%d][physical_fd=%d]", SAFESTRPTR(tpath), path.c_str(), fd, physical_fd);

    if(-1 == physical_fd){
        return -EBADF;
    }

    // check pseudo fd and its flag
    const auto miter = pseudo_fd_map.find(fd);
    if(pseudo_fd_map.cend() == miter || nullptr == miter->second){
        return -EBADF;
    }
    if(!miter->second->Writable() && !(miter->second->GetFlags() & O_CREAT)){
        // If the entity is opened read-only, it will end normally without updating.
        return 0;
    }
    PseudoFdInfo* pseudo_obj = miter->second.get();

    int result;
    if(!force_sync && !pagelist.IsModified() && !IsDirtyMetadata()){
        // nothing to update.
        return 0;
    }
    if(S3fsLog::IsS3fsLogDbg()){
        pagelist.Dump();
    }

    if(nomultipart){
        // No multipart upload
        if(!force_sync && !pagelist.IsModified()){
            // for only push pending headers
            result = UploadPendingHasLock(-1);
        }else{
            result = RowFlushNoMultipart(pseudo_obj, tpath);
        }
    }else if(FdEntity::streamupload){
        // Stream multipart upload
        result = RowFlushStreamMultipart(pseudo_obj, tpath);
    }else if(FdEntity::mixmultipart){
        // Mix multipart upload
        result = RowFlushMixMultipart(pseudo_obj, tpath);
    }else{
        // Normal multipart upload
        result = RowFlushMultipart(pseudo_obj, tpath);
    }

    // [NOTE]
    // if something went wrong, so if you are using a cache file,
    // the cache file may not be correct. So delete cache files.
    //
    if(0 != result && !cachepath.empty()){
        FdManager::DeleteCacheFile(tpath);
    }

    return result;
}

//
// ([TODO] This is a temporary modification till S3fsMultiCurl is deprecated.)
//
int FdEntity::RowFlushNoMultipart(const PseudoFdInfo* pseudo_obj, const char* tpath)
{
    S3FS_PRN_INFO3("[tpath=%s][path=%s][pseudo_fd=%d][physical_fd=%d]", SAFESTRPTR(tpath), path.c_str(), (pseudo_obj ? pseudo_obj->GetPseudoFd() : -1), physical_fd);

    if(-1 == physical_fd || !pseudo_obj){
        return -EBADF;
    }

    if(pseudo_obj->IsUploading()){
        S3FS_PRN_ERR("Why uploading now, even though s3fs is No Multipart uploading mode.");
        return -EBADF;
    }

    // If there is no loading all of the area, loading all area.
    off_t restsize = pagelist.GetTotalUnloadedPageSize();
    if(0 < restsize){
        // check disk space
        if(!ReserveDiskSpace(restsize)){
            // not enough disk space
            S3FS_PRN_WARN("Not enough local storage to flush: [path=%s][pseudo_fd=%d][physical_fd=%d]", (tpath ? tpath : path.c_str()), pseudo_obj->GetPseudoFd(), physical_fd);
            return -ENOSPC;   // No space left on device
        }
    }
    FdManager::FreeReservedDiskSpace(restsize);

    // Always load all uninitialized area
    int result;
    if(0 != (result = Load(/*start=*/ 0, /*size=*/ 0))){
        S3FS_PRN_ERR("failed to upload all area(errno=%d)", result);
        return result;
    }

    // check size
    if(pagelist.Size() > MAX_MULTIPART_CNT * S3fsCurl::GetMultipartSize()){
        S3FS_PRN_ERR("Part count exceeds %d.  Increase multipart size and try again.", MAX_MULTIPART_CNT);
        return -EFBIG;
    }

    // backup upload file size
    struct stat st{};
    if(-1 == fstat(physical_fd, &st)){
        S3FS_PRN_ERR("fstat is failed by errno(%d), but continue...", errno);
    }

    // parameter for thread worker
    put_req_thparam thargs;
    thargs.path   = tpath ? tpath : path;
    thargs.meta   = orgmeta;            // copy
    thargs.fd     = physical_fd;
    thargs.ahbe   = true;
    thargs.result = 0;

    // make parameter for thread pool
    thpoolman_param  ppoolparam;
    ppoolparam.args  = &thargs;
    ppoolparam.psem  = nullptr;         // case await
    ppoolparam.pfunc = put_req_threadworker;

    // send request by thread
    if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
        S3FS_PRN_ERR("failed to setup Put Request for Thread Worker");
        return -EIO;
    }
    if(0 != thargs.result){
        // continue...
        S3FS_PRN_DBG("Put Request(%s) returns with errno(%d)", thargs.path.c_str(), thargs.result);
    }

    // reset uploaded file size
    size_orgmeta = st.st_size;

    untreated_list.ClearAll();

    if(0 == thargs.result){
        pagelist.ClearAllModified();
    }

    return thargs.result;
}

//
// ([TODO] This is a temporary modification till S3fsMultiCurl is deprecated.)
//
int FdEntity::RowFlushMultipart(PseudoFdInfo* pseudo_obj, const char* tpath)
{
    S3FS_PRN_INFO3("[tpath=%s][path=%s][pseudo_fd=%d][physical_fd=%d]", SAFESTRPTR(tpath), path.c_str(), (pseudo_obj ? pseudo_obj->GetPseudoFd() : -1), physical_fd);

    if(-1 == physical_fd || !pseudo_obj){
        return -EBADF;
    }

    int result = 0;

    if(!pseudo_obj->IsUploading()){
        // Start uploading

        // If there is no loading all of the area, loading all area.
        off_t restsize = pagelist.GetTotalUnloadedPageSize();

        // Check rest size and free disk space
        if(0 < restsize && !ReserveDiskSpace(restsize)){
           // not enough disk space
           if(0 != (result = NoCachePreMultipartUploadRequest(pseudo_obj))){
               S3FS_PRN_ERR("failed to switch multipart uploading with no cache(errno=%d)", result);
               return result;
           }
           // upload all by multipart uploading
           if(0 != (result = NoCacheLoadAndPost(pseudo_obj))){
               S3FS_PRN_ERR("failed to upload all area by multipart uploading(errno=%d)", result);
               return result;
           }

        }else{
            // enough disk space or no rest size
            std::string tmppath    = path;
            headers_t   tmporgmeta = orgmeta;

            FdManager::FreeReservedDiskSpace(restsize);

            // Load all uninitialized area(no mix multipart uploading)
            if(0 != (result = Load(/*start=*/ 0, /*size=*/ 0))){
                S3FS_PRN_ERR("failed to upload all area(errno=%d)", result);
                return result;
            }

            // backup upload file size
            struct stat st{};
            if(-1 == fstat(physical_fd, &st)){
                S3FS_PRN_ERR("fstat is failed by errno(%d), but continue...", errno);
            }

            if(pagelist.Size() > MAX_MULTIPART_CNT * S3fsCurl::GetMultipartSize()){
                S3FS_PRN_ERR("Part count exceeds %d.  Increase multipart size and try again.", MAX_MULTIPART_CNT);
                return -EFBIG;

            }else if(pagelist.Size() >= S3fsCurl::GetMultipartSize()){
                // multipart uploading
                result = multipart_upload_request(tpath ? tpath : tmppath, tmporgmeta, physical_fd);
            }else{
                // normal uploading (too small part size)

                // parameter for thread worker
                put_req_thparam thargs;
                thargs.path   = tpath ? tpath : tmppath;
                thargs.meta   = tmporgmeta;         // copy
                thargs.fd     = physical_fd;
                thargs.ahbe   = true;
                thargs.result = 0;

                // make parameter for thread pool
                thpoolman_param  ppoolparam;
                ppoolparam.args  = &thargs;
                ppoolparam.psem  = nullptr;         // case await
                ppoolparam.pfunc = put_req_threadworker;

                // send request by thread
                if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
                    S3FS_PRN_ERR("failed to setup Put Request for Thread Worker");
                    return -EIO;
                }
                if(0 != thargs.result){
                    // continue...
                    S3FS_PRN_DBG("Put Request(%s) returns with errno(%d)", (tpath ? tpath : tmppath.c_str()), thargs.result);
                }
                result = thargs.result;
            }

            // reset uploaded file size
            size_orgmeta = st.st_size;
        }
        untreated_list.ClearAll();

    }else{
        // Already start uploading

        // upload rest data
        off_t untreated_start = 0;
        off_t untreated_size  = 0;
        if(untreated_list.GetLastUpdatedPart(untreated_start, untreated_size, S3fsCurl::GetMultipartSize(), 0) && 0 < untreated_size){
            if(0 != (result = NoCacheMultipartUploadRequest(pseudo_obj, physical_fd, untreated_start, untreated_size))){
                S3FS_PRN_ERR("failed to multipart upload(start=%lld, size=%lld) for file(physical_fd=%d).", static_cast<long long int>(untreated_start), static_cast<long long int>(untreated_size), physical_fd);
                return result;
            }
            untreated_list.ClearParts(untreated_start, untreated_size);
        }
        // complete multipart uploading.
        if(0 != (result = NoCacheMultipartUploadComplete(pseudo_obj))){
            S3FS_PRN_ERR("failed to complete(finish) multipart upload for file(physical_fd=%d).", physical_fd);
            return result;
        }
        // truncate file to zero
        if(-1 == ftruncate(physical_fd, 0)){
            // So the file has already been removed, skip error.
            S3FS_PRN_ERR("failed to truncate file(physical_fd=%d) to zero, but continue...", physical_fd);
        }
        // put pending headers or create new file
        if(0 != (result = UploadPendingHasLock(-1))){
            return result;
        }
    }

    if(0 == result){
        pagelist.ClearAllModified();
        pending_status = pending_status_t::NO_UPDATE_PENDING;
    }
    return result;
}

//
// ([TODO] This is a temporary modification till S3fsMultiCurl is deprecated.)
//
int FdEntity::RowFlushMixMultipart(PseudoFdInfo* pseudo_obj, const char* tpath)
{
    S3FS_PRN_INFO3("[tpath=%s][path=%s][pseudo_fd=%d][physical_fd=%d]", SAFESTRPTR(tpath), path.c_str(), (pseudo_obj ? pseudo_obj->GetPseudoFd() : -1), physical_fd);

    if(-1 == physical_fd || !pseudo_obj){
        return -EBADF;
    }

    int result = 0;

    if(!pseudo_obj->IsUploading()){
        // Start uploading

        // If there is no loading all of the area, loading all area.
        off_t restsize = pagelist.GetTotalUnloadedPageSize(/* start */ 0, /* size = all */ 0, MIN_MULTIPART_SIZE);

        // Check rest size and free disk space
        if(0 < restsize && !ReserveDiskSpace(restsize)){
           // not enough disk space
           if(0 != (result = NoCachePreMultipartUploadRequest(pseudo_obj))){
               S3FS_PRN_ERR("failed to switch multipart uploading with no cache(errno=%d)", result);
               return result;
           }
           // upload all by multipart uploading
           if(0 != (result = NoCacheLoadAndPost(pseudo_obj))){
               S3FS_PRN_ERR("failed to upload all area by multipart uploading(errno=%d)", result);
               return result;
           }

        }else{
            // enough disk space or no rest size
            std::string tmppath    = path;
            headers_t   tmporgmeta = orgmeta;

            FdManager::FreeReservedDiskSpace(restsize);

            // backup upload file size
            struct stat st{};
            if(-1 == fstat(physical_fd, &st)){
                S3FS_PRN_ERR("fstat is failed by errno(%d), but continue...", errno);
            }

            if(pagelist.Size() > MAX_MULTIPART_CNT * S3fsCurl::GetMultipartSize()){
                S3FS_PRN_ERR("Part count exceeds %d.  Increase multipart size and try again.", MAX_MULTIPART_CNT);
                return -EFBIG;

            }else if(pagelist.Size() >= S3fsCurl::GetMultipartSize()){
                // mix multipart uploading

                // This is to ensure that each part is 5MB or more.
                // If the part is less than 5MB, download it.
                fdpage_list_t dlpages;
                fdpage_list_t mixuppages;
                if(!pagelist.GetPageListsForMultipartUpload(dlpages, mixuppages, S3fsCurl::GetMultipartSize())){
                    S3FS_PRN_ERR("something error occurred during getting download pagelist.");
                    return -1;
                }

                // [TODO] should use parallel downloading
                //
                for(auto iter = dlpages.cbegin(); iter != dlpages.cend(); ++iter){
                    if(0 != (result = Load(iter->offset, iter->bytes, /*is_modified_flag=*/ true))){  // set loaded and modified flag
                        S3FS_PRN_ERR("failed to get parts(start=%lld, size=%lld) before uploading.", static_cast<long long int>(iter->offset), static_cast<long long int>(iter->bytes));
                        return result;
                    }
                }

                // multipart uploading with copy api
                result = mix_multipart_upload_request(tpath ? tpath : tmppath, tmporgmeta, physical_fd, mixuppages);

            }else{
                // normal uploading (too small part size)

                // If there are unloaded pages, they are loaded at here.
                if(0 != (result = Load(/*start=*/ 0, /*size=*/ 0))){
                    S3FS_PRN_ERR("failed to load parts before uploading object(%d)", result);
                    return result;
                }

                // parameter for thread worker
                put_req_thparam thargs;
                thargs.path   = tpath ? tpath : tmppath;
                thargs.meta   = tmporgmeta;         // copy
                thargs.fd     = physical_fd;
                thargs.ahbe   = true;
                thargs.result = 0;

                // make parameter for thread pool
                thpoolman_param  ppoolparam;
                ppoolparam.args  = &thargs;
                ppoolparam.psem  = nullptr;         // case await
                ppoolparam.pfunc = put_req_threadworker;

                // send request by thread
                if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
                    S3FS_PRN_ERR("failed to setup Put Request for Thread Worker");
                    return -EIO;
                }
                if(0 != thargs.result){
                    // continue...
                    S3FS_PRN_DBG("Put Request(%s) returns with errno(%d)", (tpath ? tpath : tmppath.c_str()), thargs.result);
                }
                result = thargs.result;
            }

            // reset uploaded file size
            size_orgmeta = st.st_size;
        }
        untreated_list.ClearAll();

    }else{
        // Already start uploading

        // upload rest data
        off_t untreated_start = 0;
        off_t untreated_size  = 0;
        if(untreated_list.GetLastUpdatedPart(untreated_start, untreated_size, S3fsCurl::GetMultipartSize(), 0) && 0 < untreated_size){
            if(0 != (result = NoCacheMultipartUploadRequest(pseudo_obj, physical_fd, untreated_start, untreated_size))){
                S3FS_PRN_ERR("failed to multipart upload(start=%lld, size=%lld) for file(physical_fd=%d).", static_cast<long long int>(untreated_start), static_cast<long long int>(untreated_size), physical_fd);
                return result;
            }
            untreated_list.ClearParts(untreated_start, untreated_size);
        }
        // complete multipart uploading.
        if(0 != (result = NoCacheMultipartUploadComplete(pseudo_obj))){
            S3FS_PRN_ERR("failed to complete(finish) multipart upload for file(physical_fd=%d).", physical_fd);
            return result;
        }
        // truncate file to zero
        if(-1 == ftruncate(physical_fd, 0)){
            // So the file has already been removed, skip error.
            S3FS_PRN_ERR("failed to truncate file(physical_fd=%d) to zero, but continue...", physical_fd);
        }
        // put pending headers or create new file
        if(0 != (result = UploadPendingHasLock(-1))){
            return result;
        }
    }

    if(0 == result){
        pagelist.ClearAllModified();
        pending_status = pending_status_t::NO_UPDATE_PENDING;
    }
    return result;
}

//
// ([TODO] This is a temporary modification till S3fsMultiCurl is deprecated.)
//
int FdEntity::RowFlushStreamMultipart(PseudoFdInfo* pseudo_obj, const char* tpath)
{
    S3FS_PRN_INFO3("[tpath=%s][path=%s][pseudo_fd=%d][physical_fd=%d][mix_upload=%s]", SAFESTRPTR(tpath), path.c_str(), (pseudo_obj ? pseudo_obj->GetPseudoFd() : -1), physical_fd, (FdEntity::mixmultipart ? "true" : "false"));

    if(-1 == physical_fd || !pseudo_obj){
        return -EBADF;
    }
    int result = 0;

    if(pagelist.Size() <= S3fsCurl::GetMultipartSize()){
        //
        // Use normal upload instead of multipart upload(too small part size)
        //

        // backup upload file size
        struct stat st{};
        if(-1 == fstat(physical_fd, &st)){
            S3FS_PRN_ERR("fstat is failed by errno(%d), but continue...", errno);
        }

        // If there are unloaded pages, they are loaded at here.
        if(0 != (result = Load(/*start=*/ 0, /*size=*/ 0))){
            S3FS_PRN_ERR("failed to load parts before uploading object(%d)", result);
            return result;
        }

        // parameter for thread worker
        put_req_thparam thargs;
        thargs.path   = path;
        thargs.meta   = orgmeta;            // copy
        thargs.fd     = physical_fd;
        thargs.ahbe   = true;
        thargs.result = 0;

        // make parameter for thread pool
        thpoolman_param  ppoolparam;
        ppoolparam.args  = &thargs;
        ppoolparam.psem  = nullptr;         // case await
        ppoolparam.pfunc = put_req_threadworker;

        // send request by thread
        if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
            S3FS_PRN_ERR("failed to setup Put Request for Thread Worker");
            return -EIO;
        }
        if(0 != thargs.result){
            // continue...
            S3FS_PRN_DBG("Put Request(%s) returns with errno(%d)", path.c_str(), thargs.result);
        }
        result = thargs.result;

        // reset uploaded file size
        size_orgmeta = st.st_size;

        untreated_list.ClearAll();

        if(0 == result){
            pagelist.ClearAllModified();
        }

    }else{
        //
        // Make upload/download/copy/cancel lists from file
        //
        mp_part_list_t  to_upload_list;
        mp_part_list_t  to_copy_list;
        mp_part_list_t  to_download_list;
        filepart_list_t cancel_uploaded_list;
        bool            wait_upload_complete = false;
        if(!pseudo_obj->ExtractUploadPartsFromAllArea(untreated_list, to_upload_list, to_copy_list, to_download_list, cancel_uploaded_list, wait_upload_complete, S3fsCurl::GetMultipartSize(), pagelist.Size(), FdEntity::mixmultipart)){
            S3FS_PRN_ERR("Failed to extract various upload parts list from all area: errno(EIO)");
            return -EIO;
        }

        //
        // Check total size for downloading and Download
        //
        off_t total_download_size = total_mp_part_list(to_download_list);
        if(0 < total_download_size){
            //
            // Check if there is enough free disk space for the total download size
            //
            if(!ReserveDiskSpace(total_download_size)){
                // not enough disk space
                //
                // [NOTE]
                // Because there is no left space size to download, we can't solve this anymore
                // in this case which is uploading in sequence.
                //
                S3FS_PRN_WARN("Not enough local storage(%lld byte) to cache write request for whole of the file: [path=%s][physical_fd=%d]", static_cast<long long int>(total_download_size), path.c_str(), physical_fd);
                return -ENOSPC;   // No space left on device
            }
            // enough disk space

            //
            // Download all parts
            //
            // [TODO]
            // Execute in parallel downloading with multiple thread.
            //
            for(auto download_iter = to_download_list.cbegin(); download_iter != to_download_list.cend(); ++download_iter){
                if(0 != (result = Load(download_iter->start, download_iter->size))){
                    break;
                }
            }
            FdManager::FreeReservedDiskSpace(total_download_size);
            if(0 != result){
                S3FS_PRN_ERR("failed to load uninitialized area before writing(errno=%d)", result);
                return result;
            }
        }

        //
        // Has multipart uploading already started?
        //
        if(!pseudo_obj->IsUploading()){
            //
            // Multipart uploading hasn't started yet, so start it.
            //
            if(0 != (result = PreMultipartUploadRequest(pseudo_obj))){
                return result;
            }
        }

        //
        // Output debug level information
        //
        // When canceling(overwriting) a part that has already been uploaded, output it.
        //
        if(S3fsLog::IsS3fsLogDbg()){
            for(auto cancel_iter = cancel_uploaded_list.cbegin(); cancel_iter != cancel_uploaded_list.cend(); ++cancel_iter){
                S3FS_PRN_DBG("Cancel uploaded: start(%lld), size(%lld), part number(%d)", static_cast<long long int>(cancel_iter->startpos), static_cast<long long int>(cancel_iter->size), (cancel_iter->petag ? cancel_iter->petag->part_num : -1));
            }
        }

        // [NOTE]
        // If there is a part where has already been uploading, that part
        // is re-updated after finishing uploading, so the part of the last
        // uploaded must be canceled.
        // (These are cancel_uploaded_list, cancellation processing means
        // re-uploading the same area.)
        //
        // In rare cases, the completion of the previous upload and the
        // re-upload may be reversed, causing the ETag to be reversed,
        // in which case the upload will fail.
        // To prevent this, if the upload of the same area as the re-upload
        // is incomplete, we must wait for it to complete here.
        //
        if(wait_upload_complete){
            if(0 != (result = pseudo_obj->WaitAllThreadsExit())){
                S3FS_PRN_ERR("Some cancel area uploads that were waiting to complete failed with %d.", result);
                return result;
            }
        }

        //
        // Upload multipart and copy parts and wait exiting them
        //
        if(!pseudo_obj->ParallelMultipartUploadAll(path.c_str(), to_upload_list, to_copy_list, result)){
            S3FS_PRN_ERR("Failed to upload multipart parts.");
            untreated_list.ClearAll();
            pseudo_obj->ClearUploadInfo();     // clear multipart upload info
            return -EIO;
        }
        if(0 != result){
            S3FS_PRN_ERR("An error(%d) occurred in some threads that were uploading parallel multiparts, but continue to clean up..", result);
            untreated_list.ClearAll();
            pseudo_obj->ClearUploadInfo();     // clear multipart upload info
            return result;
        }

        //
        // Complete uploading
        //
        std::string upload_id;
        etaglist_t  parts;
        if(!pseudo_obj->GetUploadId(upload_id) || !pseudo_obj->GetEtaglist(parts)){
            S3FS_PRN_ERR("There is no upload id or etag list.");
            untreated_list.ClearAll();
            pseudo_obj->ClearUploadInfo();     // clear multipart upload info
            return -EIO;
        }else{
            if(0 != (result = complete_multipart_upload_request(path, upload_id, parts))){
                S3FS_PRN_ERR("failed to complete multipart upload by errno(%d)", result);
                untreated_list.ClearAll();
                pseudo_obj->ClearUploadInfo(); // clear multipart upload info

                int result2;
                if(0 != (result2 = abort_multipart_upload_request(path, upload_id))){
                    S3FS_PRN_ERR("failed to abort multipart upload by errno(%d)", result2);
                }
                return result;
            }
        }

        untreated_list.ClearAll();
        pseudo_obj->ClearUploadInfo();         // clear multipart upload info

        // put pending headers or create new file
        if(0 != (result = UploadPendingHasLock(-1))){
            return result;
        }
    }
    untreated_list.ClearAll();

    if(0 == result){
        pagelist.ClearAllModified();
    }

    return result;
}

// [NOTICE]
// Need to lock before calling this method.
bool FdEntity::ReserveDiskSpace(off_t size)
{
    if(FdManager::ReserveDiskSpace(size)){
        return true;
    }

    if(!pagelist.IsModified()){
        // try to clear all cache for this fd.
        pagelist.Init(pagelist.Size(), false, false);
        if(-1 == ftruncate(physical_fd, 0) || -1 == ftruncate(physical_fd, pagelist.Size())){
            S3FS_PRN_ERR("failed to truncate temporary file(physical_fd=%d).", physical_fd);
            return false;
        }

        if(FdManager::ReserveDiskSpace(size)){
            return true;
        }
    }

    FdManager::get()->CleanupCacheDir();

    return FdManager::ReserveDiskSpace(size);
}

ssize_t FdEntity::Read(int fd, char* bytes, off_t start, size_t size, bool force_load)
{
    const std::lock_guard<std::mutex> lock(fdent_lock);

    S3FS_PRN_DBG("[path=%s][pseudo_fd=%d][physical_fd=%d][offset=%lld][size=%zu]", path.c_str(), fd, physical_fd, static_cast<long long int>(start), size);

    if(-1 == physical_fd || nullptr == CheckPseudoFdFlags(fd, false)){
        S3FS_PRN_DBG("pseudo_fd(%d) to physical_fd(%d) for path(%s) is not opened or not readable", fd, physical_fd, path.c_str());
        return -EBADF;
    }

    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);

    if(force_load){
        pagelist.SetPageLoadedStatus(start, size, PageList::page_status::NOT_LOAD_MODIFIED);
    }

    ssize_t rsize;

    // check disk space
    if(0 < pagelist.GetTotalUnloadedPageSize(start, size)){
        // load size(for prefetch)
        size_t load_size = size;
        if(start + static_cast<ssize_t>(size) < pagelist.Size()){
            ssize_t prefetch_max_size = std::max(static_cast<off_t>(size), S3fsCurl::GetMultipartSize() * ThreadPoolMan::GetWorkerCount());

            if(start + prefetch_max_size < pagelist.Size()){
                load_size = prefetch_max_size;
            }else{
                load_size = pagelist.Size() - start;
            }
        }

        if(!ReserveDiskSpace(load_size)){
            S3FS_PRN_WARN("could not reserve disk space for pre-fetch download");
            load_size = size;
            if(!ReserveDiskSpace(load_size)){
                S3FS_PRN_ERR("could not reserve disk space for pre-fetch download");
                return -ENOSPC;
            }
        }

        // Loading
        int result = 0;
        if(0 < size){
            result = Load(start, load_size);
        }

        FdManager::FreeReservedDiskSpace(load_size);

        if(0 != result){
            S3FS_PRN_ERR("could not download. start(%lld), size(%zu), errno(%d)", static_cast<long long int>(start), size, result);
            return result;
        }
    }

    // Reading
    if(-1 == (rsize = pread(physical_fd, bytes, size, start))){
        S3FS_PRN_ERR("pread failed. errno(%d)", errno);
        return -errno;
    }
    return rsize;
}

ssize_t FdEntity::Write(int fd, const char* bytes, off_t start, size_t size)
{
    const std::lock_guard<std::mutex> lock(fdent_lock);

    S3FS_PRN_DBG("[path=%s][pseudo_fd=%d][physical_fd=%d][offset=%lld][size=%zu]", path.c_str(), fd, physical_fd, static_cast<long long int>(start), size);

    PseudoFdInfo* pseudo_obj = nullptr;
    if(-1 == physical_fd || nullptr == (pseudo_obj = CheckPseudoFdFlags(fd, false))){
        S3FS_PRN_ERR("pseudo_fd(%d) to physical_fd(%d) for path(%s) is not opened or not writable", fd, physical_fd, path.c_str());
        return -EBADF;
    }

    // check if not enough disk space left BEFORE locking fd
    if(FdManager::IsCacheDir() && !FdManager::IsSafeDiskSpace(nullptr, size)){
        FdManager::get()->CleanupCacheDir();
    }
    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);

    // check file size
    if(pagelist.Size() < start){
        // grow file size
        if(-1 == ftruncate(physical_fd, start)){
            S3FS_PRN_ERR("failed to truncate temporary file(physical_fd=%d).", physical_fd);
            return -errno;
        }
        // set untreated area
        if(!AddUntreated(pagelist.Size(), (start - pagelist.Size()))){
            S3FS_PRN_ERR("failed to set untreated area by incremental.");
            return -EIO;
        }

        // add new area
        pagelist.SetPageLoadedStatus(pagelist.Size(), start - pagelist.Size(), PageList::page_status::MODIFIED);
    }

    ssize_t wsize;
    if(nomultipart){
        // No multipart upload
        wsize = WriteNoMultipart(pseudo_obj, bytes, start, size);
    }else if(FdEntity::streamupload){
        // Stream upload
        wsize = WriteStreamUpload(pseudo_obj, bytes, start, size);
    }else if(FdEntity::mixmultipart){
        // Mix multipart upload
        wsize = WriteMixMultipart(pseudo_obj, bytes, start, size);
    }else{
        // Normal multipart upload
        wsize = WriteMultipart(pseudo_obj, bytes, start, size);
    }

    return wsize;
}

ssize_t FdEntity::WriteNoMultipart(const PseudoFdInfo* pseudo_obj, const char* bytes, off_t start, size_t size)
{
    S3FS_PRN_DBG("[path=%s][pseudo_fd=%d][physical_fd=%d][offset=%lld][size=%zu]", path.c_str(), (pseudo_obj ? pseudo_obj->GetPseudoFd() : -1), physical_fd, static_cast<long long int>(start), size);

    if(-1 == physical_fd || !pseudo_obj){
        S3FS_PRN_ERR("pseudo_fd(%d) to physical_fd(%d) for path(%s) is not opened or not writable", (pseudo_obj ? pseudo_obj->GetPseudoFd() : -1), physical_fd, path.c_str());
        return -EBADF;
    }

    int result = 0;

    if(pseudo_obj->IsUploading()){
        S3FS_PRN_ERR("Why uploading now, even though s3fs is No Multipart uploading mode.");
        return -EBADF;
    }

    // check disk space
    off_t restsize = pagelist.GetTotalUnloadedPageSize(0, start) + size;
    if(!ReserveDiskSpace(restsize)){
        // not enough disk space
        S3FS_PRN_WARN("Not enough local storage to cache write request: [path=%s][physical_fd=%d][offset=%lld][size=%zu]", path.c_str(), physical_fd, static_cast<long long int>(start), size);
        return -ENOSPC;   // No space left on device
    }

    // Load uninitialized area which starts from 0 to (start + size) before writing.
    if(0 < start){
        result = Load(0, start);
    }

    FdManager::FreeReservedDiskSpace(restsize);
    if(0 != result){
        S3FS_PRN_ERR("failed to load uninitialized area before writing(errno=%d)", result);
        return result;
    }

    // Writing
    ssize_t wsize;
    if(-1 == (wsize = pwrite(physical_fd, bytes, size, start))){
        S3FS_PRN_ERR("pwrite failed. errno(%d)", errno);
        return -errno;
    }
    if(0 < wsize){
        pagelist.SetPageLoadedStatus(start, wsize, PageList::page_status::LOAD_MODIFIED);
        AddUntreated(start, wsize);
    }

    // Load uninitialized area which starts from (start + size) to EOF after writing.
    if(pagelist.Size() > start + static_cast<off_t>(size)){
        result = Load(start + size, pagelist.Size());
        if(0 != result){
            S3FS_PRN_ERR("failed to load uninitialized area after writing(errno=%d)", result);
            return result;
        }
    }

    return wsize;
}

ssize_t FdEntity::WriteMultipart(PseudoFdInfo* pseudo_obj, const char* bytes, off_t start, size_t size)
{
    S3FS_PRN_DBG("[path=%s][pseudo_fd=%d][physical_fd=%d][offset=%lld][size=%zu]", path.c_str(), (pseudo_obj ? pseudo_obj->GetPseudoFd() : -1), physical_fd, static_cast<long long int>(start), size);

    if(-1 == physical_fd || !pseudo_obj){
        S3FS_PRN_ERR("pseudo_fd(%d) to physical_fd(%d) for path(%s) is not opened or not writable", (pseudo_obj ? pseudo_obj->GetPseudoFd() : -1), physical_fd, path.c_str());
        return -EBADF;
    }

    int result = 0;

    if(!pseudo_obj->IsUploading()){
        // check disk space
        off_t restsize = pagelist.GetTotalUnloadedPageSize(0, start) + size;
        if(ReserveDiskSpace(restsize)){
            // enough disk space

            // Load uninitialized area which starts from 0 to (start + size) before writing.
            if(0 < start){
                result = Load(0, start);
            }

            FdManager::FreeReservedDiskSpace(restsize);
            if(0 != result){
                S3FS_PRN_ERR("failed to load uninitialized area before writing(errno=%d)", result);
                return result;
            }
        }else{
            // not enough disk space
            if((start + static_cast<off_t>(size)) <= S3fsCurl::GetMultipartSize()){
                S3FS_PRN_WARN("Not enough local storage to cache write request till multipart upload can start: [path=%s][physical_fd=%d][offset=%lld][size=%zu]", path.c_str(), physical_fd, static_cast<long long int>(start), size);
                return -ENOSPC;   // No space left on device
            }
            if(0 != (result = NoCachePreMultipartUploadRequest(pseudo_obj))){
                S3FS_PRN_ERR("failed to switch multipart uploading with no cache(errno=%d)", result);
                return result;
            }
            // start multipart uploading
            if(0 != (result = NoCacheLoadAndPost(pseudo_obj, 0, start))){
                S3FS_PRN_ERR("failed to load uninitialized area and multipart uploading it(errno=%d)", result);
                return result;
            }
            untreated_list.ClearAll();
        }
    }else{
        // already start multipart uploading
    }

    // Writing
    ssize_t wsize;
    if(-1 == (wsize = pwrite(physical_fd, bytes, size, start))){
        S3FS_PRN_ERR("pwrite failed. errno(%d)", errno);
        return -errno;
    }
    if(0 < wsize){
        pagelist.SetPageLoadedStatus(start, wsize, PageList::page_status::LOAD_MODIFIED);
        AddUntreated(start, wsize);
    }

    // Load uninitialized area which starts from (start + size) to EOF after writing.
    if(pagelist.Size() > start + static_cast<off_t>(size)){
        result = Load(start + size, pagelist.Size());
        if(0 != result){
            S3FS_PRN_ERR("failed to load uninitialized area after writing(errno=%d)", result);
            return result;
        }
    }

    // check multipart uploading
    if(pseudo_obj->IsUploading()){
        // get last untreated part(maximum size is multipart size)
        off_t untreated_start = 0;
        off_t untreated_size  = 0;
        if(untreated_list.GetLastUpdatedPart(untreated_start, untreated_size, S3fsCurl::GetMultipartSize())){
            // when multipart max size is reached
            if(0 != (result = NoCacheMultipartUploadRequest(pseudo_obj, physical_fd, untreated_start, untreated_size))){
                S3FS_PRN_ERR("failed to multipart upload(start=%lld, size=%lld) for file(physical_fd=%d).", static_cast<long long int>(untreated_start), static_cast<long long int>(untreated_size), physical_fd);
                return result;
            }

            // [NOTE]
            // truncate file to zero and set length to part offset + size
            // after this, file length is (offset + size), but file does not use any disk space.
            //
            if(-1 == ftruncate(physical_fd, 0) || -1 == ftruncate(physical_fd, (untreated_start + untreated_size))){
                S3FS_PRN_ERR("failed to truncate file(physical_fd=%d).", physical_fd);
                return -errno;
            }
            untreated_list.ClearParts(untreated_start, untreated_size);
        }
    }
    return wsize;
}

ssize_t FdEntity::WriteMixMultipart(PseudoFdInfo* pseudo_obj, const char* bytes, off_t start, size_t size)
{
    S3FS_PRN_DBG("[path=%s][pseudo_fd=%d][physical_fd=%d][offset=%lld][size=%zu]", path.c_str(), (pseudo_obj ? pseudo_obj->GetPseudoFd() : -1), physical_fd, static_cast<long long int>(start), size);

    if(-1 == physical_fd || !pseudo_obj){
        S3FS_PRN_ERR("pseudo_fd(%d) to physical_fd(%d) for path(%s) is not opened or not writable", (pseudo_obj ? pseudo_obj->GetPseudoFd() : -1), physical_fd, path.c_str());
        return -EBADF;
    }

    int result;

    if(!pseudo_obj->IsUploading()){
        // check disk space
        off_t restsize = pagelist.GetTotalUnloadedPageSize(0, start, MIN_MULTIPART_SIZE) + size;
        if(ReserveDiskSpace(restsize)){
            // enough disk space
            FdManager::FreeReservedDiskSpace(restsize);
        }else{
            // not enough disk space
            if((start + static_cast<off_t>(size)) <= S3fsCurl::GetMultipartSize()){
                S3FS_PRN_WARN("Not enough local storage to cache write request till multipart upload can start: [path=%s][physical_fd=%d][offset=%lld][size=%zu]", path.c_str(), physical_fd, static_cast<long long int>(start), size);
                return -ENOSPC;   // No space left on device
            }
            if(0 != (result = NoCachePreMultipartUploadRequest(pseudo_obj))){
                S3FS_PRN_ERR("failed to switch multipart uploading with no cache(errno=%d)", result);
                return result;
            }
            // start multipart uploading
            if(0 != (result = NoCacheLoadAndPost(pseudo_obj, 0, start))){
                S3FS_PRN_ERR("failed to load uninitialized area and multipart uploading it(errno=%d)", result);
                return result;
            }
            untreated_list.ClearAll();
        }
    }else{
        // already start multipart uploading
    }

    // Writing
    ssize_t wsize;
    if(-1 == (wsize = pwrite(physical_fd, bytes, size, start))){
        S3FS_PRN_ERR("pwrite failed. errno(%d)", errno);
        return -errno;
    }
    if(0 < wsize){
        pagelist.SetPageLoadedStatus(start, wsize, PageList::page_status::LOAD_MODIFIED);
        AddUntreated(start, wsize);
    }

    // check multipart uploading
    if(pseudo_obj->IsUploading()){
        // get last untreated part(maximum size is multipart size)
        off_t untreated_start = 0;
        off_t untreated_size  = 0;
        if(untreated_list.GetLastUpdatedPart(untreated_start, untreated_size, S3fsCurl::GetMultipartSize())){
            // when multipart max size is reached
            if(0 != (result = NoCacheMultipartUploadRequest(pseudo_obj, physical_fd, untreated_start, untreated_size))){
                S3FS_PRN_ERR("failed to multipart upload(start=%lld, size=%lld) for file(physical_fd=%d).", static_cast<long long int>(untreated_start), static_cast<long long int>(untreated_size), physical_fd);
                return result;
            }

            // [NOTE]
            // truncate file to zero and set length to part offset + size
            // after this, file length is (offset + size), but file does not use any disk space.
            //
            if(-1 == ftruncate(physical_fd, 0) || -1 == ftruncate(physical_fd, (untreated_start + untreated_size))){
                S3FS_PRN_ERR("failed to truncate file(physical_fd=%d).", physical_fd);
                return -errno;
            }
            untreated_list.ClearParts(untreated_start, untreated_size);
        }
    }
    return wsize;
}

//
// On Stream upload, the uploading is executed in another thread when the
// written area exceeds the maximum size of multipart upload.
//
ssize_t FdEntity::WriteStreamUpload(PseudoFdInfo* pseudo_obj, const char* bytes, off_t start, size_t size)
{
    S3FS_PRN_DBG("[path=%s][pseudo_fd=%d][physical_fd=%d][offset=%lld][size=%zu]", path.c_str(), (pseudo_obj ? pseudo_obj->GetPseudoFd() : -1), physical_fd, static_cast<long long int>(start), size);

    if(-1 == physical_fd || !pseudo_obj){
        S3FS_PRN_ERR("pseudo_fd(%d) to physical_fd(%d) for path(%s) is not opened or not writable", (pseudo_obj ? pseudo_obj->GetPseudoFd() : -1), physical_fd, path.c_str());
        return -EBADF;
    }

    // Writing
    ssize_t wsize;
    if(-1 == (wsize = pwrite(physical_fd, bytes, size, start))){
        S3FS_PRN_ERR("pwrite failed. errno(%d)", errno);
        return -errno;
    }
    if(0 < wsize){
        pagelist.SetPageLoadedStatus(start, wsize, PageList::page_status::LOAD_MODIFIED);
        AddUntreated(start, wsize);
    }

    // Check and Upload
    //
    // If the last updated Untreated area exceeds the maximum upload size,
    // upload processing is performed.
    //
    headers_t tmporgmeta  = orgmeta;
    bool      isuploading = pseudo_obj->IsUploading();
    ssize_t   result;
    if(0 != (result = pseudo_obj->UploadBoundaryLastUntreatedArea(path.c_str(), tmporgmeta, this))){
        S3FS_PRN_ERR("Failed to upload the last untreated parts(area) : result=%zd", result);
        return result;
    }

    if(!isuploading && pseudo_obj->IsUploading()){
        // Clear the dirty flag, because the meta data is updated.
        pending_status = pending_status_t::NO_UPDATE_PENDING;
    }

    return wsize;
}

// [NOTE]
// Returns true if merged to orgmeta.
// If true is returned, the caller can update the header.
// If it is false, do not update the header because multipart upload is in progress.
// In this case, the header is pending internally and is updated after the upload
// is complete(flush file).
//
bool FdEntity::MergeOrgMeta(headers_t& updatemeta)
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);

    merge_headers(orgmeta, updatemeta, true);      // overwrite all keys
    // [NOTE]
    // this is special cases, we remove the key which has empty values.
    for(auto hiter = orgmeta.cbegin(); hiter != orgmeta.cend(); ){
        if(hiter->second.empty()){
            hiter = orgmeta.erase(hiter);
        }else{
            ++hiter;
        }
    }
    updatemeta = orgmeta;
    orgmeta.erase("x-amz-copy-source");

    // update ctime/mtime/atime
    struct timespec mtime = get_mtime(updatemeta, false);      // not overcheck
    struct timespec ctime = get_ctime(updatemeta, false);      // not overcheck
    struct timespec atime = get_atime(updatemeta, false);      // not overcheck
    if(0 <= mtime.tv_sec){
        SetMCtimeHasLock(mtime, (ctime.tv_sec < 0 ? mtime : ctime));
    }
    if(0 <= atime.tv_sec){
        SetAtimeHasLock(atime);
    }

    if(pending_status_t::NO_UPDATE_PENDING == pending_status && (IsUploading() || pagelist.IsModified())){
        pending_status = pending_status_t::UPDATE_META_PENDING;
    }

    return (pending_status_t::NO_UPDATE_PENDING != pending_status);
}

bool FdEntity::GetOrgMeta(headers_t& meta) const
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);

    meta = orgmeta;
    return true;
}

int FdEntity::UploadPendingHasLock(int fd)
{
    int result;

    if(pending_status_t::NO_UPDATE_PENDING == pending_status){
       // nothing to do
       result = 0;

    }else if(pending_status_t::UPDATE_META_PENDING == pending_status){
        headers_t updatemeta = orgmeta;
        updatemeta["x-amz-copy-source"]        = urlEncodePath(service_path + S3fsCred::GetBucket() + get_realpath(path.c_str()));
        updatemeta["x-amz-metadata-directive"] = "REPLACE";

        // put headers, no need to update mtime to avoid dead lock
        result = put_headers(path.c_str(), updatemeta, true);
        if(0 != result){
            S3FS_PRN_ERR("failed to put header after flushing file(%s) by(%d).", path.c_str(), result);
        }else{
            pending_status = pending_status_t::NO_UPDATE_PENDING;
        }

    }else{  // CREATE_FILE_PENDING == pending_status
        if(-1 == fd){
            S3FS_PRN_ERR("could not create a new file(%s), because fd is not specified.", path.c_str());
            result = -EBADF;
        }else{
            result = RowFlushHasLock(fd, nullptr, true);
            if(0 != result){
                S3FS_PRN_ERR("failed to flush for file(%s) by(%d).", path.c_str(), result);
            }else{
                pending_status = pending_status_t::NO_UPDATE_PENDING;
            }
        }
    }
    return result;
}

// [NOTE]
// For systems where the fallocate function cannot be detected, use a dummy function.
// ex. OSX
//
#if !defined(HAVE_FALLOCATE) || defined(__MSYS__)
static int fallocate(int /*fd*/, int /*mode*/, off_t /*offset*/, off_t /*len*/)
{
    errno = ENOSYS;     // This is a bad idea, but the caller can handle it simply.
    return -1;
}
#endif  // HAVE_FALLOCATE

// [NOTE]
// If HAVE_FALLOCATE is undefined, or versions prior to 2.6.38(fallocate function exists),
// following flags are undefined. Then we need these symbols defined in fallocate, so we
// define them here.
// The definitions are copied from linux/falloc.h, but if HAVE_FALLOCATE is undefined,
// these values can be anything.
//
#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE     0x02 /* de-allocates range */
#endif
#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE      0x01
#endif

// [NOTE]
// This method punches an area(on cache file) that has no data at the time it is called.
// This is called to prevent the cache file from growing.
// However, this method uses the non-portable(Linux specific) system call fallocate().
// Also, depending on the file system, FALLOC_FL_PUNCH_HOLE mode may not work and HOLE
// will not open.(Filesystems for which this method works are ext4, btrfs, xfs, etc.)
// 
bool FdEntity::PunchHole(off_t start, size_t size)
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);

    S3FS_PRN_DBG("[path=%s][physical_fd=%d][offset=%lld][size=%zu]", path.c_str(), physical_fd, static_cast<long long int>(start), size);

    if(-1 == physical_fd){
        return false;
    }

    // get page list that have no data
    fdpage_list_t   nodata_pages;
    if(!pagelist.GetNoDataPageLists(nodata_pages)){
        S3FS_PRN_ERR("failed to get page list that have no data.");
        return false;
    }
    if(nodata_pages.empty()){
        S3FS_PRN_DBG("there is no page list that have no data, so nothing to do.");
        return true;
    }

    // try to punch hole to file
    for(auto iter = nodata_pages.cbegin(); iter != nodata_pages.cend(); ++iter){
        if(0 != fallocate(physical_fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, iter->offset, iter->bytes)){
            if(ENOSYS == errno || EOPNOTSUPP == errno){
                S3FS_PRN_ERR("failed to fallocate for punching hole to file with errno(%d), it maybe the fallocate function is not implemented in this kernel, or the file system does not support FALLOC_FL_PUNCH_HOLE.", errno);
            }else{
                S3FS_PRN_ERR("failed to fallocate for punching hole to file with errno(%d)", errno);
            }
            return false;
        }
        if(!pagelist.SetPageLoadedStatus(iter->offset, iter->bytes, PageList::page_status::NOT_LOAD_MODIFIED)){
            S3FS_PRN_ERR("succeed to punch HOLEs in the cache file, but failed to update the cache stat.");
            return false;
        }
        S3FS_PRN_DBG("made a hole at [%lld - %lld bytes](into a boundary) of the cache file.", static_cast<long long int>(iter->offset), static_cast<long long int>(iter->bytes));
    }
    return true;
}

// [NOTE]
// Indicate that a new file's is dirty.
// This ensures that both metadata and data are synced during flush.
//
void FdEntity::MarkDirtyNewFile()
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);

    pagelist.Init(0, false, true);
    pending_status = pending_status_t::CREATE_FILE_PENDING;
}

bool FdEntity::IsDirtyNewFile() const
{
    const std::lock_guard<std::mutex> lock(fdent_data_lock);

    return (pending_status_t::CREATE_FILE_PENDING == pending_status);
}

// [NOTE]
// The fdatasync call only uploads the content but does not update
// the meta data. In the flush call, if there is no update contents,
// need to upload only metadata, so use these functions.
//
void FdEntity::MarkDirtyMetadata()
{
    const std::lock_guard<std::mutex> lock(fdent_lock);
    const std::lock_guard<std::mutex> data_lock(fdent_data_lock);

    if(pending_status_t::NO_UPDATE_PENDING == pending_status){
        pending_status = pending_status_t::UPDATE_META_PENDING;
    }
}

bool FdEntity::IsDirtyMetadata() const
{
    return (pending_status_t::UPDATE_META_PENDING == pending_status);
}

bool FdEntity::AddUntreated(off_t start, off_t size)
{
    bool result = untreated_list.AddPart(start, size);
    if(!result){
        S3FS_PRN_DBG("Failed adding untreated area part.");
    }else if(S3fsLog::IsS3fsLogDbg()){
        untreated_list.Dump();
    }

    return result;
}

bool FdEntity::GetLastUpdateUntreatedPart(off_t& start, off_t& size) const
{
    // Get last untreated area
    if(!untreated_list.GetLastUpdatePart(start, size)){
        return false;
    }
    return true;
}

bool FdEntity::ReplaceLastUpdateUntreatedPart(off_t front_start, off_t front_size, off_t behind_start, off_t behind_size)
{
    if(0 < front_size){
        if(!untreated_list.ReplaceLastUpdatePart(front_start, front_size)){
            return false;
        }
    }else{
        if(!untreated_list.RemoveLastUpdatePart()){
            return false;
        }
    }
    if(0 < behind_size){
        if(!untreated_list.AddPart(behind_start, behind_size)){
            return false;
        }
    }
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
