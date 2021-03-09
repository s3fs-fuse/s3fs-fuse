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
#include <limits.h>
#include <sys/time.h>

#include "common.h"
#include "s3fs.h"
#include "fdcache_entity.h"
#include "fdcache.h"
#include "string_util.h"
#include "s3fs_util.h"
#include "autolock.h"
#include "curl.h"

//------------------------------------------------
// Symbols
//------------------------------------------------
static const int MAX_MULTIPART_CNT         = 10 * 1000; // S3 multipart max count

//------------------------------------------------
// FdEntity class variables
//------------------------------------------------
bool FdEntity::mixmultipart = true;

//------------------------------------------------
// FdEntity class methods
//------------------------------------------------
bool FdEntity::SetNoMixMultipart()
{
    bool old = mixmultipart;
    mixmultipart = false;
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
        S3FS_PRN_ERR("could not get stat for file descriptor(%d) by errno(%d).", fd, errno);
        return 0;
    }
    return st.st_ino;
}

//------------------------------------------------
// FdEntity methods
//------------------------------------------------
FdEntity::FdEntity(const char* tpath, const char* cpath) :
    is_lock_init(false), refcnt(0), path(SAFESTRPTR(tpath)),
    fd(-1), pfile(NULL), inode(0), size_orgmeta(0), mp_start(0), mp_size(0),
    cachepath(SAFESTRPTR(cpath)), is_meta_pending(false), holding_mtime(-1)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
    int result;
    if(0 != (result = pthread_mutex_init(&fdent_lock, &attr))){
        S3FS_PRN_CRIT("failed to init fdent_lock: %d", result);
        abort();
    }
    if(0 != (result = pthread_mutex_init(&fdent_data_lock, &attr))){
        S3FS_PRN_CRIT("failed to init fdent_data_lock: %d", result);
        abort();
    }
    is_lock_init = true;
}

FdEntity::~FdEntity()
{
    Clear();

    if(is_lock_init){
      int result;
      if(0 != (result = pthread_mutex_destroy(&fdent_data_lock))){
          S3FS_PRN_CRIT("failed to destroy fdent_data_lock: %d", result);
          abort();
      }
      if(0 != (result = pthread_mutex_destroy(&fdent_lock))){
          S3FS_PRN_CRIT("failed to destroy fdent_lock: %d", result);
          abort();
      }
      is_lock_init = false;
    }
}

void FdEntity::Clear()
{
    AutoLock auto_lock(&fdent_lock);
    AutoLock auto_data_lock(&fdent_data_lock);

    if(-1 != fd){
        if(!cachepath.empty()){
            // [NOTE]
            // Compare the inode of the existing cache file with the inode of
            // the cache file output by this object, and if they are the same,
            // serialize the pagelist.
            //
            ino_t cur_inode = GetInode();
            if(0 != cur_inode && cur_inode == inode){
                CacheFileStat cfstat(path.c_str());
                if(!pagelist.Serialize(cfstat, true, inode)){
                    S3FS_PRN_WARN("failed to save cache stat file(%s).", path.c_str());
                }
            }
        }
        if(pfile){
            fclose(pfile);
            pfile = NULL;
        }
        fd    = -1;
        inode = 0;

        if(!mirrorpath.empty()){
            if(-1 == unlink(mirrorpath.c_str())){
                S3FS_PRN_WARN("failed to remove mirror cache file(%s) by errno(%d).", mirrorpath.c_str(), errno);
            }
            mirrorpath.erase();
        }
    }
    pagelist.Init(0, false, false);
    refcnt        = 0;
    path          = "";
    cachepath     = "";
}

// [NOTE]
// This method returns the inode of the file in cachepath.
// The return value is the same as the class method GetInode().
// The caller must have exclusive control.
//
ino_t FdEntity::GetInode()
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

void FdEntity::Close()
{
    AutoLock auto_lock(&fdent_lock);

    S3FS_PRN_DBG("[path=%s][fd=%d][refcnt=%d]", path.c_str(), fd, (-1 != fd ? refcnt - 1 : refcnt));

    if(-1 != fd){
        if(0 < refcnt){
            refcnt--;
        }else{
            S3FS_PRN_EXIT("reference count underflow");
            abort();
        }
        if(0 == refcnt){
            AutoLock auto_data_lock(&fdent_data_lock);
            if(!cachepath.empty()){
                // [NOTE]
                // Compare the inode of the existing cache file with the inode of
                // the cache file output by this object, and if they are the same,
                // serialize the pagelist.
                //
                ino_t cur_inode = GetInode();
                if(0 != cur_inode && cur_inode == inode){
                    CacheFileStat cfstat(path.c_str());
                    if(!pagelist.Serialize(cfstat, true, inode)){
                        S3FS_PRN_WARN("failed to save cache stat file(%s).", path.c_str());
                    }
                }
            }
            if(pfile){
                fclose(pfile);
                pfile = NULL;
            }
            fd    = -1;
            inode = 0;

            if(!mirrorpath.empty()){
                if(-1 == unlink(mirrorpath.c_str())){
                    S3FS_PRN_WARN("failed to remove mirror cache file(%s) by errno(%d).", mirrorpath.c_str(), errno);
                }
                mirrorpath.erase();
            }
        }
    }
}

int FdEntity::Dup(bool lock_already_held)
{
    AutoLock auto_lock(&fdent_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);

    S3FS_PRN_DBG("[path=%s][fd=%d][refcnt=%d]", path.c_str(), fd, (-1 != fd ? refcnt + 1 : refcnt));

    if(-1 != fd){
        refcnt++;
    }
    return fd;
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
    if(!FdManager::MakeCachePath(NULL, bupdir, true, true)){
        S3FS_PRN_ERR("could not make bup cache directory path or create it.");
        return -EIO;
    }

    // create seed generating mirror file name
    unsigned int seed = static_cast<unsigned int>(time(NULL));
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
        sprintf(szfile, "%x.tmp", rand_r(&seed));
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

int FdEntity::Open(headers_t* pmeta, off_t size, time_t time, bool no_fd_lock_wait)
{
    AutoLock auto_lock(&fdent_lock, no_fd_lock_wait ? AutoLock::NO_WAIT : AutoLock::NONE);

    S3FS_PRN_DBG("[path=%s][fd=%d][size=%lld][time=%lld]", path.c_str(), fd, static_cast<long long>(size), static_cast<long long>(time));

    if (!auto_lock.isLockAcquired()) {
        // had to wait for fd lock, return
        S3FS_PRN_ERR("Could not get lock.");
        return -EIO;
    }

    AutoLock auto_data_lock(&fdent_data_lock);
    if(-1 != fd){
        // already opened, needs to increment refcnt.
        Dup(/*lock_already_held=*/ true);

        // check only file size(do not need to save cfs and time.
        if(0 <= size && pagelist.Size() != size){
            // truncate temporary file size
            if(-1 == ftruncate(fd, size)){
                S3FS_PRN_ERR("failed to truncate temporary file(%d) by errno(%d).", fd, errno);
                if(0 < refcnt){
                    refcnt--;
                }
                return -EIO;
            }
            // resize page list
            if(!pagelist.Resize(size, false, true)){      // Areas with increased size are modified
                S3FS_PRN_ERR("failed to truncate temporary file information(%d).", fd);
                if(0 < refcnt){
                    refcnt--;
                }
                return -EIO;
            }
        }
        // set original headers and set size.
        off_t new_size = (0 <= size ? size : size_orgmeta);
        if(pmeta){
            orgmeta  = *pmeta;
            new_size = get_size(orgmeta);
        }
        if(new_size < size_orgmeta){
            size_orgmeta = new_size;
        }
        return 0;
    }

    bool  need_save_csf = false;  // need to save(reset) cache stat file
    bool  is_truncate   = false;  // need to truncate

    if(!cachepath.empty()){
        // using cache

        struct stat st;
        if(stat(cachepath.c_str(), &st) == 0){
            if(st.st_mtime < time){
                S3FS_PRN_DBG("cache file stale, removing: %s", cachepath.c_str());
                if(unlink(cachepath.c_str()) != 0){
                    return (0 == errno ? -EIO : -errno);
                }
            }
        }

        // open cache and cache stat file, load page info.
        CacheFileStat cfstat(path.c_str());

        // try to open cache file
        if( -1 != (fd = open(cachepath.c_str(), O_RDWR)) &&
            0 != (inode = FdEntity::GetInode(fd))        &&
            pagelist.Serialize(cfstat, false, inode)     )
        {
            // succeed to open cache file and to load stats data
            memset(&st, 0, sizeof(struct stat));
            if(-1 == fstat(fd, &st)){
                S3FS_PRN_ERR("fstat is failed. errno(%d)", errno);
                fd    = -1;
                inode = 0;
                return (0 == errno ? -EIO : -errno);
            }
            // check size, st_size, loading stat file
            if(-1 == size){
                if(st.st_size != pagelist.Size()){
                    pagelist.Resize(st.st_size, false, true); // Areas with increased size are modified
                    need_save_csf = true;     // need to update page info
                }
                size = st.st_size;
            }else{
                if(size != pagelist.Size()){
                    pagelist.Resize(size, false, true);       // Areas with increased size are modified
                    need_save_csf = true;     // need to update page info
                }
                if(size != st.st_size){
                    is_truncate = true;
                }
            }

        }else{
            if(-1 != fd){
                close(fd);
            }
            inode = 0;

            // could not open cache file or could not load stats data, so initialize it.
            if(-1 == (fd = open(cachepath.c_str(), O_CREAT|O_RDWR|O_TRUNC, 0600))){
                S3FS_PRN_ERR("failed to open file(%s). errno(%d)", cachepath.c_str(), errno);

                // remove cache stat file if it is existed
                if(!CacheFileStat::DeleteCacheFileStat(path.c_str())){
                    if(ENOENT != errno){
                        S3FS_PRN_WARN("failed to delete current cache stat file(%s) by errno(%d), but continue...", path.c_str(), errno);
                    }
                }
                return (0 == errno ? -EIO : -errno);
            }
            need_save_csf = true;       // need to update page info
            inode         = FdEntity::GetInode(fd);
            if(-1 == size){
                size = 0;
                pagelist.Init(0, false, false);
            }else{
                // [NOTE]
                // The modify flag must not be set when opening a file,
                // if the time parameter(mtime) is specified(not -1) and
                // the cache file does not exist.
                // If mtime is specified for the file and the cache file
                // mtime is older than it, the cache file is removed and
                // the processing comes here.
                //
                pagelist.Resize(size, false, (0 <= time ? false : true));

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
        close(fd);
        fd = mirrorfd;

        // make file pointer(for being same tmpfile)
        if(NULL == (pfile = fdopen(fd, "wb"))){
            S3FS_PRN_ERR("failed to get fileno(%s). errno(%d)", cachepath.c_str(), errno);
            close(fd);
            fd    = -1;
            inode = 0;
            return (0 == errno ? -EIO : -errno);
        }

    }else{
        // not using cache
        inode = 0;

        // open temporary file
        if(NULL == (pfile = tmpfile()) || -1 ==(fd = fileno(pfile))){
            S3FS_PRN_ERR("failed to open tmp file. err(%d)", errno);
            if(pfile){
                fclose(pfile);
                pfile = NULL;
            }
            return (0 == errno ? -EIO : -errno);
        }
        if(-1 == size){
            size = 0;
            pagelist.Init(0, false, false);
        }else{
            // [NOTE]
            // The modify flag must not be set when opening a file,
            // if the time parameter(mtime) is specified(not -1) and
            // the cache file does not exist.
            // If mtime is specified for the file and the cache file
            // mtime is older than it, the cache file is removed and
            // the processing comes here.
            //
            pagelist.Resize(size, false, (0 <= time ? false : true));
            is_truncate = true;
        }
    }

    // truncate cache(tmp) file
    if(is_truncate){
        if(0 != ftruncate(fd, size) || 0 != fsync(fd)){
            S3FS_PRN_ERR("ftruncate(%s) or fsync returned err(%d)", cachepath.c_str(), errno);
            fclose(pfile);
            pfile = NULL;
            fd    = -1;
            inode = 0;
            return (0 == errno ? -EIO : -errno);
        }
    }

    // reset cache stat file
    if(need_save_csf){
        CacheFileStat cfstat(path.c_str());
        if(!pagelist.Serialize(cfstat, true, inode)){
            S3FS_PRN_WARN("failed to save cache stat file(%s), but continue...", path.c_str());
        }
    }

    // init internal data
    refcnt = 1;

    // set original headers and size in it.
    if(pmeta){
        orgmeta      = *pmeta;
        size_orgmeta = get_size(orgmeta);
    }else{
        orgmeta.clear();
        size_orgmeta = 0;
    }

    // set mtime and ctime(set "x-amz-meta-mtime" and "x-amz-meta-ctime" in orgmeta)
    if(-1 != time){
        if(0 != SetMCtime(time, time, /*lock_already_held=*/ true)){
            S3FS_PRN_ERR("failed to set mtime. errno(%d)", errno);
            fclose(pfile);
            pfile = NULL;
            fd    = -1;
            inode = 0;
            return (0 == errno ? -EIO : -errno);
        }
    }
    return 0;
}

// [NOTE]
// This method is called from only nocopyapi functions.
// So we do not check disk space for this option mode, if there is no enough
// disk space this method will be failed.
//
bool FdEntity::OpenAndLoadAll(headers_t* pmeta, off_t* size, bool force_load)
{
    AutoLock auto_lock(&fdent_lock);
    int result;

    S3FS_PRN_INFO3("[path=%s][fd=%d]", path.c_str(), fd);

    if(-1 == fd){
        if(0 != Open(pmeta)){
            return false;
        }
    }
    AutoLock auto_data_lock(&fdent_data_lock);

    if(force_load){
        SetAllStatusUnloaded();
    }
    //
    // TODO: possibly do background for delay loading
    //
    if(0 != (result = Load(/*start=*/ 0, /*size=*/ 0, /*lock_already_held=*/ true))){
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
        fentmapkey.erase();
        FdManager::MakeRandomTempPath(newpath.c_str(), fentmapkey);
    }
    // set new path
    path = newpath;

    return true;
}

bool FdEntity::IsModified() const
{
    AutoLock auto_data_lock(const_cast<pthread_mutex_t *>(&fdent_data_lock));
    return pagelist.IsModified();
}

bool FdEntity::GetStats(struct stat& st, bool lock_already_held)
{
    AutoLock auto_lock(&fdent_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);
    if(-1 == fd){
        return false;
    }

    memset(&st, 0, sizeof(struct stat)); 
    if(-1 == fstat(fd, &st)){
        S3FS_PRN_ERR("fstat failed. errno(%d)", errno);
        return false;
    }
    return true;
}

int FdEntity::SetCtime(time_t time, bool lock_already_held)
{
    AutoLock auto_lock(&fdent_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);

    S3FS_PRN_INFO3("[path=%s][fd=%d][time=%lld]", path.c_str(), fd, static_cast<long long>(time));

    if(-1 == time){
        return 0;
    }
    orgmeta["x-amz-meta-ctime"] = str(time);
    return 0;
}

int FdEntity::SetAtime(time_t time, bool lock_already_held)
{
    AutoLock auto_lock(&fdent_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);

    S3FS_PRN_INFO3("[path=%s][fd=%d][time=%lld]", path.c_str(), fd, static_cast<long long>(time));

    if(-1 == time){
        return 0;
    }
    orgmeta["x-amz-meta-atime"] = str(time);
    return 0;
}

// [NOTE]
// This method updates mtime as well as ctime.
//
int FdEntity::SetMCtime(time_t mtime, time_t ctime, bool lock_already_held)
{
    AutoLock auto_lock(&fdent_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);

    S3FS_PRN_INFO3("[path=%s][fd=%d][mtime=%lld][ctime=%lld]", path.c_str(), fd, static_cast<long long>(mtime), static_cast<long long>(ctime));

    if(mtime < 0 || ctime < 0){
        return 0;
    }

    if(-1 != fd){
        struct timeval tv[2];
        tv[0].tv_sec = mtime;
        tv[0].tv_usec= 0L;
        tv[1].tv_sec = ctime;
        tv[1].tv_usec= 0L;
        if(-1 == futimes(fd, tv)){
            S3FS_PRN_ERR("futimes failed. errno(%d)", errno);
            return -errno;
        }
    }else if(!cachepath.empty()){
        // not opened file yet.
        struct utimbuf n_time;
        n_time.modtime = mtime;
        n_time.actime  = ctime;
        if(-1 == utime(cachepath.c_str(), &n_time)){
            S3FS_PRN_ERR("utime failed. errno(%d)", errno);
            return -errno;
        }
    }
    orgmeta["x-amz-meta-mtime"] = str(mtime);
    orgmeta["x-amz-meta-ctime"] = str(ctime);

    return 0;
}

bool FdEntity::UpdateCtime()
{
    AutoLock auto_lock(&fdent_lock);
    struct stat st;
    if(!GetStats(st, /*lock_already_held=*/ true)){
        return false;
    }
    orgmeta["x-amz-meta-ctime"] = str(st.st_ctime);
    return true;
}

bool FdEntity::UpdateAtime()
{
    AutoLock auto_lock(&fdent_lock);
    struct stat st;
    if(!GetStats(st, /*lock_already_held=*/ true)){
        return false;
    }
    orgmeta["x-amz-meta-atime"] = str(st.st_atime);
    return true;
}

bool FdEntity::UpdateMtime(bool clear_holding_mtime)
{
    AutoLock auto_lock(&fdent_lock);

    if(0 <= holding_mtime){
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
            if(!ClearHoldingMtime(true)){
                return false;
            }
        }
    }else{
        struct stat st;
        if(!GetStats(st, /*lock_already_held=*/ true)){
            return false;
        }
        orgmeta["x-amz-meta-mtime"] = str(st.st_mtime);
    }
    return true;
}

bool FdEntity::SetHoldingMtime(time_t mtime, bool lock_already_held)
{
    AutoLock auto_lock(&fdent_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);

    if(mtime < 0){
        return false;
    }
    holding_mtime = mtime;
    return true;
}

bool FdEntity::ClearHoldingMtime(bool lock_already_held)
{
    AutoLock auto_lock(&fdent_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);

    if(holding_mtime < 0){
        return false;
    }
    struct stat st;
    if(!GetStats(st, true)){
        return false;
    }
    if(-1 != fd){
        struct timeval tv[2];
        tv[0].tv_sec = holding_mtime;
        tv[0].tv_usec= 0L;
        tv[1].tv_sec = st.st_ctime;
        tv[1].tv_usec= 0L;
        if(-1 == futimes(fd, tv)){
            S3FS_PRN_ERR("futimes failed. errno(%d)", errno);
            return false;
        }
    }else if(!cachepath.empty()){
        // not opened file yet.
        struct utimbuf n_time;
        n_time.modtime = holding_mtime;
        n_time.actime  = st.st_ctime;
        if(-1 == utime(cachepath.c_str(), &n_time)){
            S3FS_PRN_ERR("utime failed. errno(%d)", errno);
            return false;
        }
    }
    holding_mtime = -1;

    return true;
}

bool FdEntity::GetSize(off_t& size)
{
    AutoLock auto_lock(&fdent_lock);
    if(-1 == fd){
        return false;
    }

    AutoLock auto_data_lock(&fdent_data_lock);
    size = pagelist.Size();
    return true;
}

bool FdEntity::GetXattr(std::string& xattr)
{
    AutoLock auto_lock(&fdent_lock);

    headers_t::const_iterator iter = orgmeta.find("x-amz-meta-xattr");
    if(iter == orgmeta.end()){
        return false;
    }
    xattr = iter->second;
    return true;
}

bool FdEntity::SetXattr(const std::string& xattr)
{
    AutoLock auto_lock(&fdent_lock);
    orgmeta["x-amz-meta-xattr"] = xattr;
    return true;
}

bool FdEntity::SetMode(mode_t mode)
{
    AutoLock auto_lock(&fdent_lock);
    orgmeta["x-amz-meta-mode"] = str(mode);
    return true;
}

bool FdEntity::SetUId(uid_t uid)
{
    AutoLock auto_lock(&fdent_lock);
    orgmeta["x-amz-meta-uid"] = str(uid);
    return true;
}

bool FdEntity::SetGId(gid_t gid)
{
    AutoLock auto_lock(&fdent_lock);
    orgmeta["x-amz-meta-gid"] = str(gid);
    return true;
}

bool FdEntity::SetContentType(const char* path)
{
    if(!path){
        return false;
    }
    AutoLock auto_lock(&fdent_lock);
    orgmeta["Content-Type"] = S3fsCurl::LookupMimeType(std::string(path));
    return true;
}

bool FdEntity::SetAllStatus(bool is_loaded)
{
    S3FS_PRN_INFO3("[path=%s][fd=%d][%s]", path.c_str(), fd, is_loaded ? "loaded" : "unloaded");

    if(-1 == fd){
        return false;
    }
    // [NOTE]
    // this method is only internal use, and calling after locking.
    // so do not lock now.
    //
    //AutoLock auto_lock(&fdent_lock);

    // get file size
    struct stat st;
    memset(&st, 0, sizeof(struct stat));
    if(-1 == fstat(fd, &st)){
        S3FS_PRN_ERR("fstat is failed. errno(%d)", errno);
        return false;
    }
    // Reinit
    pagelist.Init(st.st_size, is_loaded, false);

    return true;
}

int FdEntity::Load(off_t start, off_t size, bool lock_already_held, bool is_modified_flag)
{
    AutoLock auto_lock(&fdent_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);

    S3FS_PRN_DBG("[path=%s][fd=%d][offset=%lld][size=%lld]", path.c_str(), fd, static_cast<long long int>(start), static_cast<long long int>(size));

    if(-1 == fd){
        return -EBADF;
    }
    AutoLock auto_data_lock(&fdent_data_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);

    int result = 0;

    // check loaded area & load
    fdpage_list_t unloaded_list;
    if(0 < pagelist.GetUnloadedPages(unloaded_list, start, size)){
        for(fdpage_list_t::iterator iter = unloaded_list.begin(); iter != unloaded_list.end(); ++iter){
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
                result = S3fsCurl::ParallelGetObjectRequest(path.c_str(), fd, iter->offset, need_load_size);
            }else{
                // single request
                if(0 < need_load_size){
                    S3fsCurl s3fscurl;
                    result = s3fscurl.GetObjectRequest(path.c_str(), fd, iter->offset, need_load_size);
                }else{
                    result = 0;
                }
          }
          if(0 != result){
              break;
          }
          // Set loaded flag
          pagelist.SetPageLoadedStatus(iter->offset, iter->bytes, (is_modified_flag ? PageList::PAGE_LOAD_MODIFIED : PageList::PAGE_LOADED));
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
int FdEntity::NoCacheLoadAndPost(off_t start, off_t size)
{
    int result = 0;

    S3FS_PRN_INFO3("[path=%s][fd=%d][offset=%lld][size=%lld]", path.c_str(), fd, static_cast<long long int>(start), static_cast<long long int>(size));

    if(-1 == fd){
        return -EBADF;
    }

    // [NOTE]
    // This method calling means that the cache file is never used no more.
    //
    if(!cachepath.empty()){
        // remove cache files(and cache stat file)
        FdManager::DeleteCacheFile(path.c_str());
        // cache file path does not use no more.
        cachepath.erase();
        mirrorpath.erase();
    }

    // Change entity key in manager mapping
    FdManager::get()->ChangeEntityToTempPath(this, path.c_str());

    // open temporary file
    FILE* ptmpfp;
    int   tmpfd;
    if(NULL == (ptmpfp = tmpfile()) || -1 ==(tmpfd = fileno(ptmpfp))){
        S3FS_PRN_ERR("failed to open tmp file. err(%d)", errno);
        if(ptmpfp){
            fclose(ptmpfp);
        }
        return (0 == errno ? -EIO : -errno);
    }

    // loop uploading by multipart
    for(fdpage_list_t::iterator iter = pagelist.pages.begin(); iter != pagelist.pages.end(); ++iter){
        if(iter->end() < start){
            continue;
        }
        if(0 != size && start + size <= iter->offset){
            break;
        }
        // download each multipart size(default 10MB) in unit
        for(off_t oneread = 0, totalread = (iter->offset < start ? start : 0); totalread < static_cast<off_t>(iter->bytes); totalread += oneread){
            int   upload_fd = fd;
            off_t offset    = iter->offset + totalread;
            oneread         = std::min(static_cast<off_t>(iter->bytes) - totalread, S3fsCurl::GetMultipartSize());

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
                    S3FS_PRN_ERR("failed to truncate temporary file(%d).", tmpfd);
                    result = -EIO;
                    break;
                }

                // single area get request
                if(0 < need_load_size){
                    S3fsCurl s3fscurl;
                    if(0 != (result = s3fscurl.GetObjectRequest(path.c_str(), tmpfd, offset, oneread))){
                        S3FS_PRN_ERR("failed to get object(start=%lld, size=%lld) for file(%d).", static_cast<long long int>(offset), static_cast<long long int>(oneread), tmpfd);
                        break;
                    }
                }
                // initialize fd without loading
                if(0 < over_size){
                    if(0 != (result = FdEntity::FillFile(tmpfd, 0, over_size, offset + need_load_size))){
                        S3FS_PRN_ERR("failed to fill rest bytes for fd(%d). errno(%d)", tmpfd, result);
                        break;
                    }
                }
            }else{
                // already loaded area
            }

            // single area upload by multipart post
            if(0 != (result = NoCacheMultipartPost(upload_fd, offset, oneread))){
              S3FS_PRN_ERR("failed to multipart post(start=%lld, size=%lld) for file(%d).", static_cast<long long int>(offset), static_cast<long long int>(oneread), upload_fd);
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
                pagelist.pages.insert(iter, page);
            }
            if(0 != size && start + size < iter->next()){
                fdpage page(iter->offset, start + size - iter->offset, true, false);
                iter->bytes -= (start + size - iter->offset);
                iter->offset = start + size;
                pagelist.pages.insert(iter, page);
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
        if(-1 == ftruncate(fd, 0)){
            S3FS_PRN_ERR("failed to truncate file(%d), but continue...", fd);
        }
    }

    // close temporary
    fclose(ptmpfp);

    return result;
}

// [NOTE]
// At no disk space for caching object.
// This method is starting multipart uploading.
//
int FdEntity::NoCachePreMultipartPost()
{
    // initialize multipart upload values
    upload_id.erase();
    etaglist.clear();

    S3fsCurl s3fscurl(true);
    int      result;
    if(0 != (result = s3fscurl.PreMultipartPostRequest(path.c_str(), orgmeta, upload_id, false))){
        return result;
    }
    s3fscurl.DestroyCurlHandle();
    return 0;
}

// [NOTE]
// At no disk space for caching object.
// This method is uploading one part of multipart.
//
int FdEntity::NoCacheMultipartPost(int tgfd, off_t start, off_t size)
{
    if(-1 == tgfd || upload_id.empty()){
        S3FS_PRN_ERR("Need to initialize for multipart post.");
        return -EIO;
    }
    S3fsCurl s3fscurl(true);
    return s3fscurl.MultipartUploadRequest(upload_id, path.c_str(), tgfd, start, size, etaglist);
}

// [NOTE]
// At no disk space for caching object.
// This method is finishing multipart uploading.
//
int FdEntity::NoCacheCompleteMultipartPost()
{
    if(upload_id.empty() || etaglist.empty()){
        S3FS_PRN_ERR("There is no upload id or etag list.");
        return -EIO;
    }

    S3fsCurl s3fscurl(true);
    int      result;
    if(0 != (result = s3fscurl.CompleteMultipartPostRequest(path.c_str(), upload_id, etaglist))){
        return result;
    }
    s3fscurl.DestroyCurlHandle();

    // reset values
    upload_id.erase();
    etaglist.clear();
    mp_start = 0;
    mp_size  = 0;

    return 0;
}

off_t FdEntity::BytesModified() const {
    return pagelist.BytesModified();
}

int FdEntity::RowFlush(const char* tpath, bool force_sync)
{
    int result = 0;

    std::string tmppath;
    headers_t tmporgmeta;
    {
        AutoLock auto_lock(&fdent_lock);
        tmppath = path;
        tmporgmeta = orgmeta;
    }

    S3FS_PRN_INFO3("[tpath=%s][path=%s][fd=%d]", SAFESTRPTR(tpath), tmppath.c_str(), fd);

    if(-1 == fd){
        return -EBADF;
    }
    AutoLock auto_lock(&fdent_data_lock);

    if(!force_sync && !pagelist.IsModified()){
        // nothing to update.
        return 0;
    }

    // If there is no loading all of the area, loading all area.
    off_t restsize = pagelist.GetTotalUnloadedPageSize();
    if(0 < restsize){
        if(0 == upload_id.length()){
            // check disk space
            if(ReserveDiskSpace(restsize)){
                // enough disk space
                // Load all uninitialized area(no mix multipart uploading)
                if(!FdEntity::mixmultipart){
                    result = Load(/*start=*/ 0, /*size=*/ 0, /*lock_already_held=*/ true);
                }
                FdManager::FreeReservedDiskSpace(restsize);
                if(0 != result){
                    S3FS_PRN_ERR("failed to upload all area(errno=%d)", result);
                    return static_cast<ssize_t>(result);
                }
            }else{
              // no enough disk space
              // upload all by multipart uploading
              if(0 != (result = NoCacheLoadAndPost())){
                  S3FS_PRN_ERR("failed to upload all area by multipart uploading(errno=%d)", result);
                  return static_cast<ssize_t>(result);
              }
          }
      }else{
          // already start multipart uploading
      }
    }

    if(0 == upload_id.length()){
        // normal uploading
        //
        // Make decision to do multi upload (or not) based upon file size
        // 
        // According to the AWS spec:
        //  - 1 to 10,000 parts are allowed
        //  - minimum size of parts is 5MB (expect for the last part)
        // 
        // For our application, we will define minimum part size to be 10MB (10 * 2^20 Bytes)
        // minimum file size will be 64 GB - 2 ** 36 
        // 
        // Initially uploads will be done serially
        // 
        // If file is > 20MB, then multipart will kick in
        //
        if(pagelist.Size() > MAX_MULTIPART_CNT * S3fsCurl::GetMultipartSize()){
            // close f ?
            S3FS_PRN_ERR("Part count exceeds %d.  Increase multipart size and try again.", MAX_MULTIPART_CNT);
            return -ENOTSUP;
        }

        // seek to head of file.
        if(0 != lseek(fd, 0, SEEK_SET)){
            S3FS_PRN_ERR("lseek error(%d)", errno);
            return -errno;
        }
        // backup upload file size
        struct stat st;
        memset(&st, 0, sizeof(struct stat));
        if(-1 == fstat(fd, &st)){
            S3FS_PRN_ERR("fstat is failed by errno(%d), but continue...", errno);
        }

        if(pagelist.Size() >= S3fsCurl::GetMultipartSize() && !nomultipart){
            if(FdEntity::mixmultipart){
                // multipart uploading can use copy api

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
                for(fdpage_list_t::const_iterator iter = dlpages.begin(); iter != dlpages.end(); ++iter){
                    if(0 != (result = Load(iter->offset, iter->bytes, /*lock_already_held=*/ true, /*is_modified_flag=*/ true))){  // set loaded and modified flag
                        S3FS_PRN_ERR("failed to get parts(start=%lld, size=%lld) before uploading.", static_cast<long long int>(iter->offset), static_cast<long long int>(iter->bytes));
                        return result;
                    }
                }

                // multipart uploading with copy api
                result = S3fsCurl::ParallelMixMultipartUploadRequest(tpath ? tpath : tmppath.c_str(), tmporgmeta, fd, mixuppages);

            }else{
                // multipart uploading not using copy api
                result = S3fsCurl::ParallelMultipartUploadRequest(tpath ? tpath : tmppath.c_str(), tmporgmeta, fd);
            }
        }else{
            // If there are unloaded pages, they are loaded at here.
            if(0 != (result = Load(/*start=*/ 0, /*size=*/ 0, /*lock_already_held=*/ true))){
                S3FS_PRN_ERR("failed to load parts before uploading object(%d)", result);
                return result;
            }

            S3fsCurl s3fscurl(true);
            result = s3fscurl.PutRequest(tpath ? tpath : tmppath.c_str(), tmporgmeta, fd);
        }

        // seek to head of file.
        if(0 == result && 0 != lseek(fd, 0, SEEK_SET)){
            S3FS_PRN_ERR("lseek error(%d)", errno);
            return -errno;
        }

        // reset uploaded file size
        size_orgmeta = st.st_size;

    }else{
        // upload rest data
        if(0 < mp_size){
            if(0 != (result = NoCacheMultipartPost(fd, mp_start, mp_size))){
                S3FS_PRN_ERR("failed to multipart post(start=%lld, size=%lld) for file(%d).", static_cast<long long int>(mp_start), static_cast<long long int>(mp_size), fd);
                return result;
            }
            mp_start = 0;
            mp_size  = 0;
        }
        // complete multipart uploading.
        if(0 != (result = NoCacheCompleteMultipartPost())){
            S3FS_PRN_ERR("failed to complete(finish) multipart post for file(%d).", fd);
            return result;
        }
        // truncate file to zero
        if(-1 == ftruncate(fd, 0)){
            // So the file has already been removed, skip error.
            S3FS_PRN_ERR("failed to truncate file(%d) to zero, but continue...", fd);
        }
    
        // put pading headers
        if(0 != (result = UploadPendingMeta())){
            return result;
        }
    }

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
        if(-1 == ftruncate(fd, 0) || -1 == ftruncate(fd, pagelist.Size())){
            S3FS_PRN_ERR("failed to truncate temporary file(%d).", fd);
            return false;
        }

        if(FdManager::ReserveDiskSpace(size)){
            return true;
        }
    }

    FdManager::get()->CleanupCacheDir();

    return FdManager::ReserveDiskSpace(size);
}

ssize_t FdEntity::Read(char* bytes, off_t start, size_t size, bool force_load)
{
    S3FS_PRN_DBG("[path=%s][fd=%d][offset=%lld][size=%zu]", path.c_str(), fd, static_cast<long long int>(start), size);

    if(-1 == fd){
        return -EBADF;
    }
    AutoLock auto_lock(&fdent_data_lock);

    if(force_load){
        pagelist.SetPageLoadedStatus(start, size, PageList::PAGE_NOT_LOAD_MODIFIED);
    }

    ssize_t rsize;

    // check disk space
    if(0 < pagelist.GetTotalUnloadedPageSize(start, size)){
        // load size(for prefetch)
        size_t load_size = size;
        if(start + static_cast<ssize_t>(size) < pagelist.Size()){
            ssize_t prefetch_max_size = std::max(static_cast<off_t>(size), S3fsCurl::GetMultipartSize() * S3fsCurl::GetMaxParallelCount());

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
            result = Load(start, load_size, /*lock_already_held=*/ true);
        }

        FdManager::FreeReservedDiskSpace(load_size);

        if(0 != result){
            S3FS_PRN_ERR("could not download. start(%lld), size(%zu), errno(%d)", static_cast<long long int>(start), size, result);
            return -EIO;
        }
    }

    // Reading
    if(-1 == (rsize = pread(fd, bytes, size, start))){
        S3FS_PRN_ERR("pread failed. errno(%d)", errno);
        return -errno;
    }
    return rsize;
}

ssize_t FdEntity::Write(const char* bytes, off_t start, size_t size)
{
    S3FS_PRN_DBG("[path=%s][fd=%d][offset=%lld][size=%zu]", path.c_str(), fd, static_cast<long long int>(start), size);

    if(-1 == fd){
        return -EBADF;
    }
    // check if not enough disk space left BEFORE locking fd
    if(FdManager::IsCacheDir() && !FdManager::IsSafeDiskSpace(NULL, size)){
        FdManager::get()->CleanupCacheDir();
    }
    AutoLock auto_lock(&fdent_data_lock);

    // check file size
    if(pagelist.Size() < start){
        // grow file size
        if(-1 == ftruncate(fd, start)){
            S3FS_PRN_ERR("failed to truncate temporary file(%d).", fd);
            return -EIO;
        }
        // add new area
        pagelist.SetPageLoadedStatus(pagelist.Size(), start - pagelist.Size(), PageList::PAGE_MODIFIED);
    }

    int     result = 0;
    ssize_t wsize;

    if(0 == upload_id.length()){
        // check disk space
        off_t restsize = pagelist.GetTotalUnloadedPageSize(0, start) + size;
        if(ReserveDiskSpace(restsize)){
            // enough disk space

            // Load uninitialized area which starts from 0 to (start + size) before writing.
            if(!FdEntity::mixmultipart){
                if(0 < start){
                    result = Load(0, start, /*lock_already_held=*/ true);
                }
            }

            FdManager::FreeReservedDiskSpace(restsize);
            if(0 != result){
                S3FS_PRN_ERR("failed to load uninitialized area before writing(errno=%d)", result);
                return static_cast<ssize_t>(result);
            }
        }else{
            // no enough disk space
            if (nomultipart) {
                S3FS_PRN_WARN("Not enough local storage to cache write request: [path=%s][fd=%d][offset=%lld][size=%zu]", path.c_str(), fd, static_cast<long long int>(start), size);
                return -ENOSPC;   // No space left on device
            }
            if(0 != (result = NoCachePreMultipartPost())){
                S3FS_PRN_ERR("failed to switch multipart uploading with no cache(errno=%d)", result);
                return static_cast<ssize_t>(result);
            }
            // start multipart uploading
            if(0 != (result = NoCacheLoadAndPost(0, start))){
                S3FS_PRN_ERR("failed to load uninitialized area and multipart uploading it(errno=%d)", result);
                return static_cast<ssize_t>(result);
            }
            mp_start = start;
            mp_size  = 0;
        }
    }else{
        // already start multipart uploading
    }

    // Writing
    if(-1 == (wsize = pwrite(fd, bytes, size, start))){
        S3FS_PRN_ERR("pwrite failed. errno(%d)", errno);
        return -errno;
    }
    if(0 < wsize){
        pagelist.SetPageLoadedStatus(start, wsize, PageList::PAGE_LOAD_MODIFIED);
    }

    // Load uninitialized area which starts from (start + size) to EOF after writing.
    if(!FdEntity::mixmultipart){
        if(pagelist.Size() > start + static_cast<off_t>(size)){
            result = Load(start + size, pagelist.Size(), /*lock_already_held=*/ true);
            if(0 != result){
                S3FS_PRN_ERR("failed to load uninitialized area after writing(errno=%d)", result);
                return static_cast<ssize_t>(result);
            }
        }
    }

    // check multipart uploading
    if(0 < upload_id.length()){
        mp_size += wsize;
        if(S3fsCurl::GetMultipartSize() <= mp_size){
            // over one multipart size
            if(0 != (result = NoCacheMultipartPost(fd, mp_start, mp_size))){
                S3FS_PRN_ERR("failed to multipart post(start=%lld, size=%lld) for file(%d).", static_cast<long long int>(mp_start), static_cast<long long int>(mp_size), fd);
                return result;
            }
            // [NOTE]
            // truncate file to zero and set length to part offset + size
            // after this, file length is (offset + size), but file does not use any disk space.
            //
            if(-1 == ftruncate(fd, 0) || -1 == ftruncate(fd, (mp_start + mp_size))){
                S3FS_PRN_ERR("failed to truncate file(%d).", fd);
                return -EIO;
            }
            mp_start += mp_size;
            mp_size   = 0;
        }
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
    AutoLock auto_lock(&fdent_lock);

    merge_headers(orgmeta, updatemeta, true);      // overwrite all keys
    // [NOTE]
    // this is special cases, we remove the key which has empty values.
    for(headers_t::iterator hiter = orgmeta.begin(); hiter != orgmeta.end(); ){
        if(hiter->second.empty()){
            orgmeta.erase(hiter++);
        }else{
            ++hiter;
        }
    }
    updatemeta = orgmeta;
    orgmeta.erase("x-amz-copy-source");

    // update ctime/mtime/atime
    time_t mtime = get_mtime(updatemeta, false);      // not overcheck
    time_t ctime = get_ctime(updatemeta, false);      // not overcheck
    time_t atime = get_atime(updatemeta, false);      // not overcheck
    if(0 <= mtime){
        SetMCtime(mtime, (ctime < 0 ? mtime : ctime), true);
    }
    if(0 <= atime){
        SetAtime(atime, true);
    }
    is_meta_pending |= !upload_id.empty();

    return is_meta_pending;
}

// global function in s3fs.cpp
int put_headers(const char* path, headers_t& meta, bool is_copy);

int FdEntity::UploadPendingMeta()
{
    if(!is_meta_pending) {
       return 0;
    }

    AutoLock auto_lock(&fdent_lock);
    headers_t updatemeta = orgmeta;
    updatemeta["x-amz-copy-source"]        = urlEncode(service_path + bucket + get_realpath(path.c_str()));
    // put headers, no need to update mtime to avoid dead lock
    int result = put_headers(path.c_str(), updatemeta, true);
    if(0 != result){
        S3FS_PRN_ERR("failed to put header after flushing file(%s) by(%d).", path.c_str(), result);
    }
    is_meta_pending = false;
    return result;
}

// [NOTE]
// For systems where the fallocate function cannot be detected, use a dummy function.
// ex. OSX
//
#ifndef HAVE_FALLOCATE
// We need the symbols defined in fallocate, so we define them here.
// The definitions are copied from linux/falloc.h, but if HAVE_FALLOCATE is undefined,
// these values can be anything.
//
#define FALLOC_FL_PUNCH_HOLE     0x02 /* de-allocates range */
#define FALLOC_FL_KEEP_SIZE      0x01

static int fallocate(int /*fd*/, int /*mode*/, off_t /*offset*/, off_t /*len*/)
{
    errno = ENOSYS;     // This is a bad idea, but the caller can handle it simply.
    return -1;
}
#endif  // HAVE_FALLOCATE

// [NOTE]
// This method punches an area(on cache file) that has no data at the time it is called.
// This is called to prevent the cache file from growing.
// However, this method uses the non-portable(Linux specific) system call fallocate().
// Also, depending on the file system, FALLOC_FL_PUNCH_HOLE mode may not work and HOLE
// will not open.(Filesystems for which this method works are ext4, btrfs, xfs, etc.)
// 
bool FdEntity::PunchHole(off_t start, size_t size)
{
    S3FS_PRN_DBG("[path=%s][fd=%d][offset=%lld][size=%zu]", path.c_str(), fd, static_cast<long long int>(start), size);

    if(-1 == fd){
        return false;
    }
    AutoLock auto_lock(&fdent_data_lock);

    // get page list that have no data
    fdpage_list_t   nodata_pages;
    if(!pagelist.GetNoDataPageLists(nodata_pages)){
        S3FS_PRN_ERR("filed to get page list that have no data.");
        return false;
    }
    if(nodata_pages.empty()){
        S3FS_PRN_DBG("there is no page list that have no data, so nothing to do.");
        return true;
    }

    // try to punch hole to file
    for(fdpage_list_t::const_iterator iter = nodata_pages.begin(); iter != nodata_pages.end(); ++iter){
        if(0 != fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, iter->offset, iter->bytes)){
            if(ENOSYS == errno || EOPNOTSUPP == errno){
                S3FS_PRN_ERR("filed to fallocate for punching hole to file with errno(%d), it maybe the fallocate function is not implemented in this kernel, or the file system does not support FALLOC_FL_PUNCH_HOLE.", errno);
            }else{
                S3FS_PRN_ERR("filed to fallocate for punching hole to file with errno(%d)", errno);
            }
            return false;
        }
        if(!pagelist.SetPageLoadedStatus(iter->offset, iter->bytes, PageList::PAGE_NOT_LOAD_MODIFIED)){
            S3FS_PRN_ERR("succeed to punch HOLEs in the cache file, but failed to update the cache stat.");
            return false;
        }
        S3FS_PRN_DBG("made a hole at [%lld - %lld bytes](into a boundary) of the cache file.", static_cast<long long int>(iter->offset), static_cast<long long int>(iter->bytes));
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
