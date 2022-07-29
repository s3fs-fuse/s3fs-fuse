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
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "s3fs_logger.h"
#include "fdcache_stat.h"
#include "fdcache.h"
#include "s3fs_util.h"
#include "s3fs_cred.h"
#include "string_util.h"

//------------------------------------------------
// CacheFileStat class methods
//------------------------------------------------
std::string CacheFileStat::GetCacheFileStatTopDir()
{
    std::string top_path;
    if(!FdManager::IsCacheDir() || S3fsCred::GetBucket().empty()){
        return top_path;
    }

    // stat top dir( "/<cache_dir>/.<bucket_name>.stat" )
    top_path += FdManager::GetCacheDir();
    top_path += "/.";
    top_path += S3fsCred::GetBucket();
    top_path += ".stat";
    return top_path;
}

bool CacheFileStat::MakeCacheFileStatPath(const char* path, std::string& sfile_path, bool is_create_dir)
{
    std::string top_path = CacheFileStat::GetCacheFileStatTopDir();
    if(top_path.empty()){
        S3FS_PRN_ERR("The path to cache top dir is empty.");
        return false;
    }

    if(is_create_dir){
      int result;
      if(0 != (result = mkdirp(top_path + mydirname(path), 0777))){
          S3FS_PRN_ERR("failed to create dir(%s) by errno(%d).", path, result);
          return false;
      }
    }
    if(!path || '\0' == path[0]){
        sfile_path = top_path;
    }else{
        sfile_path = top_path + SAFESTRPTR(path);
    }
    return true;
}

bool CacheFileStat::CheckCacheFileStatTopDir()
{
    std::string top_path = CacheFileStat::GetCacheFileStatTopDir();
    if(top_path.empty()){
        S3FS_PRN_INFO("The path to cache top dir is empty, thus not need to check permission.");
        return true;
    }

    return check_exist_dir_permission(top_path.c_str());
}

bool CacheFileStat::DeleteCacheFileStat(const char* path)
{
    if(!path || '\0' == path[0]){
        return false;
    }
    // stat path
    std::string sfile_path;
    if(!CacheFileStat::MakeCacheFileStatPath(path, sfile_path, false)){
        S3FS_PRN_ERR("failed to create cache stat file path(%s)", path);
        return false;
    }
    if(0 != unlink(sfile_path.c_str())){
        if(ENOENT == errno){
            S3FS_PRN_DBG("failed to delete file(%s): errno=%d", path, errno);
        }else{
            S3FS_PRN_ERR("failed to delete file(%s): errno=%d", path, errno);
        }
        return false;
    }
    return true;
}

// [NOTE]
// If remove stat file directory, it should do before removing
// file cache directory.
//
bool CacheFileStat::DeleteCacheFileStatDirectory()
{
    std::string top_path = CacheFileStat::GetCacheFileStatTopDir();
    if(top_path.empty()){
        S3FS_PRN_INFO("The path to cache top dir is empty, thus not need to remove it.");
        return true;
    }
    return delete_files_in_dir(top_path.c_str(), true);
}

bool CacheFileStat::RenameCacheFileStat(const char* oldpath, const char* newpath)
{
    if(!oldpath || '\0' == oldpath[0] || !newpath || '\0' == newpath[0]){
        return false;
    }

    // stat path
    std::string old_filestat;
    std::string new_filestat;
    if(!CacheFileStat::MakeCacheFileStatPath(oldpath, old_filestat, false) || !CacheFileStat::MakeCacheFileStatPath(newpath, new_filestat, false)){
        return false;
    }

    // check new stat path
    struct stat st;
    if(0 == stat(new_filestat.c_str(), &st)){
        // new stat path is existed, then unlink it.
        if(-1 == unlink(new_filestat.c_str())){
            S3FS_PRN_ERR("failed to unlink new cache file stat path(%s) by errno(%d).", new_filestat.c_str(), errno);
            return false;
        }
    }

    // check old stat path
    if(0 != stat(old_filestat.c_str(), &st)){
        // old stat path is not existed, then nothing to do any more.
        return true;
    }

    // link and unlink
    if(-1 == link(old_filestat.c_str(), new_filestat.c_str())){
        S3FS_PRN_ERR("failed to link old cache file stat path(%s) to new cache file stat path(%s) by errno(%d).", old_filestat.c_str(), new_filestat.c_str(), errno);
        return false;
    }
    if(-1 == unlink(old_filestat.c_str())){
        S3FS_PRN_ERR("failed to unlink old cache file stat path(%s) by errno(%d).", old_filestat.c_str(), errno);
        return false;
    }
   return true;
}

//------------------------------------------------
// CacheFileStat methods
//------------------------------------------------
CacheFileStat::CacheFileStat(const char* tpath) : fd(-1)
{
    if(tpath && '\0' != tpath[0]){
        SetPath(tpath, true);
    }
}

CacheFileStat::~CacheFileStat()
{
    Release();
}

bool CacheFileStat::SetPath(const char* tpath, bool is_open)
{
    if(!tpath || '\0' == tpath[0]){
        return false;
    }
    if(!Release()){
        // could not close old stat file.
        return false;
    }
    path = tpath;
    if(!is_open){
        return true;
    }
    return Open();
}

bool CacheFileStat::RawOpen(bool readonly)
{
    if(path.empty()){
        return false;
    }
    if(-1 != fd){
        // already opened
        return true;
    }
    // stat path
    std::string sfile_path;
    if(!CacheFileStat::MakeCacheFileStatPath(path.c_str(), sfile_path, true)){
        S3FS_PRN_ERR("failed to create cache stat file path(%s)", path.c_str());
        return false;
    }
    // open
    if(readonly){
        if(-1 == (fd = open(sfile_path.c_str(), O_RDONLY))){
            S3FS_PRN_ERR("failed to read only open cache stat file path(%s) - errno(%d)", path.c_str(), errno);
            return false;
        }
    }else{
        if(-1 == (fd = open(sfile_path.c_str(), O_CREAT|O_RDWR, 0600))){
            S3FS_PRN_ERR("failed to open cache stat file path(%s) - errno(%d)", path.c_str(), errno);
            return false;
        }
    }
    // lock
    if(-1 == flock(fd, LOCK_EX)){
        S3FS_PRN_ERR("failed to lock cache stat file(%s) - errno(%d)", path.c_str(), errno);
        close(fd);
        fd = -1;
        return false;
    }
    // seek top
    if(0 != lseek(fd, 0, SEEK_SET)){
        S3FS_PRN_ERR("failed to lseek cache stat file(%s) - errno(%d)", path.c_str(), errno);
        flock(fd, LOCK_UN);
        close(fd);
        fd = -1;
        return false;
    }
    S3FS_PRN_DBG("file locked(%s - %s)", path.c_str(), sfile_path.c_str());

    return true;
}

bool CacheFileStat::Open()
{
    return RawOpen(false);
}

bool CacheFileStat::ReadOnlyOpen()
{
    return RawOpen(true);
}

bool CacheFileStat::Release()
{
    if(-1 == fd){
        // already release
        return true;
    }
    // unlock
    if(-1 == flock(fd, LOCK_UN)){
        S3FS_PRN_ERR("failed to unlock cache stat file(%s) - errno(%d)", path.c_str(), errno);
        return false;
    }
    S3FS_PRN_DBG("file unlocked(%s)", path.c_str());

    if(-1 == close(fd)){
        S3FS_PRN_ERR("failed to close cache stat file(%s) - errno(%d)", path.c_str(), errno);
        return false;
    }
    fd = -1;

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
