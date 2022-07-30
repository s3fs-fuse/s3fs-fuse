/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2007 Randy Rizun <rrizun@gmail.com>
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

#ifndef S3FS_FDCACHE_H_
#define S3FS_FDCACHE_H_

#include "fdcache_entity.h"

//------------------------------------------------
// class FdManager
//------------------------------------------------
class FdManager
{
  private:
      static FdManager       singleton;
      static pthread_mutex_t fd_manager_lock;
      static pthread_mutex_t cache_cleanup_lock;
      static pthread_mutex_t reserved_diskspace_lock;
      static bool            is_lock_init;
      static std::string     cache_dir;
      static bool            check_cache_dir_exist;
      static off_t           free_disk_space;       // limit free disk space
      static off_t           fake_used_disk_space;  // difference between fake free disk space and actual at startup(for test/debug)
      static std::string     check_cache_output;
      static bool            checked_lseek;
      static bool            have_lseek_hole;
      static std::string     tmp_dir;

      fdent_map_t            fent;

  private:
      static off_t GetFreeDiskSpace(const char* path);
      static bool IsDir(const std::string* dir);

      int GetPseudoFdCount(const char* path);
      void CleanupCacheDirInternal(const std::string &path = "");
      bool RawCheckAllCache(FILE* fp, const char* cache_stat_top_dir, const char* sub_path, int& total_file_cnt, int& err_file_cnt, int& err_dir_cnt);

  public:
      FdManager();
      ~FdManager();

      // Reference singleton
      static FdManager* get() { return &singleton; }

      static bool DeleteCacheDirectory();
      static int DeleteCacheFile(const char* path);
      static bool SetCacheDir(const char* dir);
      static bool IsCacheDir() { return !FdManager::cache_dir.empty(); }
      static const char* GetCacheDir() { return FdManager::cache_dir.c_str(); }
      static bool SetCacheCheckOutput(const char* path);
      static const char* GetCacheCheckOutput() { return FdManager::check_cache_output.c_str(); }
      static bool MakeCachePath(const char* path, std::string& cache_path, bool is_create_dir = true, bool is_mirror_path = false);
      static bool CheckCacheTopDir();
      static bool MakeRandomTempPath(const char* path, std::string& tmppath);
      static bool SetCheckCacheDirExist(bool is_check);
      static bool CheckCacheDirExist();
      static bool HasOpenEntityFd(const char* path);
      static int GetOpenFdCount(const char* path);
      static off_t GetEnsureFreeDiskSpace();
      static off_t SetEnsureFreeDiskSpace(off_t size);
      static bool InitFakeUsedDiskSize(off_t fake_freesize);
      static bool IsSafeDiskSpace(const char* path, off_t size);
      static void FreeReservedDiskSpace(off_t size);
      static bool ReserveDiskSpace(off_t size);
      static bool HaveLseekHole();
      static bool SetTmpDir(const char* dir);
      static bool CheckTmpDirExist();
      static FILE* MakeTempFile();

      // Return FdEntity associated with path, returning NULL on error.  This operation increments the reference count; callers must decrement via Close after use.
      FdEntity* GetFdEntity(const char* path, int& existfd, bool newfd = true, AutoLock::Type locktype = AutoLock::NONE);
      FdEntity* Open(int& fd, const char* path, headers_t* pmeta, off_t size, const struct timespec& ts_mctime, int flags, bool force_tmpfile, bool is_create, bool ignore_modify, AutoLock::Type type);
      FdEntity* GetExistFdEntity(const char* path, int existfd = -1);
      FdEntity* OpenExistFdEntity(const char* path, int& fd, int flags = O_RDONLY);
      void Rename(const std::string &from, const std::string &to);
      bool Close(FdEntity* ent, int fd);
      bool ChangeEntityToTempPath(FdEntity* ent, const char* path);
      void CleanupCacheDir();

      bool CheckAllCache();
};

#endif // S3FS_FDCACHE_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
