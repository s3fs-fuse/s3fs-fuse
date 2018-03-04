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
#ifndef FD_CACHE_H_
#define FD_CACHE_H_

#include <sys/statvfs.h>
#include "curl.h"

//------------------------------------------------
// CacheFileStat
//------------------------------------------------
class CacheFileStat
{
  private:
    std::string path;
    int         fd;

  private:
    static bool MakeCacheFileStatPath(const char* path, std::string& sfile_path, bool is_create_dir = true);

  public:
    static bool DeleteCacheFileStat(const char* path);
    static bool CheckCacheFileStatTopDir(void);
    static bool DeleteCacheFileStatDirectory(void);

    explicit CacheFileStat(const char* tpath = NULL);
    ~CacheFileStat();

    bool Open(void);
    bool Release(void);
    bool SetPath(const char* tpath, bool is_open = true);
    int GetFd(void) const { return fd; }
};

//------------------------------------------------
// fdpage & PageList
//------------------------------------------------
// page block information
struct fdpage
{
  off_t  offset;
  size_t bytes;
  bool   loaded;

  fdpage(off_t start = 0, size_t size = 0, bool is_loaded = false)
           : offset(start), bytes(size), loaded(is_loaded) {}

  off_t next(void) const { return (offset + bytes); }
  off_t end(void) const { return (0 < bytes ? offset + bytes - 1 : 0); }
};
typedef std::list<struct fdpage*> fdpage_list_t;

class FdEntity;

//
// Management of loading area/modifying
//
class PageList
{
  friend class FdEntity;    // only one method access directly pages.

  private:
    fdpage_list_t pages;

  private:
    void Clear(void);
    bool Compress(void);
    bool Parse(off_t new_pos);

  public:
    static void FreeList(fdpage_list_t& list);

    explicit PageList(size_t size = 0, bool is_loaded = false);
    ~PageList();

    bool Init(size_t size, bool is_loaded);
    size_t Size(void) const;
    bool Resize(size_t size, bool is_loaded);

    bool IsPageLoaded(off_t start = 0, size_t size = 0) const;                  // size=0 is checking to end of list
    bool SetPageLoadedStatus(off_t start, size_t size, bool is_loaded = true, bool is_compress = true);
    bool FindUnloadedPage(off_t start, off_t& resstart, size_t& ressize) const;
    size_t GetTotalUnloadedPageSize(off_t start = 0, size_t size = 0) const;    // size=0 is checking to end of list
    int GetUnloadedPages(fdpage_list_t& unloaded_list, off_t start = 0, size_t size = 0) const;  // size=0 is checking to end of list

    bool Serialize(CacheFileStat& file, bool is_output);
    void Dump(void);
};

//------------------------------------------------
// class FdEntity
//------------------------------------------------
class FdEntity
{
  private:
    pthread_mutex_t fdent_lock;
    bool            is_lock_init;
    PageList        pagelist;
    int             refcnt;         // reference count
    std::string     path;           // object path
    std::string     cachepath;      // local cache file path
                                    // (if this is empty, does not load/save pagelist.)
    std::string     mirrorpath;     // mirror file path to local cache file path
    int             fd;             // file descriptor(tmp file or cache file)
    FILE*           pfile;          // file pointer(tmp file or cache file)
    bool            is_modify;      // if file is changed, this flag is true
    headers_t       orgmeta;        // original headers at opening
    size_t          size_orgmeta;   // original file size in original headers

    std::string     upload_id;      // for no cached multipart uploading when no disk space
    etaglist_t      etaglist;       // for no cached multipart uploading when no disk space
    off_t           mp_start;       // start position for no cached multipart(write method only)
    size_t          mp_size;        // size for no cached multipart(write method only)

  private:
    static int FillFile(int fd, unsigned char byte, size_t size, off_t start);

    void Clear(void);
    int OpenMirrorFile(void);
    bool SetAllStatus(bool is_loaded);                          // [NOTE] not locking
    //bool SetAllStatusLoaded(void) { return SetAllStatus(true); }
    bool SetAllStatusUnloaded(void) { return SetAllStatus(false); }

  public:
    explicit FdEntity(const char* tpath = NULL, const char* cpath = NULL);
    ~FdEntity();

    void Close(void);
    bool IsOpen(void) const { return (-1 != fd); }
    bool IsMultiOpened(void) const { return refcnt > 1; }
    int Open(headers_t* pmeta = NULL, ssize_t size = -1, time_t time = -1, bool no_fd_lock_wait = false);
    bool OpenAndLoadAll(headers_t* pmeta = NULL, size_t* size = NULL, bool force_load = false);
    int Dup();

    const char* GetPath(void) const { return path.c_str(); }
    void SetPath(const std::string &newpath) { path = newpath; }
    int GetFd(void) const { return fd; }

    bool GetStats(struct stat& st);
    int SetMtime(time_t time);
    bool UpdateMtime(void);
    bool GetSize(size_t& size);
    bool SetMode(mode_t mode);
    bool SetUId(uid_t uid);
    bool SetGId(gid_t gid);
    bool SetContentType(const char* path);

    int Load(off_t start = 0, size_t size = 0);                 // size=0 means loading to end
    int NoCacheLoadAndPost(off_t start = 0, size_t size = 0);   // size=0 means loading to end
    int NoCachePreMultipartPost(void);
    int NoCacheMultipartPost(int tgfd, off_t start, size_t size);
    int NoCacheCompleteMultipartPost(void);

    int RowFlush(const char* tpath, bool force_sync = false);
    int Flush(bool force_sync = false) { return RowFlush(NULL, force_sync); }

    ssize_t Read(char* bytes, off_t start, size_t size, bool force_load = false);
    ssize_t Write(const char* bytes, off_t start, size_t size);

    bool ReserveDiskSpace(size_t size);
    void CleanupCache();
};
typedef std::map<std::string, class FdEntity*> fdent_map_t;   // key=path, value=FdEntity*

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
    static size_t          free_disk_space; // limit free disk space

    fdent_map_t            fent;

  private:
    static uint64_t GetFreeDiskSpace(const char* path);
    void CleanupCacheDirInternal(const std::string &path = "");

  public:
    FdManager();
    ~FdManager();

    // Reference singleton
    static FdManager* get(void) { return &singleton; }

    static bool DeleteCacheDirectory(void);
    static int DeleteCacheFile(const char* path);
    static bool SetCacheDir(const char* dir);
    static bool IsCacheDir(void) { return (0 < FdManager::cache_dir.size()); }
    static const char* GetCacheDir(void) { return FdManager::cache_dir.c_str(); }
    static bool MakeCachePath(const char* path, std::string& cache_path, bool is_create_dir = true, bool is_mirror_path = false);
    static bool CheckCacheTopDir(void);
    static bool MakeRandomTempPath(const char* path, std::string& tmppath);
    static bool SetCheckCacheDirExist(bool is_check);
    static bool CheckCacheDirExist(void);

    static size_t GetEnsureFreeDiskSpace(void) { return FdManager::free_disk_space; }
    static size_t SetEnsureFreeDiskSpace(size_t size);
    static bool IsSafeDiskSpace(const char* path, size_t size);
    static void FreeReservedDiskSpace(size_t size);
    bool ReserveDiskSpace(size_t size);

    FdEntity* GetFdEntity(const char* path, int existfd = -1);
    FdEntity* Open(const char* path, headers_t* pmeta = NULL, ssize_t size = -1, time_t time = -1, bool force_tmpfile = false, bool is_create = true, bool no_fd_lock_wait = false);
    FdEntity* ExistOpen(const char* path, int existfd = -1, bool ignore_existfd = false);
    void Rename(const std::string &from, const std::string &to);
    bool Close(FdEntity* ent);
    bool ChangeEntityToTempPath(FdEntity* ent, const char* path);
    void CleanupCacheDir();
};

#endif // FD_CACHE_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
