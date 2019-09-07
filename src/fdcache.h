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
    static bool RenameCacheFileStat(const char* oldpath, const char* newpath);

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
  off_t  bytes;
  bool   loaded;
  bool   modified;

  fdpage(off_t start = 0, off_t  size = 0, bool is_loaded = false, bool is_modified = false)
           : offset(start), bytes(size), loaded(is_loaded), modified(is_modified) {}

  off_t next(void) const { return (offset + bytes); }
  off_t end(void) const { return (0 < bytes ? offset + bytes - 1 : 0); }
};
typedef std::list<struct fdpage> fdpage_list_t;

class FdEntity;

//
// Management of loading area/modifying
//
// cppcheck-suppress copyCtorAndEqOperator
class PageList
{
  friend class FdEntity;    // only one method access directly pages.

  private:
    fdpage_list_t pages;

  public:
    enum page_status{
      PAGE_NOT_LOAD_MODIFIED = 0,
      PAGE_LOADED,
      PAGE_MODIFIED,
      PAGE_LOAD_MODIFIED
    };

  private:
    void Clear(void);
    bool Compress(bool force_modified = false);
    bool Parse(off_t new_pos);
    bool RawGetUnloadPageList(fdpage_list_t& dlpages, off_t offset, off_t size);

  public:
    static void FreeList(fdpage_list_t& list);

    explicit PageList(off_t size = 0, bool is_loaded = false, bool is_modified = false);
    explicit PageList(const PageList& other);
    ~PageList();

    bool Init(off_t size, bool is_loaded, bool is_modified);
    off_t Size(void) const;
    bool Resize(off_t size, bool is_loaded, bool is_modified);

    bool IsPageLoaded(off_t start = 0, off_t size = 0) const;                  // size=0 is checking to end of list
    bool SetPageLoadedStatus(off_t start, off_t size, PageList::page_status pstatus = PAGE_LOADED, bool is_compress = true);
    bool FindUnloadedPage(off_t start, off_t& resstart, off_t& ressize) const;
    off_t GetTotalUnloadedPageSize(off_t start = 0, off_t size = 0) const;    // size=0 is checking to end of list
    int GetUnloadedPages(fdpage_list_t& unloaded_list, off_t start = 0, off_t size = 0) const;  // size=0 is checking to end of list
    bool GetLoadPageListForMultipartUpload(fdpage_list_t& dlpages);
    bool GetMultipartSizeList(fdpage_list_t& mplist, off_t partsize) const;

    bool IsModified(void) const;
    bool ClearAllModified(void);

    bool Serialize(CacheFileStat& file, bool is_output);
    void Dump(void);
};

//------------------------------------------------
// class FdEntity
//------------------------------------------------
class FdEntity
{
  private:
    static bool     mixmultipart;   // whether multipart uploading can use copy api.

    pthread_mutex_t fdent_lock;
    bool            is_lock_init;
    int             refcnt;         // reference count
    std::string     path;           // object path
    int             fd;             // file descriptor(tmp file or cache file)
    FILE*           pfile;          // file pointer(tmp file or cache file)
    headers_t       orgmeta;        // original headers at opening
    off_t           size_orgmeta;   // original file size in original headers

    pthread_mutex_t fdent_data_lock;// protects the following members
    PageList        pagelist;
    std::string     upload_id;      // for no cached multipart uploading when no disk space
    etaglist_t      etaglist;       // for no cached multipart uploading when no disk space
    off_t           mp_start;       // start position for no cached multipart(write method only)
    off_t           mp_size;        // size for no cached multipart(write method only)
    std::string     cachepath;      // local cache file path
                                    // (if this is empty, does not load/save pagelist.)
    std::string     mirrorpath;     // mirror file path to local cache file path

  private:
    static int FillFile(int fd, unsigned char byte, off_t size, off_t start);

    void Clear(void);
    int OpenMirrorFile(void);
    bool SetAllStatus(bool is_loaded);                          // [NOTE] not locking
    //bool SetAllStatusLoaded(void) { return SetAllStatus(true); }
    bool SetAllStatusUnloaded(void) { return SetAllStatus(false); }

  public:
    static bool SetNoMixMultipart(void);

    explicit FdEntity(const char* tpath = NULL, const char* cpath = NULL);
    ~FdEntity();

    void Close(void);
    bool IsOpen(void) const { return (-1 != fd); }
    int Open(headers_t* pmeta = NULL, off_t size = -1, time_t time = -1, bool no_fd_lock_wait = false);
    bool OpenAndLoadAll(headers_t* pmeta = NULL, off_t* size = NULL, bool force_load = false);
    int Dup(bool lock_already_held = false);

    const char* GetPath(void) const { return path.c_str(); }
    bool RenamePath(const std::string& newpath, std::string& fentmapkey);
    int GetFd(void) const { return fd; }
    bool IsModified(void) const { return pagelist.IsModified(); }

    bool GetStats(struct stat& st, bool lock_already_held = false);
    int SetCtime(time_t time);
    int SetMtime(time_t time, bool lock_already_held = false);
    bool UpdateCtime(void);
    bool UpdateMtime(void);
    bool GetSize(off_t& size);
    bool SetMode(mode_t mode);
    bool SetUId(uid_t uid);
    bool SetGId(gid_t gid);
    bool SetContentType(const char* path);

    int Load(off_t start = 0, off_t size = 0, bool lock_already_held = false);  // size=0 means loading to end
    int NoCacheLoadAndPost(off_t start = 0, off_t size = 0);   // size=0 means loading to end
    int NoCachePreMultipartPost(void);
    int NoCacheMultipartPost(int tgfd, off_t start, off_t size);
    int NoCacheCompleteMultipartPost(void);

    int RowFlush(const char* tpath, bool force_sync = false);
    int Flush(bool force_sync = false) { return RowFlush(NULL, force_sync); }

    ssize_t Read(char* bytes, off_t start, size_t size, bool force_load = false);
    ssize_t Write(const char* bytes, off_t start, size_t size);

    bool ReserveDiskSpace(off_t size);
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
    static off_t           free_disk_space; // limit free disk space

    fdent_map_t            fent;

  private:
    static off_t GetFreeDiskSpace(const char* path);
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

    static off_t GetEnsureFreeDiskSpace();
    static off_t SetEnsureFreeDiskSpace(off_t size);
    static bool IsSafeDiskSpace(const char* path, off_t size);
    static void FreeReservedDiskSpace(off_t size);
    static bool ReserveDiskSpace(off_t size);

    // Return FdEntity associated with path, returning NULL on error.  This operation increments the reference count; callers must decrement via Close after use.
    FdEntity* GetFdEntity(const char* path, int existfd = -1);
    FdEntity* Open(const char* path, headers_t* pmeta = NULL, off_t size = -1, time_t time = -1, bool force_tmpfile = false, bool is_create = true, bool no_fd_lock_wait = false);
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
