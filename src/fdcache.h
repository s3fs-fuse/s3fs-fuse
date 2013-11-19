#ifndef FD_CACHE_H_
#define FD_CACHE_H_

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

    CacheFileStat(const char* tpath = NULL);
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
  bool   init;

  fdpage(off_t start = 0, size_t size = 0, bool is_init = false)
           : offset(start), bytes(size), init(is_init) {}

  off_t next(void) const { return (offset + bytes); }
  off_t end(void) const { return (0 < bytes ? offset + bytes - 1 : 0); }
};
typedef std::list<struct fdpage*> fdpage_list_t;

//
// Management of loading area/modifying
//
class PageList
{
  private:
    fdpage_list_t pages;

  private:
    void Clear(void);

  public:
    static void FreeList(fdpage_list_t& list);

    PageList(off_t size = 0, bool is_init = false);
    ~PageList();

    off_t Size(void) const;
    int Resize(off_t size, bool is_init);
    int Init(off_t size, bool is_init);
    bool IsInit(off_t start, off_t size);
    bool SetInit(off_t start, off_t size, bool is_init = true);
    bool FindUninitPage(off_t start, off_t& resstart, size_t& ressize);
    int GetUninitPages(fdpage_list_t& uninit_list, off_t start = 0);
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
    int             refcnt;     // reference count
    std::string     path;       // object path
    std::string     cachepath;  // local cache file path
    int             fd;         // file discriptor(tmp file or cache file)
    FILE*           file;       // file pointer(tmp file or cache file)
    bool            is_modify;  // if file is changed, this flag is true

  private:
    void Clear(void);
    int Dup(void);
    bool SetAllStatus(bool is_enable);

  public:
    FdEntity(const char* tpath = NULL, const char* cpath = NULL);
    ~FdEntity();

    void Close(void);
    bool IsOpen(void) const { return (-1 != fd); }
    int Open(off_t size = -1, time_t time = -1);
    const char* GetPath(void) const { return path.c_str(); }
    int GetFd(void) const { return fd; }
    int SetMtime(time_t time);
    bool GetSize(off_t& size);
    bool GetMtime(time_t& time);
    bool GetStats(struct stat& st);

    bool SetAllEnable(void) { return SetAllStatus(true); }
    bool SetAllDisable(void) { return SetAllStatus(false); }
    bool LoadFull(off_t* size = NULL, bool force_load = false);
    int Load(off_t start, off_t size);
    int RowFlush(const char* tpath, headers_t& meta, bool ow_sse_flg, bool force_sync = false);
    int Flush(headers_t& meta, bool ow_sse_flg, bool force_sync = false) { return RowFlush(NULL, meta, ow_sse_flg, force_sync); }
    ssize_t Read(char* bytes, off_t start, size_t size, bool force_load = false);
    ssize_t Write(const char* bytes, off_t start, size_t size);
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
    static bool            is_lock_init;
    static std::string     cache_dir;
    static size_t          page_size;

    fdent_map_t  fent;

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
    static size_t SetPageSize(size_t size);
    static size_t GetPageSize(void) { return FdManager::page_size; }
    static bool MakeCachePath(const char* path, std::string& cache_path, bool is_create_dir = true);

    FdEntity* GetFdEntity(const char* path);
    FdEntity* Open(const char* path, off_t size = -1, time_t time = -1, bool force_tmpfile = false, bool is_create = true);
    FdEntity* ExistOpen(const char* path) { return Open(path, -1, -1, false, false); }
    bool Close(FdEntity* ent);
};

#endif // FD_CACHE_H_
