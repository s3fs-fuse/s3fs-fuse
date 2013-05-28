#ifndef FD_CACHE_H_
#define FD_CACHE_H_

#include "common.h"

//
// Struct for fuse file handle cache
//
struct fd_cache_entry {
  int fd;
  int flags;

  fd_cache_entry() : fd(0), flags(0) {}
};

typedef std::map<std::string, struct fd_cache_entry> fd_cache_t; // key="pid(oct)#path"
typedef std::map<int, int> fd_flags_t;                           // key=file discriptor

//
// Class for fuse file handle cache
//
class FdCache
{
  private:
    static FdCache singleton;
    static pthread_mutex_t fd_cache_lock;
    fd_cache_t fd_cache;
    fd_flags_t fd_flags;

  private:
    static bool makeKey(const char* path, std::string& strkey);

  public:
    FdCache();
    ~FdCache();

    // Reference singleton
    static FdCache* getFdCacheData(void) {
      return &singleton;
    }

    bool Add(const char* path, int fd, int flags);
    bool Del(const char* path, int fd);
    bool Del(const char* path);
    bool Del(int fd);
    bool Get(const char* path, int* pfd = NULL, int* pflags = NULL) const;
    bool Get(int fd, int* pflags = NULL) const;
};

#endif // FD_CACHE_H_
