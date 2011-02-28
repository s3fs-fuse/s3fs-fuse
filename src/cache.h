#ifndef S3FS_CACHE_H_
#define S3FS_CACHE_H_

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct stat_cache_entry {
  struct stat stbuf;
  unsigned long hit_count;

  stat_cache_entry() : hit_count(0) {}
};

extern bool foreground;
extern unsigned long max_stat_cache_size;

int get_stat_cache_entry(const char *path, struct stat *buf);
void add_stat_cache_entry(const char *path, struct stat *st);
void delete_stat_cache_entry(const char *path);
void truncate_stat_cache();

#endif // S3FS_CACHE_H_
