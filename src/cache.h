#ifndef S3FS_CACHE_H_
#define S3FS_CACHE_H_

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct stat_cache_entry {
  struct stat stbuf;
  unsigned long hit_count;
  time_t cache_date;

  stat_cache_entry() : hit_count(0), cache_date(0) {}
};

extern bool foreground;
extern unsigned long max_stat_cache_size;
extern time_t stat_cache_expire_time;
extern int is_stat_cache_expire_time;

int get_stat_cache_entry(const char *path, struct stat *buf);
void add_stat_cache_entry(const char *path, struct stat *st);
void delete_stat_cache_entry(const char *path);
void truncate_stat_cache();

#endif // S3FS_CACHE_H_
