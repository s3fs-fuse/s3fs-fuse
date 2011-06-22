/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright 2007-2008 Randy Rizun <rrizun@gmail.com>
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

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <iostream>
#include <string>
#include <map>

#include "cache.h"

using namespace std;

typedef std::map<std::string, struct stat_cache_entry> stat_cache_t; // key=path
static stat_cache_t stat_cache;
pthread_mutex_t stat_cache_lock;

int get_stat_cache_entry(const char *path, struct stat *buf) {
  pthread_mutex_lock(&stat_cache_lock);
  stat_cache_t::iterator iter = stat_cache.find(path);
  if(iter != stat_cache.end()) {
    if(foreground)
      cout << "    stat cache hit [path=" << path << "]"
           << " [hit count=" << (*iter).second.hit_count << "]" << endl;

    if(buf != NULL)
      *buf = (*iter).second.stbuf;

    (*iter).second.hit_count++;
    pthread_mutex_unlock(&stat_cache_lock);
    return 0;
  }
  pthread_mutex_unlock(&stat_cache_lock);

  return -1;
}

void add_stat_cache_entry(const char *path, struct stat *st) {
  if(foreground)
    cout << "    add_stat_cache_entry[path=" << path << "]" << endl;

  if(stat_cache.size() > max_stat_cache_size)
    truncate_stat_cache(); 

  pthread_mutex_lock(&stat_cache_lock);
  stat_cache[path].stbuf = *st;
  pthread_mutex_unlock(&stat_cache_lock);
}

void delete_stat_cache_entry(const char *path) {
  if(foreground)
    cout << "    delete_stat_cache_entry[path=" << path << "]" << endl;

  pthread_mutex_lock(&stat_cache_lock);
  stat_cache_t::iterator iter = stat_cache.find(path);
  if(iter != stat_cache.end())
    stat_cache.erase(iter);
  pthread_mutex_unlock(&stat_cache_lock);
}

void truncate_stat_cache() {
  string path_to_delete;
  unsigned int hit_count = 0;
  unsigned int lowest_hit_count = 0;

  pthread_mutex_lock(&stat_cache_lock);
  stat_cache_t::iterator iter;
  for(iter = stat_cache.begin(); iter != stat_cache.end(); iter++) {
    hit_count = (* iter).second.hit_count;

    if(!lowest_hit_count)
      lowest_hit_count = hit_count;

    if(lowest_hit_count > hit_count)
      path_to_delete = (* iter).first;
  }

  stat_cache.erase(path_to_delete);
  pthread_mutex_unlock(&stat_cache_lock);

  cout << "    purged " << path_to_delete << " from the stat cache" << endl;
}
