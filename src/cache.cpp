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

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <iostream>
#include <string>
#include <map>

#include "common.h"
#include "cache.h"

using namespace std;

//-------------------------------------------------------------------
// Typedef
//-------------------------------------------------------------------
typedef std::map<std::string, struct stat_cache_entry> stat_cache_t; // key=path

//-------------------------------------------------------------------
// Static valiables
//-------------------------------------------------------------------
static stat_cache_t stat_cache;
static pthread_mutex_t stat_cache_lock;

//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
int init_stat_cache_mutex(void)
{
  return pthread_mutex_init(&stat_cache_lock, NULL);
}

int destroy_stat_cache_mutex(void)
{
  return pthread_mutex_destroy(&stat_cache_lock);
}

int get_stat_cache_entry(const char *path, struct stat *buf)
{
  int is_delete_cache = 0;
  string strpath = path;

  pthread_mutex_lock(&stat_cache_lock);

  stat_cache_t::iterator iter = stat_cache.end();
  if('/' != strpath[strpath.length() - 1]){
    strpath += "/";
    iter = stat_cache.find(strpath.c_str());
  }
  if(iter == stat_cache.end()){
    strpath = path;
    iter = stat_cache.find(strpath.c_str());
  }

  if(iter != stat_cache.end()) {
    if(!is_stat_cache_expire_time || ((*iter).second.cache_date + stat_cache_expire_time) >= time(NULL)){
      // hit 
      FGPRINT("    stat cache hit [path=%s] [time=%ld] [hit count=%lu]\n",
        strpath.c_str(), (*iter).second.cache_date, (*iter).second.hit_count);

      if(buf != NULL){
        *buf = (*iter).second.stbuf;
      }
      (*iter).second.hit_count++;
      pthread_mutex_unlock(&stat_cache_lock);
      return 0;
    }else{
      // timeout
      is_delete_cache = 1;
    }
  }
  pthread_mutex_unlock(&stat_cache_lock);

  if(is_delete_cache){
    delete_stat_cache_entry(strpath.c_str());
  }

  return -1;
}

void add_stat_cache_entry(const char *path, struct stat *st)
{
  FGPRINT("    add_stat_cache_entry[path=%s]\n", path);

  if(max_stat_cache_size < 1){
    return;
  }
  if(stat_cache.size() > max_stat_cache_size){
    truncate_stat_cache(); 
  }
  pthread_mutex_lock(&stat_cache_lock);
  stat_cache[path].stbuf = *st;
  stat_cache[path].cache_date = time(NULL); // Set time.
  pthread_mutex_unlock(&stat_cache_lock);
}

void delete_stat_cache_entry(const char *path)
{
  FGPRINT("    delete_stat_cache_entry[path=%s]\n", path);

  pthread_mutex_lock(&stat_cache_lock);
  stat_cache_t::iterator iter = stat_cache.find(path);
  if(iter != stat_cache.end()){
    stat_cache.erase(iter);
  }
  if(0 < strlen(path) && '/' != path[strlen(path) - 1]){
    // If there is "path/" cache, delete it.
    string strpath = path;
    strpath += "/";
    iter = stat_cache.find(strpath.c_str());
    if(iter != stat_cache.end()){
      stat_cache.erase(iter);
    }
  }
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

    if(!lowest_hit_count) {
      lowest_hit_count = hit_count;
      path_to_delete = (* iter).first;
    }
    if(lowest_hit_count > hit_count){
      path_to_delete = (* iter).first;
    }
  }

  stat_cache.erase(path_to_delete);
  pthread_mutex_unlock(&stat_cache_lock);

  FGPRINT("    purged %s from the stat cache\n", path_to_delete.c_str());
}

