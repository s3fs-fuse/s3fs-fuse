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
#include <assert.h>
#include <syslog.h>
#include <string>
#include <map>
#include <algorithm>
#include <list>

#include "cache.h"
#include "s3fs_util.h"

using namespace std;

//-------------------------------------------------------------------
// Static
//-------------------------------------------------------------------
StatCache StatCache::singleton;
pthread_mutex_t StatCache::stat_cache_lock;

//-------------------------------------------------------------------
// Constructor/Destructor
//-------------------------------------------------------------------
StatCache::StatCache()
{
  if(this == StatCache::getStatCacheData()){
    pthread_mutex_init(&(StatCache::stat_cache_lock), NULL);
  }else{
    assert(false);
  }
  CacheSize       = 1000;
  ExpireTime      = 0;
  IsExpireTime    = false;
  IsCacheNoObject = false;
}

StatCache::~StatCache()
{
  if(this == StatCache::getStatCacheData()){
    pthread_mutex_destroy(&(StatCache::stat_cache_lock));
  }else{
    assert(false);
  }
}

//-------------------------------------------------------------------
// Methods
//-------------------------------------------------------------------
unsigned long StatCache::GetCacheSize(void) const
{
  return CacheSize;
}

unsigned long StatCache::SetCacheSize(unsigned long size)
{
  unsigned long old = CacheSize;
  CacheSize = size;
  return old;
}

time_t StatCache::GetExpireTime(void) const
{
  return (IsExpireTime ? ExpireTime : (-1));
}

time_t StatCache::SetExpireTime(time_t expire)
{
  time_t old   = ExpireTime;
  ExpireTime   = expire;
  IsExpireTime = true;
  return old;
}

time_t StatCache::UnsetExpireTime(void)
{
  time_t old   = IsExpireTime ? ExpireTime : (-1);
  ExpireTime   = 0;
  IsExpireTime = false;
  return old;
}

bool StatCache::SetCacheNoObject(bool flag)
{
  bool old = IsCacheNoObject;
  IsCacheNoObject = flag;
  return old;
}

bool StatCache::GetStat(string& key, struct stat* pst, headers_t* meta, bool overcheck, const char* petag, bool* pisforce)
{
  bool is_delete_cache = false;
  string strpath = key;

  pthread_mutex_lock(&StatCache::stat_cache_lock);

  stat_cache_t::iterator iter = stat_cache.end();
  if(overcheck && '/' != strpath[strpath.length() - 1]){
    strpath += "/";
    iter = stat_cache.find(strpath.c_str());
  }
  if(iter == stat_cache.end()){
    strpath = key;
    iter = stat_cache.find(strpath.c_str());
  }

  if(iter != stat_cache.end()) {
    if(!IsExpireTime|| ((*iter).second.cache_date + ExpireTime) >= time(NULL)){
      if((*iter).second.noobjcache){
        pthread_mutex_unlock(&StatCache::stat_cache_lock);
        if(!IsCacheNoObject){
          // need to delete this cache.
          DelStat(strpath);
        }else{
          // noobjcache = true means no object.
        }
        return false;
      }
      // hit without checking etag
      if(petag){
        string stretag = (*iter).second.meta["ETag"];
        if('\0' != petag[0] && 0 != strcmp(petag, stretag.c_str())){
          is_delete_cache = true;
        }
      }
      if(is_delete_cache){
        // not hit by different ETag
        DPRNNN("stat cache not hit by ETag[path=%s][time=%ld][hit count=%lu][ETag(%s)!=(%s)]",
          strpath.c_str(), (*iter).second.cache_date, (*iter).second.hit_count,
          petag ? petag : "null", (*iter).second.meta["ETag"].c_str());
      }else{
        // hit 
        DPRNNN("stat cache hit [path=%s] [time=%ld] [hit count=%lu]",
          strpath.c_str(), (*iter).second.cache_date, (*iter).second.hit_count);

        if(pst!= NULL){
          *pst= (*iter).second.stbuf;
        }
        if(meta != NULL){
          meta->clear();
          (*meta) = (*iter).second.meta;
        }
        if(pisforce != NULL){
          (*pisforce) = (*iter).second.isforce;
        }
        (*iter).second.hit_count++;
        pthread_mutex_unlock(&StatCache::stat_cache_lock);
        return true;
      }

    }else{
      // timeout
      is_delete_cache = true;
    }
  }
  pthread_mutex_unlock(&StatCache::stat_cache_lock);

  if(is_delete_cache){
    DelStat(strpath);
  }
  return false;
}

bool StatCache::IsNoObjectCache(string& key, bool overcheck)
{
  bool is_delete_cache = false;
  string strpath = key;

  if(!IsCacheNoObject){
    return false;
  }

  pthread_mutex_lock(&StatCache::stat_cache_lock);

  stat_cache_t::iterator iter = stat_cache.end();
  if(overcheck && '/' != strpath[strpath.length() - 1]){
    strpath += "/";
    iter = stat_cache.find(strpath.c_str());
  }
  if(iter == stat_cache.end()){
    strpath = key;
    iter = stat_cache.find(strpath.c_str());
  }

  if(iter != stat_cache.end()) {
    if(!IsExpireTime|| ((*iter).second.cache_date + ExpireTime) >= time(NULL)){
      if((*iter).second.noobjcache){
        // noobjcache = true means no object.
        pthread_mutex_unlock(&StatCache::stat_cache_lock);
        return true;
      }
    }else{
      // timeout
      is_delete_cache = true;
    }
  }
  pthread_mutex_unlock(&StatCache::stat_cache_lock);

  if(is_delete_cache){
    DelStat(strpath);
  }
  return false;
}

bool StatCache::AddStat(std::string& key, headers_t& meta, bool forcedir)
{
  if(CacheSize< 1){
    return true;
  }
  DPRNNN("add stat cache entry[path=%s]", key.c_str());

  if(stat_cache.size() > CacheSize){
    if(!TruncateCache()){
      return false;
    }
  }

  struct stat st;
  if(!convert_header_to_stat(key.c_str(), meta, &st, forcedir)){
    return false;
  }

  pthread_mutex_lock(&StatCache::stat_cache_lock);
  stat_cache[key].stbuf      = st;
  stat_cache[key].hit_count  = 0;
  stat_cache[key].cache_date = time(NULL); // Set time.
  stat_cache[key].isforce    = forcedir;
  stat_cache[key].noobjcache = false;

  //copy only some keys
  for (headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter) {
    string tag   = (*iter).first;
    string value = (*iter).second;
    if(tag == "Content-Type"){
      stat_cache[key].meta[tag] = value;
    }else if(tag == "Content-Length"){
      stat_cache[key].meta[tag] = value;
    }else if(tag == "ETag"){
      stat_cache[key].meta[tag] = value;
    }else if(tag == "Last-Modified"){
      stat_cache[key].meta[tag] = value;
    }else if(tag.substr(0, 5) == "x-amz"){
      stat_cache[key].meta[tag] = value;
    }else{
      // Check for upper case
      transform(tag.begin(), tag.end(), tag.begin(), static_cast<int (*)(int)>(std::tolower));
      if(tag.substr(0, 5) == "x-amz"){
        stat_cache[key].meta[tag] = value;
      }
    }
  }
  pthread_mutex_unlock(&StatCache::stat_cache_lock);

  return true;
}

bool StatCache::AddNoObjectCache(string& key)
{
  if(!IsCacheNoObject){
    return true;    // pretend successful
  }
  if(CacheSize < 1){
    return true;
  }
  DPRNNN("add no object cache entry[path=%s]", key.c_str());

  if(stat_cache.size() > CacheSize){
    if(!TruncateCache()){
      return false;
    }
  }

  struct stat st;
  memset(&st, 0, sizeof(struct stat));

  pthread_mutex_lock(&StatCache::stat_cache_lock);
  stat_cache[key].stbuf      = st;
  stat_cache[key].hit_count  = 0;
  stat_cache[key].cache_date = time(NULL); // Set time.
  stat_cache[key].isforce    = false;
  stat_cache[key].noobjcache = true;
  pthread_mutex_unlock(&StatCache::stat_cache_lock);

  return true;
}

bool StatCache::TruncateCache(void)
{
  string path_to_delete;
  unsigned int lowest_hit_count = 0;

  pthread_mutex_lock(&StatCache::stat_cache_lock);
  stat_cache_t::iterator iter;
  for(iter = stat_cache.begin(); iter != stat_cache.end(); iter++) {
    if(!lowest_hit_count) {
      lowest_hit_count = (*iter).second.hit_count;
      path_to_delete   = (*iter).first;
    }
    if(lowest_hit_count > (*iter).second.hit_count){
      lowest_hit_count = (*iter).second.hit_count;
      path_to_delete   = (*iter).first;
    }
  }
  stat_cache.erase(path_to_delete);
  pthread_mutex_unlock(&StatCache::stat_cache_lock);

  DPRNNN("truncate stat cache[path=%s]", path_to_delete.c_str());

  return true;
}

bool StatCache::DelStat(const char* key)
{
  if(!key){
    return false;
  }
  DPRNNN("delete stat cache entry[path=%s]", key);

  pthread_mutex_lock(&StatCache::stat_cache_lock);
  stat_cache_t::iterator iter = stat_cache.find(key);
  if(iter != stat_cache.end()){
    stat_cache.erase(iter);
  }
  if(0 < strlen(key) && 0 != strcmp(key, "/")){
    string strpath = key;
    if('/' == strpath[strpath.length() - 1]){
      // If there is "path" cache, delete it.
      strpath = strpath.substr(0, strpath.length() - 1);
    }else{
      // If there is "path/" cache, delete it.
      strpath += "/";
    }
    iter = stat_cache.find(strpath.c_str());
    if(iter != stat_cache.end()){
      stat_cache.erase(iter);
    }
  }
  pthread_mutex_unlock(&StatCache::stat_cache_lock);

  return true;
}

//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
bool convert_header_to_stat(const char* path, headers_t& meta, struct stat* pst, bool forcedir)
{
  if(!path || !pst){
    return false;
  }
  memset(pst, 0, sizeof(struct stat));

  pst->st_nlink = 1; // see fuse FAQ

  // mode
  pst->st_mode = get_mode(meta, path, true, forcedir);

  // blocks
  if(S_ISREG(pst->st_mode)){
    pst->st_blocks = get_blocks(pst->st_size);
  }

  // mtime
  pst->st_mtime = get_mtime(meta);

  // size
  pst->st_size = get_size(meta);

  // uid/gid
  pst->st_uid = get_uid(meta);
  pst->st_gid = get_gid(meta);

  return true;
}

