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
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>
#include <string>
#include <map>
#include <algorithm>
#include <list>

#include "cache.h"
#include "s3fs.h"
#include "s3fs_util.h"

using namespace std;

//-------------------------------------------------------------------
// Static
//-------------------------------------------------------------------
StatCache       StatCache::singleton;
pthread_mutex_t StatCache::stat_cache_lock;

//-------------------------------------------------------------------
// Constructor/Destructor
//-------------------------------------------------------------------
StatCache::StatCache() : IsExpireTime(false), ExpireTime(0), CacheSize(1000), IsCacheNoObject(false)
{
  if(this == StatCache::getStatCacheData()){
    stat_cache.clear();
    pthread_mutex_init(&(StatCache::stat_cache_lock), NULL);
  }else{
    assert(false);
  }
}

StatCache::~StatCache()
{
  if(this == StatCache::getStatCacheData()){
    Clear();
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

void StatCache::Clear(void)
{
  pthread_mutex_lock(&StatCache::stat_cache_lock);

  for(stat_cache_t::iterator iter = stat_cache.begin(); iter != stat_cache.end(); stat_cache.erase(iter++)){
    if((*iter).second){
      delete (*iter).second;
    }
  }
  S3FS_MALLOCTRIM(0);

  pthread_mutex_unlock(&StatCache::stat_cache_lock);
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

  if(iter != stat_cache.end() && (*iter).second){
    stat_cache_entry* ent = (*iter).second;
    if(!IsExpireTime|| (ent->cache_date + ExpireTime) >= time(NULL)){
      if(ent->noobjcache){
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
        string stretag = ent->meta["ETag"];
        if('\0' != petag[0] && 0 != strcmp(petag, stretag.c_str())){
          is_delete_cache = true;
        }
      }
      if(is_delete_cache){
        // not hit by different ETag
        DPRNNN("stat cache not hit by ETag[path=%s][time=%jd][hit count=%lu][ETag(%s)!=(%s)]",
          strpath.c_str(), (intmax_t)(ent->cache_date), ent->hit_count, petag ? petag : "null", ent->meta["ETag"].c_str());
      }else{
        // hit 
        DPRNNN("stat cache hit [path=%s][time=%jd][hit count=%lu]", strpath.c_str(), (intmax_t)(ent->cache_date), ent->hit_count);

        if(pst!= NULL){
          *pst= ent->stbuf;
        }
        if(meta != NULL){
          *meta = ent->meta;
        }
        if(pisforce != NULL){
          (*pisforce) = ent->isforce;
        }
        ent->hit_count++;
        ent->cache_date = time(NULL);
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

  if(iter != stat_cache.end() && (*iter).second) {
    if(!IsExpireTime|| ((*iter).second->cache_date + ExpireTime) >= time(NULL)){
      if((*iter).second->noobjcache){
        // noobjcache = true means no object.
        (*iter).second->cache_date = time(NULL);
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

  if(stat_cache.end() != stat_cache.find(key)){
    DelStat(key.c_str());
  }else{
    if(stat_cache.size() > CacheSize){
      if(!TruncateCache()){
        return false;
      }
    }
  }

  // make new
  stat_cache_entry* ent = new stat_cache_entry();
  if(!convert_header_to_stat(key.c_str(), meta, &(ent->stbuf), forcedir)){
    delete ent;
    return false;
  }
  ent->hit_count  = 0;
  ent->cache_date = time(NULL); // Set time.
  ent->isforce    = forcedir;
  ent->noobjcache = false;
  ent->meta.clear();
  //copy only some keys
  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string tag   = (*iter).first;
    string value = (*iter).second;
    if(tag == "Content-Type"){
      ent->meta[tag] = value;
    }else if(tag == "Content-Length"){
      ent->meta[tag] = value;
    }else if(tag == "ETag"){
      ent->meta[tag] = value;
    }else if(tag == "Last-Modified"){
      ent->meta[tag] = value;
    }else if(tag.substr(0, 5) == "x-amz"){
      ent->meta[tag] = value;
    }else{
      // Check for upper case
      transform(tag.begin(), tag.end(), tag.begin(), static_cast<int (*)(int)>(std::tolower));
      if(tag.substr(0, 5) == "x-amz"){
        ent->meta[tag] = value;
      }
    }
  }
  // add
  pthread_mutex_lock(&StatCache::stat_cache_lock);
  stat_cache[key] = ent;
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

  if(stat_cache.end() != stat_cache.find(key)){
    DelStat(key.c_str());
  }else{
    if(stat_cache.size() > CacheSize){
      if(!TruncateCache()){
        return false;
      }
    }
  }

  // make new
  stat_cache_entry* ent = new stat_cache_entry();
  memset(&(ent->stbuf), 0, sizeof(struct stat));
  ent->hit_count  = 0;
  ent->cache_date = time(NULL); // Set time.
  ent->isforce    = false;
  ent->noobjcache = true;
  ent->meta.clear();
  // add
  pthread_mutex_lock(&StatCache::stat_cache_lock);
  stat_cache[key] = ent;
  pthread_mutex_unlock(&StatCache::stat_cache_lock);

  return true;
}

bool StatCache::TruncateCache(void)
{
  if(0 == stat_cache.size()){
    return true;
  }

  pthread_mutex_lock(&StatCache::stat_cache_lock);

  time_t lowest_time = time(NULL) + 1;
  stat_cache_t::iterator iter_to_delete = stat_cache.end();
  stat_cache_t::iterator iter;

  for(iter = stat_cache.begin(); iter != stat_cache.end(); iter++) {
    if((*iter).second){
      if(lowest_time > (*iter).second->cache_date){
        lowest_time    = (*iter).second->cache_date;
        iter_to_delete = iter;
      }
    }
  }
  if(stat_cache.end() != iter_to_delete){
    DPRNNN("truncate stat cache[path=%s]", (*iter_to_delete).first.c_str());
    if((*iter_to_delete).second){
      delete (*iter_to_delete).second;
    }
    stat_cache.erase(iter_to_delete);
    S3FS_MALLOCTRIM(0);
  }

  pthread_mutex_unlock(&StatCache::stat_cache_lock);

  return true;
}

bool StatCache::DelStat(const char* key)
{
  if(!key){
    return false;
  }
  DPRNNN("delete stat cache entry[path=%s]", key);

  pthread_mutex_lock(&StatCache::stat_cache_lock);

  stat_cache_t::iterator iter;
  if(stat_cache.end() != (iter = stat_cache.find(string(key)))){
    if((*iter).second){
      delete (*iter).second;
    }
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
    if(stat_cache.end() != (iter = stat_cache.find(strpath.c_str()))){
      if((*iter).second){
        delete (*iter).second;
      }
      stat_cache.erase(iter);
    }
  }
  S3FS_MALLOCTRIM(0);

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

