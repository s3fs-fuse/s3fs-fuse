/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright 2007-2013 Takeshi Nakatani <ggtakec.com>
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
#include <string>
#include <iostream>
#include <sstream>
#include <map>

#include "fdcache.h"
#include "s3fs.h"

using namespace std;

//-------------------------------------------------------------------
// Static
//-------------------------------------------------------------------
FdCache FdCache::singleton;
pthread_mutex_t FdCache::fd_cache_lock;

//-------------------------------------------------------------------
// Constructor/Destructor
//-------------------------------------------------------------------
FdCache::FdCache()
{
  if(this == FdCache::getFdCacheData()){
    pthread_mutex_init(&(FdCache::fd_cache_lock), NULL);
  }else{
    assert(false);
  }
}

FdCache::~FdCache()
{
  if(this == FdCache::getFdCacheData()){
    pthread_mutex_destroy(&(FdCache::fd_cache_lock));
  }else{
    assert(false);
  }
}

//-------------------------------------------------------------------
// Methods
//-------------------------------------------------------------------
bool FdCache::makeKey(const char* path, string& strkey)
{
  struct fuse_context* pcxt;

  if(NULL == (pcxt = fuse_get_context())){
    return false;
  }
  if(!path){
    return false;
  }
  // make key string
  ostringstream stream;
  stream << pcxt->pid;
  strkey = stream.str();
  strkey += "#";
  strkey += path;

  return true;
}

bool FdCache::Add(const char* path, int fd, int flags)
{
  fd_cache_t::iterator iter;

  // make key string
  string strkey;
  if(!FdCache::makeKey(path, strkey)){
    return false;
  }
  FGPRINT("    FdCache::Add[path=%s] fd(%d),flags(%d)\n", path, fd, flags);

  pthread_mutex_lock(&FdCache::fd_cache_lock);
  if(fd_cache.end() != (iter = fd_cache.find(strkey))){
    if(fd == (*iter).second.fd && flags == (*iter).second.flags){
      // Do nothing

    }else if(fd == (*iter).second.fd && flags != (*iter).second.flags){
      // Check and Set flags
      if(((*iter).second.flags & O_ACCMODE) < (flags & O_ACCMODE)){
        (*iter).second.flags = flags;
      }
    }else{
      // Check, Set fd & flags
      if(((*iter).second.flags & O_ACCMODE) < (flags & O_ACCMODE)){
        (*iter).second.fd    = fd;
        (*iter).second.flags = flags;
      }
    }
  }else{
    // Set new data
    fd_cache[strkey].fd    = fd;
    fd_cache[strkey].flags = flags;
  }
  // Set fd->flags
  fd_flags[fd] = flags;

  pthread_mutex_unlock(&FdCache::fd_cache_lock);

  return true;
}

// Specified path(+pid) and fd are removed from fd_cache and fd_flags.
bool FdCache::Del(const char* path, int fd)
{
  fd_cache_t::iterator fd_iter;
  fd_flags_t::iterator flags_iter;

  // make key string
  string strkey;
  if(!FdCache::makeKey(path, strkey)){
    return false;
  }
  FGPRINT("    FdCache::Del[path=%s][fd=%d]\n", path, fd);

  pthread_mutex_lock(&FdCache::fd_cache_lock);

  // Delete path->fd
  if(fd_cache.end() != (fd_iter = fd_cache.find(strkey))){
    Del((*fd_iter).second.fd);
    fd_cache.erase(fd_iter);
  }
  // search same fd in fd_cache and remove it (for case of pid=0).
  for(fd_iter = fd_cache.begin(); fd_cache.end() != fd_iter; ){
    if((*fd_iter).second.fd == fd){
      // found same fd
      fd_cache.erase(fd_iter++);
    }else{
      fd_iter++;
    }
  }
  // Delete fd->flags
  if(fd_flags.end() != (flags_iter = fd_flags.find(fd))){
    fd_flags.erase(flags_iter);
  }

  pthread_mutex_unlock(&FdCache::fd_cache_lock);

  return true;
}

// Specified path(+pid) is removed from fd_cache.
// And if can, fd_cache[path].fd is removed from fd_flags.
bool FdCache::Del(const char* path)
{
  fd_cache_t::iterator fd_iter;

  // make key string
  string strkey;
  if(!FdCache::makeKey(path, strkey)){
    return false;
  }
  FGPRINT("    FdCache::Del[path=%s]\n", path);

  pthread_mutex_lock(&FdCache::fd_cache_lock);
  if(fd_cache.end() != (fd_iter = fd_cache.find(strkey))){
    Del((*fd_iter).second.fd);
    fd_cache.erase(fd_iter);
  }
  pthread_mutex_unlock(&FdCache::fd_cache_lock);

  return true;
}

// Only fd is removed from fd_flags.
bool FdCache::Del(int fd)
{
  fd_flags_t::iterator flags_iter;

  FGPRINT("    FdCache::Del[fd=%d]\n", fd);

  pthread_mutex_lock(&FdCache::fd_cache_lock);
  // Delete fd->flags
  if(fd_flags.end() != (flags_iter = fd_flags.find(fd))){
    fd_flags.erase(flags_iter);
  }
  pthread_mutex_unlock(&FdCache::fd_cache_lock);

  return true;
}

bool FdCache::Get(const char* path, int* pfd, int* pflags) const
{
  bool result = true;
  fd_cache_t::const_iterator iter;

  // make key string
  string strkey;
  if(!FdCache::makeKey(path, strkey)){
    return false;
  }
  
  pthread_mutex_lock(&FdCache::fd_cache_lock);
  if(fd_cache.end() != (iter = fd_cache.find(strkey))){
    if(pfd){
      *pfd = (*iter).second.fd;
    }
    if(pflags){
      *pflags = (*iter).second.flags;
    }
    FGPRINT("    FdCache::Get[path=%s] fd=%d,flags=%d\n", path, (*iter).second.fd, (*iter).second.flags);
  }else{
    result = false;
  }
  pthread_mutex_unlock(&FdCache::fd_cache_lock);

  return result;
}

bool FdCache::Get(int fd, int* pflags) const
{
  bool result = true;
  fd_flags_t::const_iterator iter;

  pthread_mutex_lock(&FdCache::fd_cache_lock);
  if(fd_flags.end() != (iter = fd_flags.find(fd))){
    if(pflags){
      *pflags = (*iter).second;
    }
    FGPRINT("    FdCache::Get[fd=%d] flags=%d\n", fd, (*iter).second);
  }else{
    result = false;
  }
  pthread_mutex_unlock(&FdCache::fd_cache_lock);

  return result;
}

