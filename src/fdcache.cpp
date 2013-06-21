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
#include <list>

#include "fdcache.h"
#include "s3fs.h"

using namespace std;

//-------------------------------------------------------------------
// Utility for fd_cache_entlist_t
//-------------------------------------------------------------------
static int get_fdlist_entlist(fd_cache_entlist_t* list, fd_list_t& fdlist);
static fd_cache_entlist_t::iterator find_entlist(fd_cache_entlist_t* list, int fd);
static fd_cache_entlist_t::iterator find_writable_fd_entlist(fd_cache_entlist_t* list);
static bool add_fd_entlist(fd_cache_entlist_t* list, int fd, int flags);
static bool erase_fd_entlist(fd_cache_entlist_t* list, int fd, bool force = false);

static int get_fdlist_entlist(fd_cache_entlist_t* list, fd_list_t& fdlist)
{
  fd_cache_entlist_t::iterator iter;
  int count = 0;

  for(count = 0, iter = list->begin(); list->end() != iter; iter++, count++){
    fdlist.push_back((*iter).fd);
  }
  return count;
}

static fd_cache_entlist_t::iterator find_entlist(fd_cache_entlist_t* list, int fd)
{
  fd_cache_entlist_t::iterator iter;

  for(iter = list->begin(); list->end() != iter; iter++){
    if(fd == (*iter).fd){
      break;
    }
  }
  return iter;
}

static fd_cache_entlist_t::iterator find_writable_fd_entlist(fd_cache_entlist_t* list)
{
  fd_cache_entlist_t::iterator iter;
  fd_cache_entlist_t::iterator titer;
  int flags;

  for(flags = -1, iter = list->begin(), titer = list->end(); list->end() != iter; iter++){
    if(flags < ((*iter).flags & O_ACCMODE)){
      flags = (*iter).flags & O_ACCMODE;
      titer = iter;
    }
  }
  return titer;
}

static bool add_fd_entlist(fd_cache_entlist_t* list, int fd, int flags)
{
  fd_cache_entlist_t::iterator iter = find_entlist(list, fd);

  if(list->end() == iter){
    // not found, add new entry.
    fd_cache_entry ent;
    ent.refcnt = 1;
    ent.fd     = fd;
    ent.flags  = flags;
    list->push_back(ent);
  }else{
    // found same fd, need to check flags.
    (*iter).refcnt++;
    if(flags != (*iter).flags){
      (*iter).flags = flags;
    }
  }
  return true;
}

static bool erase_fd_entlist(fd_cache_entlist_t* list, int fd, bool force)
{
  fd_cache_entlist_t::iterator iter = find_entlist(list, fd);

  if(list->end() == iter){
    return false;
  }
  (*iter).refcnt--;
  if(!force && 0 < (*iter).refcnt){
    return false;
  }
  list->erase(iter);
  return true;
}

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

    for(fd_cache_t::iterator iter = fd_cache.begin(); fd_cache.end() != iter; iter++){
      fd_cache_entlist_t* entlist = (*iter).second;
      delete entlist;
    }
    fd_cache.clear();
  }else{
    assert(false);
  }
}

//-------------------------------------------------------------------
// Methods
//-------------------------------------------------------------------
bool FdCache::Add(const char* path, int fd, int flags)
{
  fd_cache_t::iterator iter;
  string strkey = path;

  FGPRINT("    FdCache::Add[path=%s] fd(%d),flags(%d)\n", path, fd, flags);

  pthread_mutex_lock(&FdCache::fd_cache_lock);

  // Add path->fd
  fd_cache_entlist_t* entlist;
  if(fd_cache.end() != (iter = fd_cache.find(strkey))){
    // found same key. set into fd(or over write)
    entlist = (*iter).second;
  }else{
    // not found, set into new entry.
    entlist = new fd_cache_entlist_t();
    fd_cache[strkey] = entlist;
  }
  add_fd_entlist(entlist, fd, flags);

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
  string strkey = path;

  FGPRINT("    FdCache::Del[path=%s][fd=%d]\n", path, fd);

  pthread_mutex_lock(&FdCache::fd_cache_lock);

  // Delete path->fd
  if(fd_cache.end() != (fd_iter = fd_cache.find(strkey))){
    fd_cache_entlist_t* entlist = (*fd_iter).second;
    erase_fd_entlist(entlist, fd);
    if(0 == entlist->size()){
      delete entlist;
      fd_cache.erase(fd_iter);
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
  string strkey = path;

  FGPRINT("    FdCache::Del[path=%s]\n", path);

  pthread_mutex_lock(&FdCache::fd_cache_lock);

  if(fd_cache.end() != (fd_iter = fd_cache.find(strkey))){
    fd_cache_entlist_t* entlist = (*fd_iter).second;
    fd_list_t fdlist;
    if(0 != get_fdlist_entlist(entlist, fdlist)){
      // remove fd->flags map
      for(fd_list_t::iterator fdlist_iter; fdlist.end() != fdlist_iter; fdlist_iter++){
        Del(*fdlist_iter);
      }
    }
    // remove path->fd_entlist
    delete entlist;
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
  fd_cache_t::const_iterator iter;
  bool result   = false;
  string strkey = path;
  
  pthread_mutex_lock(&FdCache::fd_cache_lock);

  if(fd_cache.end() != (iter = fd_cache.find(strkey))){
    fd_cache_entlist_t* entlist        = (*iter).second;
    fd_cache_entlist_t::iterator titer = find_writable_fd_entlist(entlist);
    if(titer != entlist->end()){
      // returns writable fd.
      result = true;
      if(pfd){
        *pfd = (*titer).fd;
      }
      if(pflags){
        *pflags = (*titer).flags;
      }
      FGPRINT("    FdCache::Get[path=%s] fd=%d,flags=%d\n", path, (*titer).fd, (*titer).flags);
    }
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

