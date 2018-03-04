/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2007 Takeshi Nakatani <ggtakec.com>
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
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <curl/curl.h>
#include <string>
#include <iostream>
#include <sstream>
#include <map>
#include <list>
#include <vector>

#include "common.h"
#include "fdcache.h"
#include "s3fs.h"
#include "s3fs_util.h"
#include "string_util.h"
#include "curl.h"

using namespace std;

//------------------------------------------------
// Symbols
//------------------------------------------------
static const int MAX_MULTIPART_CNT = 10 * 1000;  // S3 multipart max count

//
// For cache directory top path
//
#if defined(P_tmpdir)
#define TMPFILE_DIR_0PATH   P_tmpdir
#else
#define TMPFILE_DIR_0PATH   "/tmp"
#endif

//------------------------------------------------
// CacheFileStat class methods
//------------------------------------------------
bool CacheFileStat::MakeCacheFileStatPath(const char* path, string& sfile_path, bool is_create_dir)
{
  // make stat dir top path( "/<cache_dir>/.<bucket_name>.stat" )
  string top_path = FdManager::GetCacheDir();
  top_path       += "/.";
  top_path       += bucket;
  top_path       += ".stat";

  if(is_create_dir){
    int result;
    if(0 != (result = mkdirp(top_path + mydirname(path), 0777))){
      S3FS_PRN_ERR("failed to create dir(%s) by errno(%d).", path, result);
      return false;
    }
  }
  if(!path || '\0' == path[0]){
    sfile_path = top_path;
  }else{
    sfile_path = top_path + SAFESTRPTR(path);
  }
  return true;
}

bool CacheFileStat::CheckCacheFileStatTopDir(void)
{
  if(!FdManager::IsCacheDir()){
    return true;
  }
  // make stat dir top path( "/<cache_dir>/.<bucket_name>.stat" )
  string top_path = FdManager::GetCacheDir();
  top_path       += "/.";
  top_path       += bucket;
  top_path       += ".stat";

  return check_exist_dir_permission(top_path.c_str());
}

bool CacheFileStat::DeleteCacheFileStat(const char* path)
{
  if(!path || '\0' == path[0]){
    return false;
  }
  // stat path
  string sfile_path;
  if(!CacheFileStat::MakeCacheFileStatPath(path, sfile_path, false)){
    S3FS_PRN_ERR("failed to create cache stat file path(%s)", path);
    return false;
  }
  if(0 != unlink(sfile_path.c_str())){
    if(ENOENT == errno){
      S3FS_PRN_DBG("failed to delete file(%s): errno=%d", path, errno);
    }else{
      S3FS_PRN_ERR("failed to delete file(%s): errno=%d", path, errno);
    }
    return false;
  }
  return true;
}

// [NOTE]
// If remove stat file directory, it should do before removing
// file cache directory.
//
bool CacheFileStat::DeleteCacheFileStatDirectory(void)
{
  string top_path = FdManager::GetCacheDir();

  if(top_path.empty() || bucket.empty()){
    return true;
  }
  top_path       += "/.";
  top_path       += bucket;
  top_path       += ".stat";
  return delete_files_in_dir(top_path.c_str(), true);
}

//------------------------------------------------
// CacheFileStat methods
//------------------------------------------------
CacheFileStat::CacheFileStat(const char* tpath) : path(""), fd(-1)
{
  if(tpath && '\0' != tpath[0]){
    SetPath(tpath, true);
  }
}

CacheFileStat::~CacheFileStat()
{
  Release();
}

bool CacheFileStat::SetPath(const char* tpath, bool is_open)
{
  if(!tpath || '\0' == tpath[0]){
    return false;
  }
  if(!Release()){
    // could not close old stat file.
    return false;
  }
  if(tpath){
    path = tpath;
  }
  if(!is_open){
    return true;
  }
  return Open();
}

bool CacheFileStat::Open(void)
{
  if(0 == path.size()){
    return false;
  }
  if(-1 != fd){
    // already opened
    return true;
  }
  // stat path
  string sfile_path;
  if(!CacheFileStat::MakeCacheFileStatPath(path.c_str(), sfile_path, true)){
    S3FS_PRN_ERR("failed to create cache stat file path(%s)", path.c_str());
    return false;
  }
  // open
  if(-1 == (fd = open(sfile_path.c_str(), O_CREAT|O_RDWR, 0600))){
    S3FS_PRN_ERR("failed to open cache stat file path(%s) - errno(%d)", path.c_str(), errno);
    return false;
  }
  // lock
  if(-1 == flock(fd, LOCK_EX)){
    S3FS_PRN_ERR("failed to lock cache stat file(%s) - errno(%d)", path.c_str(), errno);
    close(fd);
    fd = -1;
    return false;
  }
  // seek top
  if(0 != lseek(fd, 0, SEEK_SET)){
    S3FS_PRN_ERR("failed to lseek cache stat file(%s) - errno(%d)", path.c_str(), errno);
    flock(fd, LOCK_UN);
    close(fd);
    fd = -1;
    return false;
  }
  S3FS_PRN_DBG("file locked(%s - %s)", path.c_str(), sfile_path.c_str());

  return true;
}

bool CacheFileStat::Release(void)
{
  if(-1 == fd){
    // already release
    return true;
  }
  // unlock
  if(-1 == flock(fd, LOCK_UN)){
    S3FS_PRN_ERR("failed to unlock cache stat file(%s) - errno(%d)", path.c_str(), errno);
    return false;
  }
  S3FS_PRN_DBG("file unlocked(%s)", path.c_str());

  if(-1 == close(fd)){
    S3FS_PRN_ERR("failed to close cache stat file(%s) - errno(%d)", path.c_str(), errno);
    return false;
  }
  fd = -1;

  return true;
}

//------------------------------------------------
// PageList methods
//------------------------------------------------
void PageList::FreeList(fdpage_list_t& list)
{
  for(fdpage_list_t::iterator iter = list.begin(); iter != list.end(); iter = list.erase(iter)){
    delete (*iter);
  }
  list.clear();
}

PageList::PageList(size_t size, bool is_loaded)
{
  Init(size, is_loaded);
}

PageList::~PageList()
{
  Clear();
}

void PageList::Clear(void)
{
  PageList::FreeList(pages);
}

bool PageList::Init(size_t size, bool is_loaded)
{
  Clear();
  fdpage* page = new fdpage(0, size, is_loaded);
  pages.push_back(page);
  return true;
}

size_t PageList::Size(void) const
{
  if(pages.empty()){
    return 0;
  }
  fdpage_list_t::const_reverse_iterator riter = pages.rbegin();
  return static_cast<size_t>((*riter)->next());
}

bool PageList::Compress(void)
{
  bool is_first       = true;
  bool is_last_loaded = false;
  for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); ){
    if(is_first){
      is_first       = false;
      is_last_loaded = (*iter)->loaded;
      ++iter;
    }else{
      if(is_last_loaded == (*iter)->loaded){
        fdpage_list_t::iterator biter = iter;
        --biter;
        (*biter)->bytes += (*iter)->bytes;
        delete *iter;
        iter = pages.erase(iter);
      }else{
        is_last_loaded = (*iter)->loaded;
        ++iter;
      }
    }
  }
  return true;
}

bool PageList::Parse(off_t new_pos)
{
  for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); ++iter){
    if(new_pos == (*iter)->offset){
      // nothing to do
      return true;
    }else if((*iter)->offset < new_pos && new_pos < (*iter)->next()){
      fdpage* page    = new fdpage((*iter)->offset, static_cast<size_t>(new_pos - (*iter)->offset), (*iter)->loaded);
      (*iter)->bytes -= (new_pos - (*iter)->offset);
      (*iter)->offset = new_pos;
      pages.insert(iter, page);
      return true;
    }
  }
  return false;
}

bool PageList::Resize(size_t size, bool is_loaded)
{
  size_t total = Size();

  if(0 == total){
    Init(size, is_loaded);

  }else if(total < size){
    // add new area
    fdpage* page = new fdpage(static_cast<off_t>(total), (size - total), is_loaded);
    pages.push_back(page);

  }else if(size < total){
    // cut area
    for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); ){
      if(static_cast<size_t>((*iter)->next()) <= size){
        ++iter;
      }else{
        if(size <= static_cast<size_t>((*iter)->offset)){
          delete *iter;
          iter = pages.erase(iter);
        }else{
          (*iter)->bytes = size - static_cast<size_t>((*iter)->offset);
        }
      }
    }
  }else{    // total == size
    // nothing to do
  }
  // compress area
  return Compress();
}

bool PageList::IsPageLoaded(off_t start, size_t size) const
{
  for(fdpage_list_t::const_iterator iter = pages.begin(); iter != pages.end(); ++iter){
    if((*iter)->end() < start){
      continue;
    }
    if(!(*iter)->loaded){
      return false;
    }
    if(0 != size && static_cast<size_t>(start + size) <= static_cast<size_t>((*iter)->next())){
      break;
    }
  }
  return true;
}

bool PageList::SetPageLoadedStatus(off_t start, size_t size, bool is_loaded, bool is_compress)
{
  size_t now_size = Size();

  if(now_size <= static_cast<size_t>(start)){
    if(now_size < static_cast<size_t>(start)){
      // add
      Resize(static_cast<size_t>(start), false);
    }
    Resize(static_cast<size_t>(start + size), is_loaded);

  }else if(now_size <= static_cast<size_t>(start + size)){
    // cut
    Resize(static_cast<size_t>(start), false);
    // add
    Resize(static_cast<size_t>(start + size), is_loaded);

  }else{
    // start-size are inner pages area
    // parse "start", and "start + size" position
    Parse(start);
    Parse(start + size);

    // set loaded flag
    for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); ++iter){
      if((*iter)->end() < start){
        continue;
      }else if(static_cast<off_t>(start + size) <= (*iter)->offset){
        break;
      }else{
        (*iter)->loaded = is_loaded;
      }
    }
  }
  // compress area
  return (is_compress ? Compress() : true);
}

bool PageList::FindUnloadedPage(off_t start, off_t& resstart, size_t& ressize) const
{
  for(fdpage_list_t::const_iterator iter = pages.begin(); iter != pages.end(); ++iter){
    if(start <= (*iter)->end()){
      if(!(*iter)->loaded){
        resstart = (*iter)->offset;
        ressize  = (*iter)->bytes;
        return true;
      }
    }
  }
  return false;
}

size_t PageList::GetTotalUnloadedPageSize(off_t start, size_t size) const
{
  size_t restsize = 0;
  off_t  next     = static_cast<off_t>(start + size);
  for(fdpage_list_t::const_iterator iter = pages.begin(); iter != pages.end(); ++iter){
    if((*iter)->next() <= start){
      continue;
    }
    if(next <= (*iter)->offset){
      break;
    }
    if((*iter)->loaded){
      continue;
    }
    size_t tmpsize;
    if((*iter)->offset <= start){
      if((*iter)->next() <= next){
        tmpsize = static_cast<size_t>((*iter)->next() - start);
      }else{
        tmpsize = static_cast<size_t>(next - start);                         // = size
      }
    }else{
      if((*iter)->next() <= next){
        tmpsize = static_cast<size_t>((*iter)->next() - (*iter)->offset);   // = (*iter)->bytes
      }else{
        tmpsize = static_cast<size_t>(next - (*iter)->offset);
      }
    }
    restsize += tmpsize;
  }
  return restsize;
}

int PageList::GetUnloadedPages(fdpage_list_t& unloaded_list, off_t start, size_t size) const
{
  // If size is 0, it means loading to end.
  if(0 == size){
    if(static_cast<size_t>(start) < Size()){
      size = static_cast<size_t>(Size() - start);
    }
  }
  off_t next = static_cast<off_t>(start + size);

  for(fdpage_list_t::const_iterator iter = pages.begin(); iter != pages.end(); ++iter){
    if((*iter)->next() <= start){
      continue;
    }
    if(next <= (*iter)->offset){
      break;
    }
    if((*iter)->loaded){
      continue; // already loaded
    }

    // page area
    off_t  page_start = max((*iter)->offset, start);
    off_t  page_next  = min((*iter)->next(), next);
    size_t page_size  = static_cast<size_t>(page_next - page_start);

    // add list
    fdpage_list_t::reverse_iterator riter = unloaded_list.rbegin();
    if(riter != unloaded_list.rend() && (*riter)->next() == page_start){
      // merge to before page
      (*riter)->bytes += page_size;
    }else{
      fdpage* page = new fdpage(page_start, page_size, false);
      unloaded_list.push_back(page);
    }
  }
  return unloaded_list.size();
}

bool PageList::Serialize(CacheFileStat& file, bool is_output)
{
  if(!file.Open()){
    return false;
  }
  if(is_output){
    //
    // put to file
    //
    stringstream ssall;
    ssall << Size();

    for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); ++iter){
      ssall << "\n" << (*iter)->offset << ":" << (*iter)->bytes << ":" << ((*iter)->loaded ? "1" : "0");
    }

    string strall = ssall.str();
    if(0 >= pwrite(file.GetFd(), strall.c_str(), strall.length(), 0)){
      S3FS_PRN_ERR("failed to write stats(%d)", errno);
      return false;
    }

  }else{
    //
    // loading from file
    //
    struct stat st;
    memset(&st, 0, sizeof(struct stat));
    if(-1 == fstat(file.GetFd(), &st)){
      S3FS_PRN_ERR("fstat is failed. errno(%d)", errno);
      return false;
    }
    if(0 >= st.st_size){
      // nothing
      Init(0, false);
      return true;
    }
    char* ptmp;
    if(NULL == (ptmp = (char*)calloc(st.st_size + 1, sizeof(char)))){
      S3FS_PRN_CRIT("could not allocate memory.");
      S3FS_FUSE_EXIT();
      return false;
    }
    // read from file
    if(0 >= pread(file.GetFd(), ptmp, st.st_size, 0)){
      S3FS_PRN_ERR("failed to read stats(%d)", errno);
      free(ptmp);
      return false;
    }
    string       oneline;
    stringstream ssall(ptmp);

    // loaded
    Clear();

    // load(size)
    if(!getline(ssall, oneline, '\n')){
      S3FS_PRN_ERR("failed to parse stats.");
      free(ptmp);
      return false;
    }
    size_t total = s3fs_strtoofft(oneline.c_str());

    // load each part
    bool is_err = false;
    while(getline(ssall, oneline, '\n')){
      string       part;
      stringstream ssparts(oneline);
      // offset
      if(!getline(ssparts, part, ':')){
        is_err = true;
        break;
      }
      off_t offset = s3fs_strtoofft(part.c_str());
      // size
      if(!getline(ssparts, part, ':')){
        is_err = true;
        break;
      }
      off_t size = s3fs_strtoofft(part.c_str());
      // loaded
      if(!getline(ssparts, part, ':')){
        is_err = true;
        break;
      }
      bool is_loaded = (1 == s3fs_strtoofft(part.c_str()) ? true : false);
      // add new area
      SetPageLoadedStatus(offset, size, is_loaded);
    }
    free(ptmp);
    if(is_err){
      S3FS_PRN_ERR("failed to parse stats.");
      Clear();
      return false;
    }

    // check size
    if(total != Size()){
      S3FS_PRN_ERR("different size(%jd - %jd).", (intmax_t)total, (intmax_t)Size());
      Clear();
      return false;
    }
  }
  return true;
}

void PageList::Dump(void)
{
  int cnt = 0;

  S3FS_PRN_DBG("pages = {");
  for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); ++iter, ++cnt){
    S3FS_PRN_DBG("  [%08d] -> {%014jd - %014zu : %s}", cnt, (intmax_t)((*iter)->offset), (*iter)->bytes, (*iter)->loaded ? "true" : "false");
  }
  S3FS_PRN_DBG("}");
}

//------------------------------------------------
// FdEntity class methods
//------------------------------------------------
int FdEntity::FillFile(int fd, unsigned char byte, size_t size, off_t start)
{
  unsigned char bytes[1024 * 32];         // 32kb
  memset(bytes, byte, min(sizeof(bytes), size));

  for(ssize_t total = 0, onewrote = 0; static_cast<size_t>(total) < size; total += onewrote){
    if(-1 == (onewrote = pwrite(fd, bytes, min(sizeof(bytes), (size - static_cast<size_t>(total))), start + total))){
      S3FS_PRN_ERR("pwrite failed. errno(%d)", errno);
      return -errno;
    }
  }
  return 0;
}

//------------------------------------------------
// FdEntity methods
//------------------------------------------------
FdEntity::FdEntity(const char* tpath, const char* cpath)
        : is_lock_init(false), refcnt(0), path(SAFESTRPTR(tpath)), cachepath(SAFESTRPTR(cpath)), mirrorpath(""),
          fd(-1), pfile(NULL), is_modify(false), size_orgmeta(0), upload_id(""), mp_start(0), mp_size(0)
{
  try{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, S3FS_MUTEX_RECURSIVE);   // recursive mutex
    pthread_mutex_init(&fdent_lock, &attr);
    is_lock_init = true;
  }catch(exception& e){
    S3FS_PRN_CRIT("failed to init mutex");
  }
}

FdEntity::~FdEntity()
{
  Clear();

  if(is_lock_init){
    try{
      pthread_mutex_destroy(&fdent_lock);
    }catch(exception& e){
      S3FS_PRN_CRIT("failed to destroy mutex");
    }
    is_lock_init = false;
  }
}

void FdEntity::Clear(void)
{
  AutoLock auto_lock(&fdent_lock);

  if(-1 != fd){
    if(0 != cachepath.size()){
      CacheFileStat cfstat(path.c_str());
      if(!pagelist.Serialize(cfstat, true)){
        S3FS_PRN_WARN("failed to save cache stat file(%s).", path.c_str());
      }
    }
    if(pfile){
      fclose(pfile);
      pfile = NULL;
    }
    fd = -1;

    if(!mirrorpath.empty()){
      if(-1 == unlink(mirrorpath.c_str())){
        S3FS_PRN_WARN("failed to remove mirror cache file(%s) by errno(%d).", mirrorpath.c_str(), errno);
      }
      mirrorpath.erase();
    }
  }
  pagelist.Init(0, false);
  refcnt        = 0;
  path          = "";
  cachepath     = "";
  is_modify     = false;
}

void FdEntity::Close(void)
{
  S3FS_PRN_DBG("[path=%s][fd=%d][refcnt=%d]", path.c_str(), fd, (-1 != fd ? refcnt - 1 : refcnt));

  if(-1 != fd){
    AutoLock auto_lock(&fdent_lock);

    if(0 < refcnt){
      refcnt--;
    }
    if(0 == refcnt){
      if(0 != cachepath.size()){
        CacheFileStat cfstat(path.c_str());
        if(!pagelist.Serialize(cfstat, true)){
          S3FS_PRN_WARN("failed to save cache stat file(%s).", path.c_str());
        }
      }
      if(pfile){
        fclose(pfile);
        pfile = NULL;
      }
      fd = -1;

      if(!mirrorpath.empty()){
        if(-1 == unlink(mirrorpath.c_str())){
          S3FS_PRN_WARN("failed to remove mirror cache file(%s) by errno(%d).", mirrorpath.c_str(), errno);
        }
        mirrorpath.erase();
      }
    }
  }
}

int FdEntity::Dup()
{
  S3FS_PRN_DBG("[path=%s][fd=%d][refcnt=%d]", path.c_str(), fd, (-1 != fd ? refcnt + 1 : refcnt));

  if(-1 != fd){
    AutoLock auto_lock(&fdent_lock);
    refcnt++;
  }
  return fd;
}

//
// Open mirror file which is linked cache file.
//
int FdEntity::OpenMirrorFile(void)
{
  if(cachepath.empty()){
    S3FS_PRN_ERR("cache path is empty, why come here");
    return -EIO;
  }

  // make temporary directory
  string bupdir;
  if(!FdManager::MakeCachePath(NULL, bupdir, true, true)){
    S3FS_PRN_ERR("could not make bup cache directory path or create it.");
    return -EIO;
  }

  // create seed generating mirror file name
  unsigned int seed = static_cast<unsigned int>(time(NULL));
  int urandom_fd;
  if(-1 != (urandom_fd = open("/dev/urandom", O_RDONLY))){
    unsigned int rand_data;
    if(sizeof(rand_data) == read(urandom_fd, &rand_data, sizeof(rand_data))){
      seed ^= rand_data;
    }
    close(urandom_fd);
  }

  // try to link mirror file
  while(true){
    // make random(temp) file path
    // (do not care for threading, because allowed any value returned.)
    //
    char         szfile[NAME_MAX + 1];
    sprintf(szfile, "%x.tmp", rand_r(&seed));
    mirrorpath = bupdir + "/" + szfile;

    // link mirror file to cache file
    if(0 == link(cachepath.c_str(), mirrorpath.c_str())){
      break;
    }
    if(EEXIST != errno){
      S3FS_PRN_ERR("could not link mirror file(%s) to cache file(%s) by errno(%d).", mirrorpath.c_str(), cachepath.c_str(), errno);
      return -errno;
    }
    ++seed;
  }

  // open mirror file
  int mirrorfd;
  if(-1 == (mirrorfd = open(mirrorpath.c_str(), O_RDWR))){
    S3FS_PRN_ERR("could not open mirror file(%s) by errno(%d).", mirrorpath.c_str(), errno);
    return -errno;
  }
  return mirrorfd;
}

int FdEntity::Open(headers_t* pmeta, ssize_t size, time_t time, bool no_fd_lock_wait)
{
  S3FS_PRN_DBG("[path=%s][fd=%d][size=%jd][time=%jd]", path.c_str(), fd, (intmax_t)size, (intmax_t)time);

  AutoLock auto_lock(&fdent_lock, no_fd_lock_wait);
  if (!auto_lock.isLockAcquired()) {
    // had to wait for fd lock, return
    return -EIO;
  }

  if(-1 != fd){
    // already opened, needs to increment refcnt.
    Dup();

    // check only file size(do not need to save cfs and time.
    if(0 <= size && pagelist.Size() != static_cast<size_t>(size)){
      // truncate temporary file size
      if(-1 == ftruncate(fd, static_cast<size_t>(size))){
        S3FS_PRN_ERR("failed to truncate temporary file(%d) by errno(%d).", fd, errno);
        return -EIO;
      }
      // resize page list
      if(!pagelist.Resize(static_cast<size_t>(size), false)){
        S3FS_PRN_ERR("failed to truncate temporary file information(%d).", fd);
        return -EIO;
      }
    }
    // set original headers and set size.
    size_t new_size = (0 <= size ? static_cast<size_t>(size) : size_orgmeta);
    if(pmeta){
      orgmeta  = *pmeta;
      new_size = static_cast<size_t>(get_size(orgmeta));
    }
    if(new_size < size_orgmeta){
      size_orgmeta = new_size;
    }
    return 0;
  }

  bool  need_save_csf = false;  // need to save(reset) cache stat file
  bool  is_truncate   = false;  // need to truncate

  if(0 != cachepath.size()){
    // using cache

    // open cache and cache stat file, load page info.
    CacheFileStat cfstat(path.c_str());

    // try to open cache file
    if(-1 != (fd = open(cachepath.c_str(), O_RDWR)) && pagelist.Serialize(cfstat, false)){
      // succeed to open cache file and to load stats data
      struct stat st;
      memset(&st, 0, sizeof(struct stat));
      if(-1 == fstat(fd, &st)){
        S3FS_PRN_ERR("fstat is failed. errno(%d)", errno);
        fd = -1;
        return (0 == errno ? -EIO : -errno);
      }
      // check size, st_size, loading stat file
      if(-1 == size){
        if(static_cast<size_t>(st.st_size) != pagelist.Size()){
          pagelist.Resize(st.st_size, false);
          need_save_csf = true;     // need to update page info
        }
        size = static_cast<ssize_t>(st.st_size);
      }else{
        if(static_cast<size_t>(size) != pagelist.Size()){
          pagelist.Resize(static_cast<size_t>(size), false);
          need_save_csf = true;     // need to update page info
        }
        if(static_cast<size_t>(size) != static_cast<size_t>(st.st_size)){
          is_truncate = true;
        }
      }

    }else{
      // could not open cache file or could not load stats data, so initialize it.
      if(-1 == (fd = open(cachepath.c_str(), O_CREAT|O_RDWR|O_TRUNC, 0600))){
        S3FS_PRN_ERR("failed to open file(%s). errno(%d)", cachepath.c_str(), errno);
        return (0 == errno ? -EIO : -errno);
      }
      need_save_csf = true;       // need to update page info
      if(-1 == size){
        size = 0;
        pagelist.Init(0, false);
      }else{
        pagelist.Resize(static_cast<size_t>(size), false);
        is_truncate = true;
      }
    }

    // open mirror file
    int mirrorfd;
    if(0 >= (mirrorfd = OpenMirrorFile())){
      S3FS_PRN_ERR("failed to open mirror file linked cache file(%s).", cachepath.c_str());
      return (0 == mirrorfd ? -EIO : mirrorfd);
    }
    // switch fd
    close(fd);
    fd = mirrorfd;

    // make file pointer(for being same tmpfile)
    if(NULL == (pfile = fdopen(fd, "wb"))){
      S3FS_PRN_ERR("failed to get fileno(%s). errno(%d)", cachepath.c_str(), errno);
      close(fd);
      fd = -1;
      return (0 == errno ? -EIO : -errno);
    }

  }else{
    // not using cache

    // open temporary file
    if(NULL == (pfile = tmpfile()) || -1 ==(fd = fileno(pfile))){
      S3FS_PRN_ERR("failed to open tmp file. err(%d)", errno);
      if(pfile){
        fclose(pfile);
        pfile = NULL;
      }
      return (0 == errno ? -EIO : -errno);
    }
    if(-1 == size){
      size = 0;
      pagelist.Init(0, false);
    }else{
      pagelist.Resize(static_cast<size_t>(size), false);
      is_truncate = true;
    }
  }

  // truncate cache(tmp) file
  if(is_truncate){
    if(0 != ftruncate(fd, static_cast<off_t>(size)) || 0 != fsync(fd)){
      S3FS_PRN_ERR("ftruncate(%s) or fsync returned err(%d)", cachepath.c_str(), errno);
      fclose(pfile);
      pfile = NULL;
      fd    = -1;
      return (0 == errno ? -EIO : -errno);
    }
  }

  // reset cache stat file
  if(need_save_csf){
    CacheFileStat cfstat(path.c_str());
    if(!pagelist.Serialize(cfstat, true)){
      S3FS_PRN_WARN("failed to save cache stat file(%s), but continue...", path.c_str());
    }
  }

  // init internal data
  refcnt    = 1;
  is_modify = false;

  // set original headers and size in it.
  if(pmeta){
    orgmeta      = *pmeta;
    size_orgmeta = static_cast<size_t>(get_size(orgmeta));
  }else{
    orgmeta.clear();
    size_orgmeta = 0;
  }

  // set mtime(set "x-amz-meta-mtime" in orgmeta)
  if(-1 != time){
    if(0 != SetMtime(time)){
      S3FS_PRN_ERR("failed to set mtime. errno(%d)", errno);
      fclose(pfile);
      pfile = NULL;
      fd    = -1;
      return (0 == errno ? -EIO : -errno);
    }
  }

  return 0;
}

// [NOTE]
// This method is called from only nocopyapi functions.
// So we do not check disk space for this option mode, if there is no enough
// disk space this method will be failed.
//
bool FdEntity::OpenAndLoadAll(headers_t* pmeta, size_t* size, bool force_load)
{
  int result;

  S3FS_PRN_INFO3("[path=%s][fd=%d]", path.c_str(), fd);

  if(-1 == fd){
    if(0 != Open(pmeta)){
      return false;
    }
  }
  AutoLock auto_lock(&fdent_lock);

  if(force_load){
    SetAllStatusUnloaded();
  }
  //
  // TODO: possibly do background for delay loading
  //
  if(0 != (result = Load())){
    S3FS_PRN_ERR("could not download, result(%d)", result);
    return false;
  }
  if(is_modify){
    is_modify = false;
  }
  if(size){
    *size = pagelist.Size();
  }
  return true;
}

bool FdEntity::GetStats(struct stat& st)
{
  AutoLock auto_lock(&fdent_lock);
  if(-1 == fd){
    return false;
  }

  memset(&st, 0, sizeof(struct stat)); 
  if(-1 == fstat(fd, &st)){
    S3FS_PRN_ERR("fstat failed. errno(%d)", errno);
    return false;
  }
  return true;
}

int FdEntity::SetMtime(time_t time)
{
  S3FS_PRN_INFO3("[path=%s][fd=%d][time=%jd]", path.c_str(), fd, (intmax_t)time);

  if(-1 == time){
    return 0;
  }

  AutoLock auto_lock(&fdent_lock);
  if(-1 != fd){
    struct timeval tv[2];
    tv[0].tv_sec = time;
    tv[0].tv_usec= 0L;
    tv[1].tv_sec = tv[0].tv_sec;
    tv[1].tv_usec= 0L;
    if(-1 == futimes(fd, tv)){
      S3FS_PRN_ERR("futimes failed. errno(%d)", errno);
      return -errno;
    }
  }else if(0 < cachepath.size()){
    // not opened file yet.
    struct utimbuf n_mtime;
    n_mtime.modtime = time;
    n_mtime.actime  = time;
    if(-1 == utime(cachepath.c_str(), &n_mtime)){
      S3FS_PRN_ERR("utime failed. errno(%d)", errno);
      return -errno;
    }
  }
  orgmeta["x-amz-meta-mtime"] = str(time);

  return 0;
}

bool FdEntity::UpdateMtime(void)
{
  AutoLock auto_lock(&fdent_lock);
  struct stat st;
  if(!GetStats(st)){
    return false;
  }
  orgmeta["x-amz-meta-mtime"] = str(st.st_mtime);
  return true;
}

bool FdEntity::GetSize(size_t& size)
{
  if(-1 == fd){
    return false;
  }
  AutoLock auto_lock(&fdent_lock);

  size = pagelist.Size();
  return true;
}

bool FdEntity::SetMode(mode_t mode)
{
  AutoLock auto_lock(&fdent_lock);
  orgmeta["x-amz-meta-mode"] = str(mode);
  return true;
}

bool FdEntity::SetUId(uid_t uid)
{
  AutoLock auto_lock(&fdent_lock);
  orgmeta["x-amz-meta-uid"] = str(uid);
  return true;
}

bool FdEntity::SetGId(gid_t gid)
{
  AutoLock auto_lock(&fdent_lock);
  orgmeta["x-amz-meta-gid"] = str(gid);
  return true;
}

bool FdEntity::SetContentType(const char* path)
{
  if(!path){
    return false;
  }
  AutoLock auto_lock(&fdent_lock);
  orgmeta["Content-Type"] = S3fsCurl::LookupMimeType(string(path));
  return true;
}

bool FdEntity::SetAllStatus(bool is_loaded)
{
  S3FS_PRN_INFO3("[path=%s][fd=%d][%s]", path.c_str(), fd, is_loaded ? "loaded" : "unloaded");

  if(-1 == fd){
    return false;
  }
  // [NOTE]
  // this method is only internal use, and calling after locking.
  // so do not lock now.
  //
  //AutoLock auto_lock(&fdent_lock);

  // get file size
  struct stat st;
  memset(&st, 0, sizeof(struct stat));
  if(-1 == fstat(fd, &st)){
    S3FS_PRN_ERR("fstat is failed. errno(%d)", errno);
    return false;
  }
  // Reinit
  pagelist.Init(st.st_size, is_loaded);

  return true;
}

int FdEntity::Load(off_t start, size_t size)
{
  S3FS_PRN_DBG("[path=%s][fd=%d][offset=%jd][size=%jd]", path.c_str(), fd, (intmax_t)start, (intmax_t)size);

  if(-1 == fd){
    return -EBADF;
  }
  AutoLock auto_lock(&fdent_lock);

  int result = 0;

  // check loaded area & load
  fdpage_list_t unloaded_list;
  if(0 < pagelist.GetUnloadedPages(unloaded_list, start, size)){
    for(fdpage_list_t::iterator iter = unloaded_list.begin(); iter != unloaded_list.end(); ++iter){
      if(0 != size && static_cast<size_t>(start + size) <= static_cast<size_t>((*iter)->offset)){
        // reached end
        break;
      }
      // check loading size
      size_t need_load_size = 0;
      if(static_cast<size_t>((*iter)->offset) < size_orgmeta){
        // original file size(on S3) is smaller than request.
        need_load_size = (static_cast<size_t>((*iter)->next()) <= size_orgmeta ? (*iter)->bytes : (size_orgmeta - (*iter)->offset));
      }
      size_t over_size = (*iter)->bytes - need_load_size;

      // download
      if(static_cast<size_t>(2 * S3fsCurl::GetMultipartSize()) <= need_load_size && !nomultipart){ // default 20MB
        // parallel request
        // Additional time is needed for large files
        time_t backup = 0;
        if(120 > S3fsCurl::GetReadwriteTimeout()){
          backup = S3fsCurl::SetReadwriteTimeout(120);
        }
        result = S3fsCurl::ParallelGetObjectRequest(path.c_str(), fd, (*iter)->offset, need_load_size);
        if(0 != backup){
          S3fsCurl::SetReadwriteTimeout(backup);
        }
      }else{
        // single request
        if(0 < need_load_size){
          S3fsCurl s3fscurl;
          result = s3fscurl.GetObjectRequest(path.c_str(), fd, (*iter)->offset, need_load_size);
        }else{
          result = 0;
        }
      }
      if(0 != result){
        break;
      }

      // initialize for the area of over original size
      if(0 < over_size){
        if(0 != (result = FdEntity::FillFile(fd, 0, over_size, (*iter)->offset + need_load_size))){
          S3FS_PRN_ERR("failed to fill rest bytes for fd(%d). errno(%d)", fd, result);
          break;
        }
        // set modify flag
        is_modify = false;
      }

      // Set loaded flag
      pagelist.SetPageLoadedStatus((*iter)->offset, static_cast<off_t>((*iter)->bytes), true);
    }
    PageList::FreeList(unloaded_list);
  }
  return result;
}

// [NOTE]
// At no disk space for caching object.
// This method is downloading by dividing an object of the specified range
// and uploading by multipart after finishing downloading it.
//
// [NOTICE]
// Need to lock before calling this method.
//
int FdEntity::NoCacheLoadAndPost(off_t start, size_t size)
{
  int result = 0;

  S3FS_PRN_INFO3("[path=%s][fd=%d][offset=%jd][size=%jd]", path.c_str(), fd, (intmax_t)start, (intmax_t)size);

  if(-1 == fd){
    return -EBADF;
  }

  // [NOTE]
  // This method calling means that the cache file is never used no more.
  //
  if(0 != cachepath.size()){
    // remove cache files(and cache stat file)
    FdManager::DeleteCacheFile(path.c_str());
    // cache file path does not use no more.
    cachepath.erase();
    mirrorpath.erase();
  }

  // Change entity key in manager mapping
  FdManager::get()->ChangeEntityToTempPath(this, path.c_str());

  // open temporary file
  FILE* ptmpfp;
  int   tmpfd;
  if(NULL == (ptmpfp = tmpfile()) || -1 ==(tmpfd = fileno(ptmpfp))){
    S3FS_PRN_ERR("failed to open tmp file. err(%d)", errno);
    if(ptmpfp){
      fclose(ptmpfp);
    }
    return (0 == errno ? -EIO : -errno);
  }

  // loop uploading by multipart
  for(fdpage_list_t::iterator iter = pagelist.pages.begin(); iter != pagelist.pages.end(); ++iter){
    if((*iter)->end() < start){
      continue;
    }
    if(0 != size && static_cast<size_t>(start + size) <= static_cast<size_t>((*iter)->offset)){
      break;
    }
    // download each multipart size(default 10MB) in unit
    for(size_t oneread = 0, totalread = ((*iter)->offset < start ? start : 0); totalread < (*iter)->bytes; totalread += oneread){
      int   upload_fd = fd;
      off_t offset    = (*iter)->offset + totalread;
      oneread         = min(((*iter)->bytes - totalread), static_cast<size_t>(S3fsCurl::GetMultipartSize()));

      // check rest size is over minimum part size
      //
      // [NOTE]
      // If the final part size is smaller than 5MB, it is not allowed by S3 API.
      // For this case, if the previous part of the final part is not over 5GB,
      // we incorporate the final part to the previous part. If the previous part
      // is over 5GB, we want to even out the last part and the previous part.
      //
      if(((*iter)->bytes - totalread - oneread) < MIN_MULTIPART_SIZE){
        if(FIVE_GB < ((*iter)->bytes - totalread)){
          oneread = ((*iter)->bytes - totalread) / 2;
        }else{
          oneread = ((*iter)->bytes - totalread);
        }
      }

      if(!(*iter)->loaded){
        //
        // loading or initializing
        //
        upload_fd = tmpfd;

        // load offset & size
        size_t need_load_size = 0;
        if(size_orgmeta <= static_cast<size_t>(offset)){
          // all area is over of original size
          need_load_size      = 0;
        }else{
          if(size_orgmeta < (offset + oneread)){
            // original file size(on S3) is smaller than request.
            need_load_size    = size_orgmeta - offset;
          }else{
            need_load_size    = oneread;
          }
        }
        size_t over_size      = oneread - need_load_size;

        // [NOTE]
        // truncate file to zero and set length to part offset + size
        // after this, file length is (offset + size), but file does not use any disk space.
        //
        if(-1 == ftruncate(tmpfd, 0) || -1 == ftruncate(tmpfd, (offset + oneread))){
          S3FS_PRN_ERR("failed to truncate temporary file(%d).", tmpfd);
          result = -EIO;
          break;
        }

        // single area get request
        if(0 < need_load_size){
          S3fsCurl s3fscurl;
          if(0 != (result = s3fscurl.GetObjectRequest(path.c_str(), tmpfd, offset, oneread))){
            S3FS_PRN_ERR("failed to get object(start=%zd, size=%zu) for file(%d).", offset, oneread, tmpfd);
            break;
          }
        }
        // initialize fd without loading
        if(0 < over_size){
          if(0 != (result = FdEntity::FillFile(tmpfd, 0, over_size, offset + need_load_size))){
            S3FS_PRN_ERR("failed to fill rest bytes for fd(%d). errno(%d)", tmpfd, result);
            break;
          }
          // set modify flag
          is_modify = false;
        }

      }else{
        // already loaded area
      }

      // single area upload by multipart post
      if(0 != (result = NoCacheMultipartPost(upload_fd, offset, oneread))){
        S3FS_PRN_ERR("failed to multipart post(start=%zd, size=%zu) for file(%d).", offset, oneread, upload_fd);
        break;
      }
    }
    if(0 != result){
      break;
    }

    // set loaded flag
    if(!(*iter)->loaded){
      if((*iter)->offset < start){
        fdpage* page    = new fdpage((*iter)->offset, static_cast<size_t>(start - (*iter)->offset), (*iter)->loaded);
        (*iter)->bytes -= (start - (*iter)->offset);
        (*iter)->offset = start;
        pagelist.pages.insert(iter, page);
      }
      if(0 != size && static_cast<size_t>(start + size) < static_cast<size_t>((*iter)->next())){
        fdpage* page    = new fdpage((*iter)->offset, static_cast<size_t>((start + size) - (*iter)->offset), true);
        (*iter)->bytes -= static_cast<size_t>((start + size) - (*iter)->offset);
        (*iter)->offset = start + size;
        pagelist.pages.insert(iter, page);
      }else{
        (*iter)->loaded = true;
      }
    }
  }
  if(0 == result){
    // compress pagelist
    pagelist.Compress();

    // fd data do empty
    if(-1 == ftruncate(fd, 0)){
      S3FS_PRN_ERR("failed to truncate file(%d), but continue...", fd);
    }
  }

  // close temporary
  fclose(ptmpfp);

  return result;
}

// [NOTE]
// At no disk space for caching object.
// This method is starting multipart uploading.
//
int FdEntity::NoCachePreMultipartPost(void)
{
  // initialize multipart upload values
  upload_id.erase();
  etaglist.clear();

  S3fsCurl s3fscurl(true);
  int      result;
  if(0 != (result = s3fscurl.PreMultipartPostRequest(path.c_str(), orgmeta, upload_id, false))){
    return result;
  }
  s3fscurl.DestroyCurlHandle();
  return 0;
}

// [NOTE]
// At no disk space for caching object.
// This method is uploading one part of multipart.
//
int FdEntity::NoCacheMultipartPost(int tgfd, off_t start, size_t size)
{
  if(-1 == tgfd || upload_id.empty()){
    S3FS_PRN_ERR("Need to initialize for multipart post.");
    return -EIO;
  }
  S3fsCurl s3fscurl(true);
  return s3fscurl.MultipartUploadRequest(upload_id, path.c_str(), tgfd, start, size, etaglist);
}

// [NOTE]
// At no disk space for caching object.
// This method is finishing multipart uploading.
//
int FdEntity::NoCacheCompleteMultipartPost(void)
{
  if(upload_id.empty() || etaglist.empty()){
    S3FS_PRN_ERR("There is no upload id or etag list.");
    return -EIO;
  }

  S3fsCurl s3fscurl(true);
  int      result;
  if(0 != (result = s3fscurl.CompleteMultipartPostRequest(path.c_str(), upload_id, etaglist))){
    return result;
  }
  s3fscurl.DestroyCurlHandle();

  // reset values
  upload_id.erase();
  etaglist.clear();
  mp_start = 0;
  mp_size  = 0;

  return 0;
}

int FdEntity::RowFlush(const char* tpath, bool force_sync)
{
  int result = 0;

  S3FS_PRN_INFO3("[tpath=%s][path=%s][fd=%d]", SAFESTRPTR(tpath), path.c_str(), fd);

  if(-1 == fd){
    return -EBADF;
  }
  AutoLock auto_lock(&fdent_lock);

  if(!force_sync && !is_modify){
    // nothing to update.
    return 0;
  }

  // If there is no loading all of the area, loading all area.
  size_t restsize = pagelist.GetTotalUnloadedPageSize();
  if(0 < restsize){
    if(0 == upload_id.length()){
      // check disk space
      if(ReserveDiskSpace(restsize)){
        // enough disk space
        // Load all uninitialized area
        result = Load();
        FdManager::get()->FreeReservedDiskSpace(restsize);
        if(0 != result){
          S3FS_PRN_ERR("failed to upload all area(errno=%d)", result);
          return static_cast<ssize_t>(result);
        }
      }else{
        // no enough disk space
        // upload all by multipart uploading
        if(0 != (result = NoCacheLoadAndPost())){
          S3FS_PRN_ERR("failed to upload all area by multipart uploading(errno=%d)", result);
          return static_cast<ssize_t>(result);
        }
      }
    }else{
      // already start multipart uploading
    }
  }

  if(0 == upload_id.length()){
    // normal uploading

    /*
     * Make decision to do multi upload (or not) based upon file size
     * 
     * According to the AWS spec:
     *  - 1 to 10,000 parts are allowed
     *  - minimum size of parts is 5MB (expect for the last part)
     * 
     * For our application, we will define minimum part size to be 10MB (10 * 2^20 Bytes)
     * minimum file size will be 64 GB - 2 ** 36 
     * 
     * Initially uploads will be done serially
     * 
     * If file is > 20MB, then multipart will kick in
     */
    if(pagelist.Size() > static_cast<size_t>(MAX_MULTIPART_CNT * S3fsCurl::GetMultipartSize())){
      // close f ?
      return -ENOTSUP;
    }

    // seek to head of file.
    if(0 != lseek(fd, 0, SEEK_SET)){
      S3FS_PRN_ERR("lseek error(%d)", errno);
      return -errno;
    }
    // backup upload file size
    struct stat st;
    memset(&st, 0, sizeof(struct stat));
    if(-1 == fstat(fd, &st)){
      S3FS_PRN_ERR("fstat is failed by errno(%d), but continue...", errno);
    }

    if(pagelist.Size() >= static_cast<size_t>(2 * S3fsCurl::GetMultipartSize()) && !nomultipart){ // default 20MB
      // Additional time is needed for large files
      time_t backup = 0;
      if(120 > S3fsCurl::GetReadwriteTimeout()){
        backup = S3fsCurl::SetReadwriteTimeout(120);
      }
      result = S3fsCurl::ParallelMultipartUploadRequest(tpath ? tpath : path.c_str(), orgmeta, fd);
      if(0 != backup){
        S3fsCurl::SetReadwriteTimeout(backup);
      }
    }else{
      S3fsCurl s3fscurl(true);
      result = s3fscurl.PutRequest(tpath ? tpath : path.c_str(), orgmeta, fd);
    }

    // seek to head of file.
    if(0 == result && 0 != lseek(fd, 0, SEEK_SET)){
      S3FS_PRN_ERR("lseek error(%d)", errno);
      return -errno;
    }

    // reset uploaded file size
    size_orgmeta = static_cast<size_t>(st.st_size);

  }else{
    // upload rest data
    if(0 < mp_size){
      if(0 != (result = NoCacheMultipartPost(fd, mp_start, mp_size))){
        S3FS_PRN_ERR("failed to multipart post(start=%zd, size=%zu) for file(%d).", mp_start, mp_size, fd);
        return result;
      }
      mp_start = 0;
      mp_size  = 0;
    }
    // complete multipart uploading.
    if(0 != (result = NoCacheCompleteMultipartPost())){
      S3FS_PRN_ERR("failed to complete(finish) multipart post for file(%d).", fd);
      return result;
    }
    // truncate file to zero
    if(-1 == ftruncate(fd, 0)){
      // So the file has already been removed, skip error.
      S3FS_PRN_ERR("failed to truncate file(%d) to zero, but continue...", fd);
    }
  }

  if(0 == result){
    is_modify = false;
  }
  return result;
}

// [NOTICE]
// Need to lock before calling this method.
bool FdEntity::ReserveDiskSpace(size_t size)
{
  if(FdManager::get()->ReserveDiskSpace(size)){
    return true;
  }

  if(!is_modify){
    // try to clear all cache for this fd.
    pagelist.Init(pagelist.Size(), false);
    if(-1 == ftruncate(fd, 0) || -1 == ftruncate(fd, pagelist.Size())){
      S3FS_PRN_ERR("failed to truncate temporary file(%d).", fd);
      return false;
    }

    if(FdManager::get()->ReserveDiskSpace(size)){
      return true;
    }
  }

  FdManager::get()->CleanupCacheDir();

  return FdManager::get()->ReserveDiskSpace(size);
}

ssize_t FdEntity::Read(char* bytes, off_t start, size_t size, bool force_load)
{
  S3FS_PRN_DBG("[path=%s][fd=%d][offset=%jd][size=%zu]", path.c_str(), fd, (intmax_t)start, size);

  if(-1 == fd){
    return -EBADF;
  }
  AutoLock auto_lock(&fdent_lock);

  if(force_load){
    pagelist.SetPageLoadedStatus(start, size, false);
  }

  ssize_t rsize;

  // check disk space
  if(0 < pagelist.GetTotalUnloadedPageSize(start, size)){
    // load size(for prefetch)
    size_t load_size = size;
    if(static_cast<size_t>(start + size) < pagelist.Size()){
      size_t prefetch_max_size = max(size, static_cast<size_t>(S3fsCurl::GetMultipartSize() * S3fsCurl::GetMaxParallelCount()));

      if(static_cast<size_t>(start + prefetch_max_size) < pagelist.Size()){
        load_size = prefetch_max_size;
      }else{
        load_size = static_cast<size_t>(pagelist.Size() - start);
      }
    }

    if(!ReserveDiskSpace(load_size)){
      S3FS_PRN_WARN("could not reserve disk space for pre-fetch download");
      load_size = size;
      if(!ReserveDiskSpace(load_size)){
        S3FS_PRN_ERR("could not reserve disk space for pre-fetch download");
        return -ENOSPC;
      }
    }

    // Loading
    int result = 0;
    if(0 < size){
      result = Load(start, load_size);
    }

    FdManager::get()->FreeReservedDiskSpace(load_size);

    if(0 != result){
      S3FS_PRN_ERR("could not download. start(%jd), size(%zu), errno(%d)", (intmax_t)start, size, result);
      return -EIO;
    }
  }
  // Reading
  if(-1 == (rsize = pread(fd, bytes, size, start))){
    S3FS_PRN_ERR("pread failed. errno(%d)", errno);
    return -errno;
  }
  return rsize;
}

ssize_t FdEntity::Write(const char* bytes, off_t start, size_t size)
{
  S3FS_PRN_DBG("[path=%s][fd=%d][offset=%jd][size=%zu]", path.c_str(), fd, (intmax_t)start, size);

  if(-1 == fd){
    return -EBADF;
  }
  // check if not enough disk space left BEFORE locking fd
  if(FdManager::IsCacheDir() && !FdManager::IsSafeDiskSpace(NULL, size)){
    FdManager::get()->CleanupCacheDir();
  }
  AutoLock auto_lock(&fdent_lock);

  // check file size
  if(pagelist.Size() < static_cast<size_t>(start)){
    // grow file size
    if(-1 == ftruncate(fd, static_cast<size_t>(start))){
      S3FS_PRN_ERR("failed to truncate temporary file(%d).", fd);
      return -EIO;
    }
    // add new area
    pagelist.SetPageLoadedStatus(static_cast<off_t>(pagelist.Size()), static_cast<size_t>(start) - pagelist.Size(), false);
  }

  int     result = 0;
  ssize_t wsize;

  if(0 == upload_id.length()){
    // check disk space
    size_t restsize = pagelist.GetTotalUnloadedPageSize(0, start) + size;
    if(ReserveDiskSpace(restsize)){
      // enough disk space

      // Load uninitialized area which starts from 0 to (start + size) before writing.
      if(0 < start){
        result = Load(0, static_cast<size_t>(start));
      }
      FdManager::get()->FreeReservedDiskSpace(restsize);
      if(0 != result){
        S3FS_PRN_ERR("failed to load uninitialized area before writing(errno=%d)", result);
        return static_cast<ssize_t>(result);
      }
    }else{
      // no enough disk space
      if(0 != (result = NoCachePreMultipartPost())){
        S3FS_PRN_ERR("failed to switch multipart uploading with no cache(errno=%d)", result);
        return static_cast<ssize_t>(result);
      }
      // start multipart uploading
      if(0 != (result = NoCacheLoadAndPost(0, start))){
        S3FS_PRN_ERR("failed to load uninitialized area and multipart uploading it(errno=%d)", result);
        return static_cast<ssize_t>(result);
      }
      mp_start = start;
      mp_size  = 0;
    }
  }else{
    // already start multipart uploading
  }

  // Writing
  if(-1 == (wsize = pwrite(fd, bytes, size, start))){
    S3FS_PRN_ERR("pwrite failed. errno(%d)", errno);
    return -errno;
  }
  if(!is_modify){
    is_modify = true;
  }
  if(0 < wsize){
    pagelist.SetPageLoadedStatus(start, static_cast<size_t>(wsize), true);
  }

  // check multipart uploading
  if(0 < upload_id.length()){
    mp_size += static_cast<size_t>(wsize);
    if(static_cast<size_t>(S3fsCurl::GetMultipartSize()) <= mp_size){
      // over one multipart size
      if(0 != (result = NoCacheMultipartPost(fd, mp_start, mp_size))){
        S3FS_PRN_ERR("failed to multipart post(start=%zd, size=%zu) for file(%d).", mp_start, mp_size, fd);
        return result;
      }
      // [NOTE]
      // truncate file to zero and set length to part offset + size
      // after this, file length is (offset + size), but file does not use any disk space.
      //
      if(-1 == ftruncate(fd, 0) || -1 == ftruncate(fd, (mp_start + mp_size))){
        S3FS_PRN_ERR("failed to truncate file(%d).", fd);
        return -EIO;
      }
      mp_start += mp_size;
      mp_size   = 0;
    }
  }
  return wsize;
}

void FdEntity::CleanupCache()
{
  AutoLock auto_lock(&fdent_lock, true);

  if (!auto_lock.isLockAcquired()) {
    return;
  }

  if (is_modify) {
    // cache is not commited to s3, cannot cleanup
    return;
  }

  FdManager::DeleteCacheFile(path.c_str());
}

//------------------------------------------------
// FdManager symbol
//------------------------------------------------
// [NOTE]
// NOCACHE_PATH_PREFIX symbol needs for not using cache mode.
// Now s3fs I/F functions in s3fs.cpp has left the processing
// to FdManager and FdEntity class. FdManager class manages
// the list of local file stat and file descriptor in conjunction
// with the FdEntity class.
// When s3fs is not using local cache, it means FdManager must
// return new temporary file descriptor at each opening it.
// Then FdManager caches fd by key which is dummy file path
// instead of real file path.
// This process may not be complete, but it is easy way can
// be realized.
//
#define NOCACHE_PATH_PREFIX_FORM    " __S3FS_UNEXISTED_PATH_%lx__ / "      // important space words for simply

//------------------------------------------------
// FdManager class variable
//------------------------------------------------
FdManager       FdManager::singleton;
pthread_mutex_t FdManager::fd_manager_lock;
pthread_mutex_t FdManager::cache_cleanup_lock;
pthread_mutex_t FdManager::reserved_diskspace_lock;
bool            FdManager::is_lock_init(false);
string          FdManager::cache_dir("");
bool            FdManager::check_cache_dir_exist(false);
size_t          FdManager::free_disk_space = 0;

//------------------------------------------------
// FdManager class methods
//------------------------------------------------
bool FdManager::SetCacheDir(const char* dir)
{
  if(!dir || '\0' == dir[0]){
    cache_dir = "";
  }else{
    cache_dir = dir;
  }
  return true;
}

bool FdManager::DeleteCacheDirectory(void)
{
  if(0 == FdManager::cache_dir.size()){
    return true;
  }
  string cache_dir;
  if(!FdManager::MakeCachePath(NULL, cache_dir, false)){
    return false;
  }
  return delete_files_in_dir(cache_dir.c_str(), true);
}

int FdManager::DeleteCacheFile(const char* path)
{
  S3FS_PRN_INFO3("[path=%s]", SAFESTRPTR(path));

  if(!path){
    return -EIO;
  }
  if(0 == FdManager::cache_dir.size()){
    return 0;
  }
  string cache_path = "";
  if(!FdManager::MakeCachePath(path, cache_path, false)){
    return 0;
  }
  int result = 0;
  if(0 != unlink(cache_path.c_str())){
    if(ENOENT == errno){
      S3FS_PRN_DBG("failed to delete file(%s): errno=%d", path, errno);
    }else{
      S3FS_PRN_ERR("failed to delete file(%s): errno=%d", path, errno);
    }
    result = -errno;
  }
  if(!CacheFileStat::DeleteCacheFileStat(path)){
    if(ENOENT == errno){
      S3FS_PRN_DBG("failed to delete stat file(%s): errno=%d", path, errno);
    }else{
      S3FS_PRN_ERR("failed to delete stat file(%s): errno=%d", path, errno);
    }
    if(0 != errno){
      result = -errno;
    }else{
      result = -EIO;
    }
  }
  return result;
}

bool FdManager::MakeCachePath(const char* path, string& cache_path, bool is_create_dir, bool is_mirror_path)
{
  if(0 == FdManager::cache_dir.size()){
    cache_path = "";
    return true;
  }

  string resolved_path(FdManager::cache_dir);
  if(!is_mirror_path){
    resolved_path += "/";
    resolved_path += bucket;
  }else{
    resolved_path += "/.";
    resolved_path += bucket;
    resolved_path += ".mirror";
  }

  if(is_create_dir){
    int result;
    if(0 != (result = mkdirp(resolved_path + mydirname(path), 0777))){
      S3FS_PRN_ERR("failed to create dir(%s) by errno(%d).", path, result);
      return false;
    }
  }
  if(!path || '\0' == path[0]){
    cache_path = resolved_path;
  }else{
    cache_path = resolved_path + SAFESTRPTR(path);
  }
  return true;
}

bool FdManager::CheckCacheTopDir(void)
{
  if(0 == FdManager::cache_dir.size()){
    return true;
  }
  string toppath(FdManager::cache_dir + "/" + bucket);

  return check_exist_dir_permission(toppath.c_str());
}

bool FdManager::MakeRandomTempPath(const char* path, string& tmppath)
{
  char szBuff[64];

  sprintf(szBuff, NOCACHE_PATH_PREFIX_FORM, random());     // worry for performance, but maybe don't worry.
  tmppath  = szBuff;
  tmppath += path ? path : "";
  return true;
}

bool FdManager::SetCheckCacheDirExist(bool is_check)
{
  bool old = FdManager::check_cache_dir_exist;
  FdManager::check_cache_dir_exist = is_check;
  return old;
}

bool FdManager::CheckCacheDirExist(void)
{
  if(!FdManager::check_cache_dir_exist){
    return true;
  }
  if(0 == FdManager::cache_dir.size()){
    return true;
  }
  // check the directory
  struct stat st;
  if(0 != stat(cache_dir.c_str(), &st)){
    S3FS_PRN_ERR("could not access to cache directory(%s) by errno(%d).", cache_dir.c_str(), errno);
    return false;
  }
  if(!S_ISDIR(st.st_mode)){
    S3FS_PRN_ERR("the cache directory(%s) is not directory.", cache_dir.c_str());
    return false;
  }
  return true;
}

size_t FdManager::SetEnsureFreeDiskSpace(size_t size)
{
  size_t old = FdManager::free_disk_space;
  FdManager::free_disk_space = size;
  return old;
}

uint64_t FdManager::GetFreeDiskSpace(const char* path)
{
  struct statvfs vfsbuf;
  string         ctoppath;
  if(0 < FdManager::cache_dir.size()){
    ctoppath = FdManager::cache_dir + "/";
    ctoppath = get_exist_directory_path(ctoppath);	// existed directory
    if(ctoppath != "/"){
      ctoppath += "/";
    }
  }else{
    ctoppath = TMPFILE_DIR_0PATH "/";
  }
  if(path && '\0' != *path){
    ctoppath += path;
  }else{
    ctoppath += ".";
  }
  if(-1 == statvfs(ctoppath.c_str(), &vfsbuf)){
    S3FS_PRN_ERR("could not get vfs stat by errno(%d)", errno);
    return 0;
  }
  return (vfsbuf.f_bavail * vfsbuf.f_frsize);
}

bool FdManager::IsSafeDiskSpace(const char* path, size_t size)
{
  uint64_t fsize = FdManager::GetFreeDiskSpace(path);
  return ((size + FdManager::GetEnsureFreeDiskSpace()) <= fsize);
}

//------------------------------------------------
// FdManager methods
//------------------------------------------------
FdManager::FdManager()
{
  if(this == FdManager::get()){
    try{
      pthread_mutex_init(&FdManager::fd_manager_lock, NULL);
      pthread_mutex_init(&FdManager::cache_cleanup_lock, NULL);
      pthread_mutex_init(&FdManager::reserved_diskspace_lock, NULL);
      FdManager::is_lock_init = true;
    }catch(exception& e){
      FdManager::is_lock_init = false;
      S3FS_PRN_CRIT("failed to init mutex");
    }
  }else{
    assert(false);
  }
}

FdManager::~FdManager()
{
  if(this == FdManager::get()){
    for(fdent_map_t::iterator iter = fent.begin(); fent.end() != iter; ++iter){
      FdEntity* ent = (*iter).second;
      delete ent;
    }
    fent.clear();

    if(FdManager::is_lock_init){
      try{
        pthread_mutex_destroy(&FdManager::fd_manager_lock);
        pthread_mutex_destroy(&FdManager::cache_cleanup_lock);
        pthread_mutex_destroy(&FdManager::reserved_diskspace_lock);
      }catch(exception& e){
        S3FS_PRN_CRIT("failed to init mutex");
      }
      FdManager::is_lock_init = false;
    }
  }else{
    assert(false);
  }
}

FdEntity* FdManager::GetFdEntity(const char* path, int existfd)
{
  S3FS_PRN_INFO3("[path=%s][fd=%d]", SAFESTRPTR(path), existfd);

  if(!path || '\0' == path[0]){
    return NULL;
  }
  AutoLock auto_lock(&FdManager::fd_manager_lock);

  fdent_map_t::iterator iter = fent.find(string(path));
  if(fent.end() != iter && (-1 == existfd || (*iter).second->GetFd() == existfd)){
    return (*iter).second;
  }

  if(-1 != existfd){
    for(iter = fent.begin(); iter != fent.end(); ++iter){
      if((*iter).second && (*iter).second->GetFd() == existfd){
        // found opened fd in map
        if(0 == strcmp((*iter).second->GetPath(), path)){
          return (*iter).second;
        }
        // found fd, but it is used another file(file descriptor is recycled)
        // so returns NULL.
        break;
      }
    }
  }
  return NULL;
}

FdEntity* FdManager::Open(const char* path, headers_t* pmeta, ssize_t size, time_t time, bool force_tmpfile, bool is_create, bool no_fd_lock_wait)
{
  S3FS_PRN_DBG("[path=%s][size=%jd][time=%jd]", SAFESTRPTR(path), (intmax_t)size, (intmax_t)time);

  if(!path || '\0' == path[0]){
    return NULL;
  }
  FdEntity* ent;
  {
    AutoLock auto_lock(&FdManager::fd_manager_lock);

    // search in mapping by key(path)
    fdent_map_t::iterator iter = fent.find(string(path));

    if(fent.end() == iter && !force_tmpfile && !FdManager::IsCacheDir()){
      // If the cache directory is not specified, s3fs opens a temporary file
      // when the file is opened.
      // Then if it could not find a entity in map for the file, s3fs should
      // search a entity in all which opened the temporary file.
      //
      for(iter = fent.begin(); iter != fent.end(); ++iter){
        if((*iter).second && (*iter).second->IsOpen() && 0 == strcmp((*iter).second->GetPath(), path)){
          break;      // found opened fd in mapping
        }
      }
    }

    if(fent.end() != iter){
      // found
      ent = (*iter).second;

    }else if(is_create){
      // not found
      string cache_path = "";
      if(!force_tmpfile && !FdManager::MakeCachePath(path, cache_path, true)){
        S3FS_PRN_ERR("failed to make cache path for object(%s).", path);
        return NULL;
      }
      // make new obj
      ent = new FdEntity(path, cache_path.c_str());

      if(0 < cache_path.size()){
        // using cache
        fent[string(path)] = ent;
      }else{
        // not using cache, so the key of fdentity is set not really existing path.
        // (but not strictly unexisting path.)
        //
        // [NOTE]
        // The reason why this process here, please look at the definition of the
        // comments of NOCACHE_PATH_PREFIX_FORM symbol.
        //
        string tmppath("");
        FdManager::MakeRandomTempPath(path, tmppath);
        fent[tmppath] = ent;
      }
    }else{
      return NULL;
    }
  }

  // open
  if(0 != ent->Open(pmeta, size, time, no_fd_lock_wait)){
    return NULL;
  }
  return ent;
}

FdEntity* FdManager::ExistOpen(const char* path, int existfd, bool ignore_existfd)
{
  S3FS_PRN_DBG("[path=%s][fd=%d][ignore_existfd=%s]", SAFESTRPTR(path), existfd, ignore_existfd ? "true" : "false");

  // search by real path
  FdEntity* ent = Open(path, NULL, -1, -1, false, false);

  if(!ent && (ignore_existfd || (-1 != existfd))){
    // search from all fdentity because of not using cache.
    AutoLock auto_lock(&FdManager::fd_manager_lock);

    for(fdent_map_t::iterator iter = fent.begin(); iter != fent.end(); ++iter){
      if((*iter).second && (*iter).second->IsOpen() && (ignore_existfd || ((*iter).second->GetFd() == existfd))){
        // found opened fd in map
        if(0 == strcmp((*iter).second->GetPath(), path)){
          ent = (*iter).second;
          ent->Dup();
        }else{
          // found fd, but it is used another file(file descriptor is recycled)
          // so returns NULL.
        }
        break;
      }
    }
  }
  return ent;
}

void FdManager::Rename(const std::string &from, const std::string &to)
{
  AutoLock auto_lock(&FdManager::fd_manager_lock);
  fdent_map_t::iterator iter = fent.find(from);
  if(fent.end() != iter){
    // found
    S3FS_PRN_DBG("[from=%s][to=%s]", from.c_str(), to.c_str());
    FdEntity* ent = (*iter).second;
    fent.erase(iter);
    ent->SetPath(to);
    fent[to] = ent;
  }
}

bool FdManager::Close(FdEntity* ent)
{
  S3FS_PRN_DBG("[ent->file=%s][ent->fd=%d]", ent ? ent->GetPath() : "", ent ? ent->GetFd() : -1);

  if(!ent){
    return true;  // returns success
  }

  AutoLock auto_lock(&FdManager::fd_manager_lock);

  for(fdent_map_t::iterator iter = fent.begin(); iter != fent.end(); ++iter){
    if((*iter).second == ent){
      ent->Close();
      if(!ent->IsOpen()){
        // remove found entity from map.
        fent.erase(iter++);

        // check another key name for entity value to be on the safe side
        for(; iter != fent.end(); ){
          if((*iter).second == ent){
            fent.erase(iter++);
          }else{
            ++iter;
          }
        }
        delete ent;
      }
      return true;
    }
  }
  return false;
}

bool FdManager::ChangeEntityToTempPath(FdEntity* ent, const char* path)
{
  AutoLock auto_lock(&FdManager::fd_manager_lock);

  for(fdent_map_t::iterator iter = fent.begin(); iter != fent.end(); ){
    if((*iter).second == ent){
      fent.erase(iter++);

      string tmppath("");
      FdManager::MakeRandomTempPath(path, tmppath);
      fent[tmppath] = ent;
    }else{
      ++iter;
    }
  }
  return false;
}

void FdManager::CleanupCacheDir()
{
  S3FS_PRN_INFO("cache cleanup requested");

  if(!FdManager::IsCacheDir()){
    return;
  }

  AutoLock auto_lock_no_wait(&FdManager::cache_cleanup_lock, true);

  if(auto_lock_no_wait.isLockAcquired()){
    S3FS_PRN_INFO("cache cleanup started");
    CleanupCacheDirInternal("");
    S3FS_PRN_INFO("cache cleanup ended");
  }else{
    // wait for other thread to finish cache cleanup
    AutoLock auto_lock(&FdManager::cache_cleanup_lock);
  }
}

void FdManager::CleanupCacheDirInternal(const std::string &path)
{
  DIR*           dp;
  struct dirent* dent;
  std::string    abs_path = cache_dir + "/" + bucket + path;

  if(NULL == (dp = opendir(abs_path.c_str()))){
    S3FS_PRN_ERR("could not open cache dir(%s) - errno(%d)", abs_path.c_str(), errno);
    return;
  }

  for(dent = readdir(dp); dent; dent = readdir(dp)){
    if(0 == strcmp(dent->d_name, "..") || 0 == strcmp(dent->d_name, ".")){
      continue;
    }
    string   fullpath = abs_path;
    fullpath         += "/";
    fullpath         += dent->d_name;
    struct stat st;
    if(0 != lstat(fullpath.c_str(), &st)){
      S3FS_PRN_ERR("could not get stats of file(%s) - errno(%d)", fullpath.c_str(), errno);
      closedir(dp);
      return;
    }
    string next_path = path + "/" + dent->d_name;
    if(S_ISDIR(st.st_mode)){
      CleanupCacheDirInternal(next_path);
    }else{
      FdEntity* ent;
      if(NULL == (ent = FdManager::get()->Open(next_path.c_str(), NULL, -1, -1, false, true, true))){
        S3FS_PRN_DBG("skipping locked file: %s", next_path.c_str());
        continue;
      }

      if(ent->IsMultiOpened()){
        S3FS_PRN_DBG("skipping opened file: %s", next_path.c_str());
      }else{
        ent->CleanupCache();
        S3FS_PRN_DBG("cleaned up: %s", next_path.c_str());
      }
      Close(ent);
    }
  }
  closedir(dp);
}

bool FdManager::ReserveDiskSpace(size_t size)
{
  AutoLock auto_lock(&FdManager::reserved_diskspace_lock);
  if(IsSafeDiskSpace(NULL, size)){
    free_disk_space += size;
    return true;
  }
  return false;
}

void FdManager::FreeReservedDiskSpace(size_t size)
{
  AutoLock auto_lock(&FdManager::reserved_diskspace_lock);
  free_disk_space -= size;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
