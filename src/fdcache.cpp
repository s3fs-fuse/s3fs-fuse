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
#include <sys/time.h>
#include <sys/file.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <curl/curl.h>
#include <openssl/crypto.h>
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
#define MAX_OBJECT_SIZE     68719476735LL           // 64GB - 1L
#define MULTIPART_LOWLIMIT  (20 * 1024 * 1024)      // 20MB
#define	FDPAGE_SIZE	    (50 * 1024 * 1024)      // 50MB(parallel uploading is 5 parallel(default) * 10 MB)

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
    mkdirp(top_path + mydirname(path), 0777);
  }
  if(!path || '\0' == path[0]){
    sfile_path = top_path;
  }else{
    sfile_path = top_path + SAFESTRPTR(path);
  }
  return true;
}

bool CacheFileStat::DeleteCacheFileStat(const char* path)
{
  if(!path || '\0' == path[0]){
    return false;
  }
  // stat path
  string sfile_path;
  if(!CacheFileStat::MakeCacheFileStatPath(path, sfile_path, false)){
    DPRNINFO("failed to create cache stat file path(%s)", path);
    return false;
  }
  if(0 != unlink(sfile_path.c_str())){
    DPRNINFO("failed to delete file(%s): errno=%d", path, errno);
    return false;
  }
  return true;
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
    DPRN("failed to create cache stat file path(%s)", path.c_str());
    return false;
  }
  // open
  if(-1 == (fd = open(sfile_path.c_str(), O_CREAT|O_RDWR, 0600))){
    DPRNINFO("failed to open cache stat file path(%s) - errno(%d)", path.c_str(), errno);
    return false;
  }
  // lock
  if(-1 == flock(fd, LOCK_EX)){
    DPRN("failed to lock cache stat file(%s) - errno(%d)", path.c_str(), errno);
    close(fd);
    fd = -1;
    return false;
  }
  // seek top
  if(0 != lseek(fd, 0, SEEK_SET)){
    DPRN("failed to lseek cache stat file(%s) - errno(%d)", path.c_str(), errno);
    flock(fd, LOCK_UN);
    close(fd);
    fd = -1;
    return false;
  }
  DPRNINFO("file locked(%s - %s)", path.c_str(), sfile_path.c_str());

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
    DPRN("failed to unlock cache stat file(%s) - errno(%d)", path.c_str(), errno);
    return false;
  }
  DPRNINFO("file unlocked(%s)", path.c_str());

  if(-1 == close(fd)){
    DPRN("failed to close cache stat file(%s) - errno(%d)", path.c_str(), errno);
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

PageList::PageList(off_t size, bool is_init)
{
  Init(size, is_init);
}

PageList::~PageList()
{
  Clear();
}

off_t PageList::Size(void) const
{
  if(0 == pages.size()){
    return 0;
  }
  fdpage_list_t::const_reverse_iterator riter = pages.rbegin();
  return ((*riter)->offset + (*riter)->bytes);
}

int PageList::Resize(off_t size, bool is_init)
{
  off_t total = Size();

  if(0 == total){
    Init(size, is_init);

  }else if(total < size){
    off_t remain = size - total;           // remaining bytes
    fdpage_list_t::reverse_iterator riter = pages.rbegin();

    if((*riter)->bytes < FdManager::GetPageSize()){
      // resize last area
      remain         += (*riter)->bytes;    // remaining bytes(without last page)
      (*riter)->bytes = remain > static_cast<off_t>(FdManager::GetPageSize()) ? FdManager::GetPageSize() : static_cast<size_t>(remain); // reset page size
      remain         -= (*riter)->bytes;    // remaining bytes(after last page)
      (*riter)->init  = is_init;
    }

    // add new area
    for(off_t next = (*riter)->next(); 0 < remain; remain -= size, next += size){
      size         = remain > static_cast<off_t>(FdManager::GetPageSize()) ? static_cast<off_t>(FdManager::GetPageSize()) : remain;
      fdpage* page = new fdpage(next, size, is_init);
      pages.push_back(page);
    }

  }else if(total > size){
    for(fdpage_list_t::reverse_iterator riter = pages.rbegin(); riter != pages.rend(); riter++){
      if((*riter)->offset < size){
        (*riter)->bytes = static_cast<size_t>(size - (*riter)->offset);
        break;
      }
    }
  }
  return true;
}

void PageList::Clear(void)
{
  PageList::FreeList(pages);
}

int PageList::Init(off_t size, bool is_init)
{
  Clear();
  for(off_t total = 0; total < size; total += FdManager::GetPageSize()){
    size_t areasize = (total + FdManager::GetPageSize()) < size ? FdManager::GetPageSize() : static_cast<size_t>(size - total);
    fdpage* page    = new fdpage(total, areasize, is_init);
    pages.push_back(page);
  }
  return pages.size();
}

bool PageList::IsInit(off_t start, off_t size)
{
  off_t next = start + size;

  if(0 == pages.size()){
    return false;
  }
  // check end
  fdpage_list_t::reverse_iterator riter = pages.rbegin();
  if((*riter)->next() < next){
    // size is over end of page list.
    return false;
  }
  for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); iter++){
    if(next <= (*iter)->offset){
      break;
    }
    if((start <= (*iter)->offset && (*iter)->offset < next) || // start < iter-start < end
       (start <= (*iter)->end()  && (*iter)->end() < next)  || // start < iter-end < end
       ((*iter)->offset <= start && next <= (*iter)->end()) )  // iter-start < start < end < iter-end
    {
      if(!(*iter)->init){
        return false;
      }
    }
  }
  return true;
}

bool PageList::SetInit(off_t start, off_t size, bool is_init)
{
  // check size & resize
  if(Size() < (start + size)){
    Resize(start + size, false);
  }

  off_t next = start + size;
  for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); iter++){
    if((*iter)->end() < start){
      // out of area
      //   iter:start < iter:end < start < end
      continue;
    }else if(next <= (*iter)->offset){
      // out of area
      //   start < end < iter:start < iter:end
      break;
    }
    // area of target overlaps with iter area
    //   iter:start < start < iter:end < end
    //   iter:start < start < end < iter:end
    //   start < iter:start < iter:end < end
    //   start < iter:start < end < iter:end
    if((*iter)->init != is_init){
      (*iter)->init = is_init;
    }
  }
  return true;
}

bool PageList::FindUninitPage(off_t start, off_t& resstart, size_t& ressize)
{
  for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); iter++){
    if(start <= (*iter)->end()){
      if(!(*iter)->init){
        resstart = (*iter)->offset;
        ressize  = (*iter)->bytes;
        return true;
      }
    }
  }
  return false;
}

int PageList::GetUninitPages(fdpage_list_t& uninit_list, off_t start)
{
  for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); iter++){
    if(start <= (*iter)->end()){
      // after start pos
      if(!(*iter)->init){
        // found uninitialized area
        fdpage_list_t::reverse_iterator riter = uninit_list.rbegin();
        if(riter != uninit_list.rend() && (*riter)->next() == (*iter)->offset){
          // merge to before page
          (*riter)->bytes += (*iter)->bytes;
        }else{
          fdpage* page = new fdpage((*iter)->offset, (*iter)->bytes, false);
          uninit_list.push_back(page);
        }
      }
    }
  }
  return uninit_list.size();
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

    for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); iter++){
      ssall << "\n" << (*iter)->offset << ":" << (*iter)->bytes << ":" << ((*iter)->init ? "1" : "0");
    }

    string strall = ssall.str();
    if(0 >= pwrite(file.GetFd(), strall.c_str(), strall.length(), 0)){
      DPRN("failed to write stats(%d)", errno);
      return false;
    }

  }else{
    //
    // loading from file
    //
    struct stat st;
    memset(&st, 0, sizeof(struct stat));
    if(-1 == fstat(file.GetFd(), &st)){
      DPRN("fstat is failed. errno(%d)", errno);
      return false;
    }
    if(0 >= st.st_size){
      // nothing
      Init(0, false);
      return true;
    }
    char* ptmp;
    if(NULL == (ptmp = (char*)calloc(st.st_size + 1, sizeof(char)))){
      DPRNCRIT("could not allocate memory.");
      S3FS_FUSE_EXIT();
      return false;
    }
    // read from file
    if(0 >= pread(file.GetFd(), ptmp, st.st_size, 0)){
      DPRN("failed to read stats(%d)", errno);
      free(ptmp);
      return false;
    }
    string       oneline;
    stringstream ssall(ptmp);

    // init
    Clear();

    // load(size)
    if(!getline(ssall, oneline, '\n')){
      DPRN("failed to parse stats.");
      free(ptmp);
      return false;
    }
    off_t total = s3fs_strtoofft(oneline.c_str());

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
      // init
      if(!getline(ssparts, part, ':')){
        is_err = true;
        break;
      }
      bool is_init = (1 == s3fs_strtoofft(part.c_str()) ? true : false);
      // add new area
      SetInit(offset, size, is_init);
    }
    free(ptmp);
    if(is_err){
      DPRN("failed to parse stats.");
      Clear();
      return false;
    }

    // check size
    if(total != Size()){
      DPRN("different size(%jd - %jd).", (intmax_t)total, (intmax_t)Size());
      Clear();
      return false;
    }
  }
  return true;
}

void PageList::Dump(void)
{
  int cnt = 0;

  DPRNINFO("pages = {");
  for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); iter++, cnt++){
    DPRNINFO("  [%08d] -> {%014jd - %014zu : %s}", cnt, (intmax_t)((*iter)->offset), (*iter)->bytes, (*iter)->init ? "true" : "false");
  }
  DPRNINFO("}");
}

//------------------------------------------------
// FdEntity methods
//------------------------------------------------
FdEntity::FdEntity(const char* tpath, const char* cpath)
          : is_lock_init(false), path(SAFESTRPTR(tpath)), cachepath(SAFESTRPTR(cpath)), fd(-1), file(NULL), is_modify(false)
{
  try{
    pthread_mutex_init(&fdent_lock, NULL);
    is_lock_init = true;
  }catch(exception& e){
    DPRNCRIT("failed to init mutex");
  }
}

FdEntity::~FdEntity()
{
  Clear();

  if(is_lock_init){
    try{
      pthread_mutex_destroy(&fdent_lock);
    }catch(exception& e){
      DPRNCRIT("failed to destroy mutex");
    }
    is_lock_init = false;
  }
}

void FdEntity::Clear(void)
{
  AutoLock auto_lock(&fdent_lock);

  if(file){
    if(0 != cachepath.size()){
      CacheFileStat cfstat(path.c_str());
      if(!pagelist.Serialize(cfstat, true)){
        DPRN("failed to save cache stat file(%s).", path.c_str());
      }
    }
    fclose(file);
    file = NULL;
    fd   = -1;
  }
  pagelist.Init(0, false);
  refcnt    = 0;
  path      = "";
  cachepath = "";
  is_modify = false;
}

void FdEntity::Close(void)
{
  FPRNINFO("[path=%s][fd=%d][refcnt=%d]", path.c_str(), fd, (-1 != fd ? refcnt - 1 : refcnt));

  if(-1 != fd){
    AutoLock auto_lock(&fdent_lock);

    if(0 < refcnt){
      refcnt--;
    }
    if(0 == refcnt){
      if(0 != cachepath.size()){
        CacheFileStat cfstat(path.c_str());
        if(!pagelist.Serialize(cfstat, true)){
          DPRN("failed to save cache stat file(%s).", path.c_str());
        }
      }
      fclose(file);
      file = NULL;
      fd   = -1;
    }
  }
}

int FdEntity::Dup(void)
{
  FPRNINFO("[path=%s][fd=%d][refcnt=%d]", path.c_str(), fd, (-1 != fd ? refcnt + 1 : refcnt));

  if(-1 != fd){
    AutoLock auto_lock(&fdent_lock);
    refcnt++;
  }
  return fd;
}

int FdEntity::Open(off_t size, time_t time)
{
  bool already_opened = false;  // already opened fd
  bool is_csf_loaded  = false;  // loaded by cache stat file
  bool is_truncate    = false;  // need to truncate
  bool init_value     = false;  // value for pagelist

  FPRNINFO("[path=%s][fd=%d][size=%jd][time=%jd]", path.c_str(), fd, (intmax_t)size, (intmax_t)time);

  if(-1 != fd){
    // already opened, needs to increment refcnt.
    already_opened = true;

  }else{
    // open
    if(0 != cachepath.size()){
      // At first, open & flock stat file.
      {
        CacheFileStat cfstat(path.c_str());
        is_csf_loaded = pagelist.Serialize(cfstat, false);
      }

      // open cache file
      if(is_csf_loaded && -1 != (fd = open(cachepath.c_str(), O_RDWR))){
        // file exists
        struct stat st;
        memset(&st, 0, sizeof(struct stat));
        if(-1 == fstat(fd, &st)){
          DPRN("fstat is failed. errno(%d)", errno);
          fclose(file);
          file = NULL;
          fd   = -1;
          return (0 == errno ? -EIO : -errno);
        }
        if((-1 != size && size != pagelist.Size()) || st.st_size != pagelist.Size()){
          is_csf_loaded = false;   // reinitializing
          if(-1 == size){
            size = st.st_size;
          }else{
            is_truncate = true;
          }
        }else{
          // size OK! --> no initialize after this line.
        }

      }else{
        // file does not exist -> create & open
        if(-1 == (fd = open(cachepath.c_str(), O_CREAT|O_RDWR|O_TRUNC, 0600))){
          DPRN("failed to open file(%s). errno(%d)", cachepath.c_str(), errno);
          return (0 == errno ? -EIO : -errno);
        }
        if(-1 == size){
          size = 0;
        }else{
          is_truncate = true;
        }
        is_csf_loaded = false;
      }
      // make file pointer(for being same tmpfile)
      if(NULL == (file = fdopen(fd, "wb"))){
        DPRN("failed to get fileno(%s). errno(%d)", cachepath.c_str(), errno);
        close(fd);
        fd = -1;
        return (0 == errno ? -EIO : -errno);
      }

    }else{
      // open temporary file
      if(NULL == (file = tmpfile()) || -1 ==(fd = fileno(file))){
        DPRN("failed to open tmp file. err(%d)", errno);
        if(file){
          fclose(file);
          file = NULL;
        }
        return (0 == errno ? -EIO : -errno);
      }
      if(-1 == size){
        size = 0;
      }else{
        is_truncate = true;
      }
    }
  }

  // truncate
  if(is_truncate){
    if(0 != ftruncate(fd, size) || 0 != fsync(fd)){
      DPRN("ftruncate(%s) or fsync returned err(%d)", cachepath.c_str(), errno);
      fclose(file);
      file = NULL;
      fd   = -1;
      return (0 == errno ? -EIO : -errno);
    }
  }

  // set mtime
  if(-1 != time){
    if(0 != SetMtime(time)){
      DPRN("failed to set mtime. errno(%d)", errno);
      fclose(file);
      file = NULL;
      fd   = -1;
      return (0 == errno ? -EIO : -errno);
    }
  }

  // set internal data
  if(already_opened){
    Dup();
  }else{
    if(!is_csf_loaded){
      pagelist.Init(size, init_value);
    }
    refcnt    = 1;
    is_modify = false;
  }
  return 0;
}

int FdEntity::SetMtime(time_t time)
{
  FPRNINFO("[path=%s][fd=%d][time=%jd]", path.c_str(), fd, (intmax_t)time);

  if(-1 == time){
    return 0;
  }
  if(-1 != fd){
    AutoLock auto_lock(&fdent_lock);

    struct timeval tv[2];
    tv[0].tv_sec = time;
    tv[0].tv_usec= 0L;
    tv[1].tv_sec = tv[0].tv_sec;
    tv[1].tv_usec= 0L;
    if(-1 == futimes(fd, tv)){
      DPRN("futimes failed. errno(%d)", errno);
      return -errno;
    }
  }else if(0 < cachepath.size()){
    // not opened file yet.
    struct utimbuf n_mtime;
    n_mtime.modtime = time;
    n_mtime.actime  = time;
    if(-1 == utime(cachepath.c_str(), &n_mtime)){
      DPRNINFO("utime failed. errno(%d)", errno);
      return -errno;
    }
  }
  return 0;
}

bool FdEntity::GetSize(off_t& size)
{
  if(-1 == fd){
    return false;
  }
  AutoLock auto_lock(&fdent_lock);

  size = pagelist.Size();
  return true;
}

bool FdEntity::GetMtime(time_t& time)
{
  struct stat st;

  if(!GetStats(st)){
    return false;
  }
  time = st.st_mtime;
  return true;
}

bool FdEntity::GetStats(struct stat& st)
{
  if(-1 == fd){
    return false;
  }
  AutoLock auto_lock(&fdent_lock);

  memset(&st, 0, sizeof(struct stat)); 
  if(-1 == fstat(fd, &st)){
    DPRN("fstat failed. errno(%d)", errno);
    return false;
  }
  return true;
}

bool FdEntity::SetAllStatus(bool is_enable)
{
  FPRNINFO("[path=%s][fd=%d][%s]", path.c_str(), fd, is_enable ? "enable" : "disable");

  if(-1 == fd){
    return false;
  }
  AutoLock auto_lock(&fdent_lock);

  // get file size
  struct stat st;
  memset(&st, 0, sizeof(struct stat));
  if(-1 == fstat(fd, &st)){
    DPRN("fstat is failed. errno(%d)", errno);
    return false;
  }
  // Reinit
  pagelist.Init(st.st_size, is_enable);

  return true;
}

int FdEntity::Load(off_t start, off_t size)
{
  int result = 0;

  FPRNINFO("[path=%s][fd=%d][offset=%jd][size=%jd]", path.c_str(), fd, (intmax_t)start, (intmax_t)size);

  if(-1 == fd){
    return -EBADF;
  }
  AutoLock auto_lock(&fdent_lock);

  // check loaded area & load
  fdpage_list_t uninit_list;
  if(0 < pagelist.GetUninitPages(uninit_list, start)){
    for(fdpage_list_t::iterator iter = uninit_list.begin(); iter != uninit_list.end(); iter++){
      if(-1 != size && (start + size) <= (*iter)->offset){
        break;
      }
      // download
      if((*iter)->bytes >= MULTIPART_LOWLIMIT && !nomultipart){ // 20MB
        // parallel request
        // Additional time is needed for large files
        time_t backup = 0;
        if(120 > S3fsCurl::GetReadwriteTimeout()){
          backup = S3fsCurl::SetReadwriteTimeout(120);
        }
        result = S3fsCurl::ParallelGetObjectRequest(path.c_str(), fd, (*iter)->offset, (*iter)->bytes);
        if(0 != backup){
          S3fsCurl::SetReadwriteTimeout(backup);
        }
      }else{
        // single request
        S3fsCurl s3fscurl;
        result = s3fscurl.GetObjectRequest(path.c_str(), fd, (*iter)->offset, (*iter)->bytes);
      }
      if(0 != result){
        break;
      }

      // Set init flag
      pagelist.SetInit((*iter)->offset, static_cast<off_t>((*iter)->bytes), true);
    }
    PageList::FreeList(uninit_list);
  }
  return result;
}

bool FdEntity::LoadFull(off_t* size, bool force_load)
{
  int result;

  FPRNINFO("[path=%s][fd=%d]", path.c_str(), fd);

  if(-1 == fd){
    if(0 != Open()){
      return false;
    }
  }
  if(force_load){
    SetAllDisable();
  }
  //
  // TODO: possibly do background for delay loading
  //
  if(0 != (result = Load(0, pagelist.Size()))){
    DPRN("could not download, result(%d)", result);
    return false;
  }
  if(is_modify){
    AutoLock auto_lock(&fdent_lock);
    is_modify = false;
  }
  if(size){
    *size = pagelist.Size();
  }
  return true;
}

int FdEntity::RowFlush(const char* tpath, headers_t& meta, bool ow_sse_flg, bool force_sync)
{
  int result;

  FPRNINFO("[tpath=%s][path=%s][fd=%d]", SAFESTRPTR(tpath), path.c_str(), fd);

  if(-1 == fd){
    return -EBADF;
  }
  AutoLock auto_lock(&fdent_lock);

  if(!force_sync && !is_modify){
    // nothing to update.
    return 0;
  }

  /*
   * Make decision to do multi upload (or not) based upon file size
   * 
   * According to the AWS spec:
   *  - 1 to 10,000 parts are allowed
   *  - minimum size of parts is 5MB (expect for the last part)
   * 
   * For our application, we will define part size to be 10MB (10 * 2^20 Bytes)
   * maximum file size will be ~64 GB - 2 ** 36 
   * 
   * Initially uploads will be done serially
   * 
   * If file is > 20MB, then multipart will kick in
   */
  if(pagelist.Size() > MAX_OBJECT_SIZE){ // 64GB - 1
    // close f ?
    return -ENOTSUP;
  }

  // seek to head of file.
  if(0 != lseek(fd, 0, SEEK_SET)){
    DPRN("lseek error(%d)", errno);
    return -errno;
  }

  if(pagelist.Size() >= MULTIPART_LOWLIMIT && !nomultipart){ // 20MB
    // Additional time is needed for large files
    time_t backup = 0;
    if(120 > S3fsCurl::GetReadwriteTimeout()){
      backup = S3fsCurl::SetReadwriteTimeout(120);
    }
    result = S3fsCurl::ParallelMultipartUploadRequest(tpath ? tpath : path.c_str(), meta, fd, ow_sse_flg);
    if(0 != backup){
      S3fsCurl::SetReadwriteTimeout(backup);
    }
  }else{
    S3fsCurl s3fscurl(true);
    result = s3fscurl.PutRequest(tpath ? tpath : path.c_str(), meta, fd, ow_sse_flg);
  }

  // seek to head of file.
  if(0 == result && 0 != lseek(fd, 0, SEEK_SET)){
    DPRN("lseek error(%d)", errno);
    return -errno;
  }

  if(0 == result){
    is_modify = false;
  }
  return result;
}

ssize_t FdEntity::Read(char* bytes, off_t start, size_t size, bool force_load)
{
  int     result;
  ssize_t rsize;

  FPRNINFO("[path=%s][fd=%d][offset=%jd][size=%zu]", path.c_str(), fd, (intmax_t)start, size);

  if(-1 == fd){
    return -EBADF;
  }
  if(force_load){
    AutoLock auto_lock(&fdent_lock);
    pagelist.SetInit(start, static_cast<off_t>(size), false);
  }
  // Loading
  if(0 != (result = Load(start, size))){
    DPRN("could not download. start(%jd), size(%zu), errno(%d)", (intmax_t)start, size, result);
    return -EIO;
  }
  // Reading
  {
    AutoLock auto_lock(&fdent_lock);

    if(-1 == (rsize = pread(fd, bytes, size, start))){
      DPRN("pread failed. errno(%d)", errno);
      return -errno;
    }
  }
  return rsize;
}

ssize_t FdEntity::Write(const char* bytes, off_t start, size_t size)
{
  int     result;
  ssize_t wsize;

  FPRNINFO("[path=%s][fd=%d][offset=%jd][size=%zu]", path.c_str(), fd, (intmax_t)start, size);

  if(-1 == fd){
    return -EBADF;
  }

  // Load unitialized area which starts from 0 to (start + size) before writing.
  if(0 != (result = Load(0, start))){
    DPRN("failed to load uninitialized area before writing(errno=%d)", result);
    return static_cast<ssize_t>(result);
  }

  // Writing
  {
    AutoLock auto_lock(&fdent_lock);

    if(-1 == (wsize = pwrite(fd, bytes, size, start))){
      DPRN("pwrite failed. errno(%d)", errno);
      return -errno;
    }
    if(!is_modify){
      is_modify = true;
    }
    if(0 < wsize){
      pagelist.SetInit(start, static_cast<off_t>(wsize), true);
    }
  }
  return wsize;
}

//------------------------------------------------
// FdManager class valiable
//------------------------------------------------
FdManager       FdManager::singleton;
pthread_mutex_t FdManager::fd_manager_lock;
bool            FdManager::is_lock_init(false);
string          FdManager::cache_dir("");
size_t          FdManager::page_size(FDPAGE_SIZE);

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

size_t FdManager::SetPageSize(size_t size)
{
  // If already has entries, this function is failed.
  if(0 < FdManager::get()->fent.size()){
    return -1;
  }
  size_t old = FdManager::page_size;
  FdManager::page_size = size;
  return old;
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
  FPRNINFO("[path=%s]", SAFESTRPTR(path));

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
    DPRNINFO("failed to delete file(%s): errno=%d", path, errno);
    result = -errno;
  }
  if(!CacheFileStat::DeleteCacheFileStat(path)){
    DPRNINFO("failed to delete stat file(%s): errno=%d", path, errno);
    if(0 != errno){
      result = -errno;
    }else{
      result = -EIO;
    }
  }
  return result;
}

bool FdManager::MakeCachePath(const char* path, string& cache_path, bool is_create_dir)
{
  if(0 == FdManager::cache_dir.size()){
    cache_path = "";
    return true;
  }
  string resolved_path(FdManager::cache_dir + "/" + bucket);
  if(is_create_dir){
    mkdirp(resolved_path + mydirname(path), 0777);
  }
  if(!path || '\0' == path[0]){
    cache_path = resolved_path;
  }else{
    cache_path = resolved_path + SAFESTRPTR(path);
  }
  return true;
}

//------------------------------------------------
// FdManager methods
//------------------------------------------------
FdManager::FdManager()
{
  if(this == FdManager::get()){
    try{
      pthread_mutex_init(&FdManager::fd_manager_lock, NULL);
      FdManager::is_lock_init = true;
    }catch(exception& e){
      FdManager::is_lock_init = false;
      DPRNCRIT("failed to init mutex");
    }
  }else{
    assert(false);
  }
}

FdManager::~FdManager()
{
  if(this == FdManager::get()){
    for(fdent_map_t::iterator iter = fent.begin(); fent.end() != iter; iter++){
      FdEntity* ent = (*iter).second;
      delete ent;
    }
    fent.clear();

    if(FdManager::is_lock_init){
      try{
        pthread_mutex_destroy(&FdManager::fd_manager_lock);
      }catch(exception& e){
        DPRNCRIT("failed to init mutex");
      }
      FdManager::is_lock_init = false;
    }
  }else{
    assert(false);
  }
}

FdEntity* FdManager::GetFdEntity(const char* path)
{
  FPRNINFO("[path=%s]", SAFESTRPTR(path));

  if(!path || '\0' == path[0]){
    return NULL;
  }
  AutoLock auto_lock(&FdManager::fd_manager_lock);

  fdent_map_t::iterator iter = fent.find(string(path));
  if(fent.end() == iter){
    return NULL;
  }
  return (*iter).second;
}

FdEntity* FdManager::Open(const char* path, off_t size, time_t time, bool force_tmpfile, bool is_create)
{
  FdEntity* ent;

  FPRNINFO("[path=%s][size=%jd][time=%jd]", SAFESTRPTR(path), (intmax_t)size, (intmax_t)time);

  if(!path || '\0' == path[0]){
    return NULL;
  }

  AutoLock auto_lock(&FdManager::fd_manager_lock);

  fdent_map_t::iterator iter = fent.find(string(path));
  if(fent.end() != iter){
    // found
    ent = (*iter).second;

  }else if(is_create){
    // not found
    string cache_path = "";
    if(!force_tmpfile && !FdManager::MakeCachePath(path, cache_path, true)){
      DPRN("failed to make cache path for object(%s).", path);
      return NULL;
    }
    // make new obj
    ent = new FdEntity(path, cache_path.c_str());
    fent[string(path)] = ent;

  }else{
    return NULL;
  }

  // open
  if(-1 == ent->Open(size, time)){
    return NULL;
  }
  return ent;
}

bool FdManager::Close(FdEntity* ent)
{
  FPRNINFO("[ent->file=%s][ent->fd=%d]", ent ? ent->GetPath() : "", ent ? ent->GetFd() : -1);

  AutoLock auto_lock(&FdManager::fd_manager_lock);

  for(fdent_map_t::iterator iter = fent.begin(); iter != fent.end(); iter++){
    if((*iter).second == ent){
      ent->Close();
      if(!ent->IsOpen()){
        delete (*iter).second;
        fent.erase(iter);
        return true;
      }
    }
  }
  return false;
}

