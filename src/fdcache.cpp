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

#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <cerrno>
#include <cstring>
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

bool CacheFileStat::CheckCacheFileStatTopDir()
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
bool CacheFileStat::DeleteCacheFileStatDirectory()
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

bool CacheFileStat::RenameCacheFileStat(const char* oldpath, const char* newpath)
{
  if(!oldpath || '\0' == oldpath[0] || !newpath || '\0' == newpath[0]){
    return false;
  }

  // stat path
  string old_filestat;
  string new_filestat;
  if(!CacheFileStat::MakeCacheFileStatPath(oldpath, old_filestat, false) || !CacheFileStat::MakeCacheFileStatPath(newpath, new_filestat, false)){
    return false;
  }

  // check new stat path
  struct stat st;
  if(0 == stat(new_filestat.c_str(), &st)){
    // new stat path is existed, then unlink it.
    if(-1 == unlink(new_filestat.c_str())){
      S3FS_PRN_ERR("failed to unlink new cache file stat path(%s) by errno(%d).", new_filestat.c_str(), errno);
      return false;
    }
  }

  // check old stat path
  if(0 != stat(old_filestat.c_str(), &st)){
    // old stat path is not existed, then nothing to do any more.
    return true;
  }

  // link and unlink
  if(-1 == link(old_filestat.c_str(), new_filestat.c_str())){
    S3FS_PRN_ERR("failed to link old cache file stat path(%s) to new cache file stat path(%s) by errno(%d).", old_filestat.c_str(), new_filestat.c_str(), errno);
    return false;
  }
  if(-1 == unlink(old_filestat.c_str())){
    S3FS_PRN_ERR("failed to unlink old cache file stat path(%s) by errno(%d).", old_filestat.c_str(), errno);
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

bool CacheFileStat::Open()
{
  if(path.empty()){
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

bool CacheFileStat::Release()
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
  list.clear();
}

PageList::PageList(off_t size, bool is_loaded, bool is_modified)
{
  Init(size, is_loaded, is_modified);
}

PageList::PageList(const PageList& other)
{
  for(fdpage_list_t::const_iterator iter = other.pages.begin(); iter != other.pages.end(); ++iter){
    pages.push_back(*iter);
  }
}

PageList::~PageList()
{
  Clear();
}

void PageList::Clear()
{
  PageList::FreeList(pages);
}

bool PageList::Init(off_t size, bool is_loaded, bool is_modified)
{
  Clear();
  fdpage page(0, size, is_loaded, is_modified);
  pages.push_back(page);
  return true;
}

off_t PageList::Size() const
{
  if(pages.empty()){
    return 0;
  }
  fdpage_list_t::const_reverse_iterator riter = pages.rbegin();
  return riter->next();
}

bool PageList::Compress(bool force_modified)
{
  bool is_first         = true;
  bool is_last_loaded   = false;
  bool is_last_modified = false;

  for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); ){
    if(is_first){
      is_first         = false;
      is_last_loaded   = force_modified ? true : iter->loaded;
      is_last_modified = iter->modified;
      ++iter;
    }else{
      if(is_last_modified == iter->modified){
        if(force_modified || is_last_loaded == iter->loaded){
          fdpage_list_t::iterator biter = iter;
          --biter;
          biter->bytes += iter->bytes;
          iter = pages.erase(iter);
        }else{
          is_last_loaded   = iter->loaded;
          is_last_modified = iter->modified;
          ++iter;
        }
      }else{
        is_last_loaded   = force_modified ? true : iter->loaded;
        is_last_modified = iter->modified;
        ++iter;
      }
    }
  }
  return true;
}

bool PageList::Parse(off_t new_pos)
{
  for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); ++iter){
    if(new_pos == iter->offset){
      // nothing to do
      return true;
    }else if(iter->offset < new_pos && new_pos < iter->next()){
      fdpage page(iter->offset, new_pos - iter->offset, iter->loaded, false);
      iter->bytes -= (new_pos - iter->offset);
      iter->offset = new_pos;
      pages.insert(iter, page);
      return true;
    }
  }
  return false;
}

bool PageList::Resize(off_t size, bool is_loaded, bool is_modified)
{
  off_t total = Size();

  if(0 == total){
    Init(size, is_loaded, is_modified);

  }else if(total < size){
    // add new area
    fdpage page(total, (size - total), is_loaded, is_modified);
    pages.push_back(page);

  }else if(size < total){
    // cut area
    for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); ){
      if(iter->next() <= size){
        ++iter;
      }else{
        if(size <= iter->offset){
          iter = pages.erase(iter);
        }else{
          iter->bytes = size - iter->offset;
        }
      }
    }
  }else{    // total == size
    // nothing to do
  }
  // compress area
  return Compress();
}

bool PageList::IsPageLoaded(off_t start, off_t size) const
{
  for(fdpage_list_t::const_iterator iter = pages.begin(); iter != pages.end(); ++iter){
    if(iter->end() < start){
      continue;
    }
    if(!iter->loaded){
      return false;
    }
    if(0 != size && start + size <= iter->next()){
      break;
    }
  }
  return true;
}

bool PageList::SetPageLoadedStatus(off_t start, off_t size, PageList::page_status pstatus, bool is_compress)
{
  off_t now_size    = Size();
  bool  is_loaded   = (PAGE_LOAD_MODIFIED == pstatus || PAGE_LOADED == pstatus);
  bool  is_modified = (PAGE_LOAD_MODIFIED == pstatus || PAGE_MODIFIED == pstatus);

  if(now_size <= start){
    if(now_size < start){
      // add
      Resize(start, false, is_modified);   // set modified flag from now end pos to specified start pos.
    }
    Resize(start + size, is_loaded, is_modified);

  }else if(now_size <= start + size){
    // cut
    Resize(start, false, false);            // not changed loaded/modified flags in existing area.
    // add
    Resize(start + size, is_loaded, is_modified);

  }else{
    // start-size are inner pages area
    // parse "start", and "start + size" position
    Parse(start);
    Parse(start + size);

    // set loaded flag
    for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); ++iter){
      if(iter->end() < start){
        continue;
      }else if(start + size <= iter->offset){
        break;
      }else{
        iter->loaded   = is_loaded;
        iter->modified = is_modified;
      }
    }
  }
  // compress area
  return (is_compress ? Compress() : true);
}

bool PageList::FindUnloadedPage(off_t start, off_t& resstart, off_t& ressize) const
{
  for(fdpage_list_t::const_iterator iter = pages.begin(); iter != pages.end(); ++iter){
    if(start <= iter->end()){
      if(!iter->loaded && !iter->modified){     // Do not load unloaded and modified areas
        resstart = iter->offset;
        ressize  = iter->bytes;
        return true;
      }
    }
  }
  return false;
}

off_t PageList::GetTotalUnloadedPageSize(off_t start, off_t size) const
{
  off_t restsize = 0;
  off_t next     = start + size;
  for(fdpage_list_t::const_iterator iter = pages.begin(); iter != pages.end(); ++iter){
    if(iter->next() <= start){
      continue;
    }
    if(next <= iter->offset){
      break;
    }
    if(iter->loaded || iter->modified){
      continue;
    }
    off_t tmpsize;
    if(iter->offset <= start){
      if(iter->next() <= next){
        tmpsize = (iter->next() - start);
      }else{
        tmpsize = next - start;                         // = size
      }
    }else{
      if(iter->next() <= next){
        tmpsize = iter->next() - iter->offset;   // = iter->bytes
      }else{
        tmpsize = next - iter->offset;
      }
    }
    restsize += tmpsize;
  }
  return restsize;
}

int PageList::GetUnloadedPages(fdpage_list_t& unloaded_list, off_t start, off_t size) const
{
  // If size is 0, it means loading to end.
  if(0 == size){
    if(start < Size()){
      size = Size() - start;
    }
  }
  off_t next = start + size;

  for(fdpage_list_t::const_iterator iter = pages.begin(); iter != pages.end(); ++iter){
    if(iter->next() <= start){
      continue;
    }
    if(next <= iter->offset){
      break;
    }
    if(iter->loaded || iter->modified){
      continue; // already loaded or modified
    }

    // page area
    off_t page_start = max(iter->offset, start);
    off_t page_next  = min(iter->next(), next);
    off_t page_size  = page_next - page_start;

    // add list
    fdpage_list_t::reverse_iterator riter = unloaded_list.rbegin();
    if(riter != unloaded_list.rend() && riter->next() == page_start){
      // merge to before page
      riter->bytes += page_size;
    }else{
      fdpage page(page_start, page_size, false, false);
      unloaded_list.push_back(page);
    }
  }
  return unloaded_list.size();
}

// [NOTE]
// This method is called in advance when mixing POST and COPY in multi-part upload.
// The minimum size of each part must be 5 MB, and the data area below this must be
// downloaded from S3.
// This method checks the current PageList status and returns the area that needs
// to be downloaded so that each part is at least 5 MB.
//
bool PageList::GetLoadPageListForMultipartUpload(fdpage_list_t& dlpages)
{
  // compress before this processing
  if(!Compress()){
    return false;
  }

  bool  is_prev_modified_page = false;
  off_t accumulated_bytes     = 0;
  off_t last_modified_bytes   = 0;

  for(fdpage_list_t::const_iterator iter = pages.begin(); iter != pages.end(); ++iter){
    if(iter->modified){
      // this is modified page
      if(is_prev_modified_page){
        // in case of continuous modified page
        accumulated_bytes += iter->bytes;

      }else{
        // previous page is unmodified page
        // check unmodified page bytes is over minimum size(5MB)
        if(static_cast<const off_t>(MIN_MULTIPART_SIZE) <= accumulated_bytes){
          // over minimum size
          accumulated_bytes = iter->bytes;                          // reset accumulated size

        }else{
          // less than minimum size(5MB)
          // the previous unmodified page needs to load, if it is not loaded.
          // and that page will be included in consecutive modified page.
          PageList::RawGetUnloadPageList(dlpages, (iter->offset - accumulated_bytes), accumulated_bytes);

          accumulated_bytes  += last_modified_bytes + iter->bytes;  // this page size and last modified page size are accumulated
          last_modified_bytes = 0;
        }
        is_prev_modified_page = true;
      }

    }else{
      // this is unmodified page
      if(!is_prev_modified_page){
        // in case of continuous unmodified page
        accumulated_bytes += iter->bytes;

      }else{
        // previous page is modified page
        // check modified page bytes is over minimum size(5MB)
        if(static_cast<const off_t>(MIN_MULTIPART_SIZE) <= accumulated_bytes){
          // over minimum size
          last_modified_bytes   = accumulated_bytes;    // backup last modified page size
          accumulated_bytes     = iter->bytes;          // set new accumulated size(this page size)
          is_prev_modified_page = false;

        }else{
          // less than minimum size(5MB)
          // this unmodified page needs to load, if it is not loaded.
          // and this page will be included in consecutive modified page.
          if((static_cast<const off_t>(MIN_MULTIPART_SIZE) - accumulated_bytes) <= iter->bytes){
            // Split the missing size from this page size for just before modified page.
            if(!iter->loaded){
              // because this page is not loaded
              fdpage    dlpage(iter->offset, (iter->bytes - (static_cast<const off_t>(MIN_MULTIPART_SIZE) - accumulated_bytes)));   // don't care for loaded/modified flag
              dlpages.push_back(dlpage);
            }
            last_modified_bytes   = static_cast<const off_t>(MIN_MULTIPART_SIZE);                                       // backup last modified page size
            accumulated_bytes     = iter->bytes - (static_cast<const off_t>(MIN_MULTIPART_SIZE) - accumulated_bytes);   // set rest bytes to accumulated size
            is_prev_modified_page = false;

          }else{
            // assign all this page sizes to just before modified page.
            // but still it is not enough for the minimum size.
            if(!iter->loaded){
              // because this page is not loaded
              fdpage    dlpage(iter->offset, iter->bytes);  // don't care for loaded/modified flag
              dlpages.push_back(dlpage);
            }
            accumulated_bytes += iter->bytes;               // add all bytes to accumulated size
          }
        }
      }
    }
  }

  // compress dlpages
  bool is_first = true;
  for(fdpage_list_t::iterator dliter = dlpages.begin(); dliter != dlpages.end(); ){
    if(is_first){
      is_first = false;
      ++dliter;
      continue;
    }
    fdpage_list_t::iterator biter = dliter;
    --biter;
    if((biter->offset + biter->bytes) == dliter->offset){
      biter->bytes += dliter->bytes;
      dliter = dlpages.erase(dliter);
    }else{
      ++dliter;
    }
  }

  return true;
}

// [NOTE]
// This static method assumes that it is called only from GetLoadPageListForMultipartUpload.
// If you want to exclusive control, please do with GetLoadPageListForMultipartUpload,
// not with this method.
//
bool PageList::RawGetUnloadPageList(fdpage_list_t& dlpages, off_t offset, off_t size)
{
  for(fdpage_list_t::const_iterator iter = pages.begin(); iter != pages.end(); ++iter){
    if((iter->offset + iter->bytes) <= offset){
      continue;
    }else if((offset + size) <= iter->offset){
      break;
    }else{
      if(!iter->loaded && !iter->modified){
        fdpage    dlpage(iter->offset, iter->bytes);       // don't care for loaded/modified flag
        dlpages.push_back(dlpage);
      }
    }
  }
  return true;
}

bool PageList::GetMultipartSizeList(fdpage_list_t& mplist, off_t partsize) const
{
  if(!mplist.empty()){
    return false;
  }

  // temporary page list
  PageList tmpPageObj(*this);
  if(!tmpPageObj.Compress(true)){   // compress by modified flag
    return false;
  }

  // [NOTE]
  // Set the modified flag in page list to the minimum size.
  // This process needs to match the GetLoadPageListForMultipartUpload method exactly.
  //
  // [FIXME]
  // Make the common processing of GetLoadPageListForMultipartUpload and this method
  // to one method.
  //
  bool  is_first              = true;
  bool  is_prev_modified_page = false;
  off_t accumulated_bytes     = 0;
  off_t last_modified_bytes   = 0;
  fdpage_list_t::iterator     iter;

  for(iter = tmpPageObj.pages.begin(); iter != tmpPageObj.pages.end(); ++iter){
    if(is_first){
      is_prev_modified_page = iter->modified;
      is_first              = false;
    }
    if(iter->modified){
      // this is modified page
      if(is_prev_modified_page){
        // in case of continuous modified page
        accumulated_bytes += iter->bytes;

      }else{
        // previous page is unmodified page
        // check unmodified page bytes is over minimum size(5MB)
        if(static_cast<const off_t>(MIN_MULTIPART_SIZE) <= accumulated_bytes){
          // over minimum size
          accumulated_bytes = iter->bytes;                          // reset accumulated size

        }else{
          // less than minimum size(5MB)
          // the previous unmodified page is set modified flag.
          fdpage_list_t::iterator biter = iter;
          --biter;
          biter->loaded       = true;
          biter->modified     = true;
          accumulated_bytes  += last_modified_bytes + iter->bytes;  // this page size and last modified page size are accumulated
          last_modified_bytes = 0;
        }
        is_prev_modified_page = true;
      }

    }else{
      // this is unmodified page
      if(!is_prev_modified_page){
        // in case of continuous unmodified page
        accumulated_bytes += iter->bytes;

      }else{
        // previous page is modified page
        // check modified page bytes is over minimum size(5MB)
        if(static_cast<const off_t>(MIN_MULTIPART_SIZE) <= accumulated_bytes){
          // over minimum size
          last_modified_bytes   = accumulated_bytes;    // backup last modified page size
          accumulated_bytes     = iter->bytes;          // set new accumulated size(this page size)
          is_prev_modified_page = false;

        }else{
          // less than minimum size(5MB)
          // this unmodified page is set modified flag.
          if((static_cast<const off_t>(MIN_MULTIPART_SIZE) - accumulated_bytes) <= iter->bytes){
            // Split the missing size from this page size for just before modified page.
            fdpage newpage(iter->offset, (static_cast<const off_t>(MIN_MULTIPART_SIZE) - accumulated_bytes), true, true);
            iter->bytes  -= (static_cast<const off_t>(MIN_MULTIPART_SIZE) - accumulated_bytes);
            iter->offset += (static_cast<const off_t>(MIN_MULTIPART_SIZE) - accumulated_bytes);
            tmpPageObj.pages.insert(iter, newpage);

            last_modified_bytes   = static_cast<const off_t>(MIN_MULTIPART_SIZE);   // backup last modified page size
            accumulated_bytes     = iter->bytes;                                    // set rest bytes to accumulated size
            is_prev_modified_page = false;

          }else{
            // assign all this page sizes to just before modified page.
            // but still it is not enough for the minimum size.
            accumulated_bytes += iter->bytes;           // add all bytes to accumulated size
          }
        }
      }
    }
  }

  // recompress
  if(!tmpPageObj.Compress(true)){   // compress by modified flag
    return false;
  }

  // normalization for uploading parts
  for(iter = tmpPageObj.pages.begin(); iter != tmpPageObj.pages.end(); ++iter){
    off_t  start    = iter->offset;
    off_t remains   = iter->bytes;

    while(0 < remains){
      off_t     onesize;
      if(iter->modified){
        // Uploading parts, this page must be 5MB - partsize
        onesize = std::min(remains, partsize);
      }else{
        // Not uploading parts, this page must be 5MB - 5GB
        onesize = std::min(remains, static_cast<off_t>(FIVE_GB));
      }
      fdpage    page(start, onesize, iter->loaded, iter->modified);
      mplist.push_back(page);

      start     += onesize;
      remains   -= onesize;
    }
  }
  return true;
}

bool PageList::IsModified() const
{
  for(fdpage_list_t::const_iterator iter = pages.begin(); iter != pages.end(); ++iter){
    if(iter->modified){
      return true;
    }
  }
  return false;
}

bool PageList::ClearAllModified()
{
  for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); ++iter){
    if(iter->modified){
      iter->modified = false;
    }
  }
  return Compress();
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
    ostringstream ssall;
    ssall << Size();

    for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); ++iter){
      ssall << "\n" << iter->offset << ":" << iter->bytes << ":" << (iter->loaded ? "1" : "0") << ":" << (iter->modified ? "1" : "0");
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
      Init(0, false, false);
      return true;
    }
    char* ptmp = new char[st.st_size + 1];
    ptmp[st.st_size] = '\0';
    // read from file
    if(0 >= pread(file.GetFd(), ptmp, st.st_size, 0)){
      S3FS_PRN_ERR("failed to read stats(%d)", errno);
      delete[] ptmp;
      return false;
    }
    string        oneline;
    istringstream ssall(ptmp);

    // loaded
    Clear();

    // load(size)
    if(!getline(ssall, oneline, '\n')){
      S3FS_PRN_ERR("failed to parse stats.");
      delete[] ptmp;
      return false;
    }
    off_t total = s3fs_strtoofft(oneline.c_str());

    // load each part
    bool is_err = false;
    while(getline(ssall, oneline, '\n')){
      string        part;
      istringstream ssparts(oneline);
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
      bool is_modified;
      if(!getline(ssparts, part, ':')){
        is_modified = false;        // old version does not have this part.
      }else{
        is_modified = (1 == s3fs_strtoofft(part.c_str()) ? true : false);
      }
      // add new area
      PageList::page_status pstatus = 
        ( is_loaded && is_modified  ? PageList::PAGE_LOAD_MODIFIED : 
          !is_loaded && is_modified ? PageList::PAGE_MODIFIED      : 
          is_loaded && !is_modified ? PageList::PAGE_LOADED        : PageList::PAGE_NOT_LOAD_MODIFIED );

      SetPageLoadedStatus(offset, size, pstatus);
    }
    delete[] ptmp;
    if(is_err){
      S3FS_PRN_ERR("failed to parse stats.");
      Clear();
      return false;
    }

    // check size
    if(total != Size()){
      S3FS_PRN_ERR("different size(%lld - %lld).", static_cast<long long int>(total), static_cast<long long int>(Size()));
      Clear();
      return false;
    }
  }
  return true;
}

void PageList::Dump()
{
  int cnt = 0;

  S3FS_PRN_DBG("pages = {");
  for(fdpage_list_t::iterator iter = pages.begin(); iter != pages.end(); ++iter, ++cnt){
    S3FS_PRN_DBG("  [%08d] -> {%014lld - %014lld : %s / %s}", cnt, static_cast<long long int>(iter->offset), static_cast<long long int>(iter->bytes), iter->loaded ? "loaded" : "unloaded", iter->modified ? "modified" : "not modified");
  }
  S3FS_PRN_DBG("}");
}

//------------------------------------------------
// FdEntity class methods
//------------------------------------------------
bool FdEntity::mixmultipart = true;

bool FdEntity::SetNoMixMultipart()
{
  bool old = mixmultipart;
  mixmultipart = false;
  return old;
}

int FdEntity::FillFile(int fd, unsigned char byte, off_t size, off_t start)
{
  unsigned char bytes[1024 * 32];         // 32kb
  memset(bytes, byte, min(static_cast<off_t>(sizeof(bytes)), size));

  for(off_t total = 0, onewrote = 0; total < size; total += onewrote){
    if(-1 == (onewrote = pwrite(fd, bytes, min(static_cast<off_t>(sizeof(bytes)), size - total), start + total))){
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
        : is_lock_init(false), refcnt(0), path(SAFESTRPTR(tpath)),
          fd(-1), pfile(NULL), size_orgmeta(0), upload_id(""), mp_start(0), mp_size(0),
          cachepath(SAFESTRPTR(cpath)), mirrorpath("")
{
  try{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
    pthread_mutex_init(&fdent_lock, &attr);
    pthread_mutex_init(&fdent_data_lock, &attr);
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
      pthread_mutex_destroy(&fdent_data_lock);
      pthread_mutex_destroy(&fdent_lock);
    }catch(exception& e){
      S3FS_PRN_CRIT("failed to destroy mutex");
    }
    is_lock_init = false;
  }
}

void FdEntity::Clear()
{
  AutoLock auto_lock(&fdent_lock);
  AutoLock auto_data_lock(&fdent_data_lock);

  if(-1 != fd){
    if(!cachepath.empty()){
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
  pagelist.Init(0, false, false);
  refcnt        = 0;
  path          = "";
  cachepath     = "";
}

void FdEntity::Close()
{
  AutoLock auto_lock(&fdent_lock);

  S3FS_PRN_DBG("[path=%s][fd=%d][refcnt=%d]", path.c_str(), fd, (-1 != fd ? refcnt - 1 : refcnt));

  if(-1 != fd){

    if(0 < refcnt){
      refcnt--;
    }else{
      S3FS_PRN_EXIT("reference count underflow");
      abort();
    }
    if(0 == refcnt){
      AutoLock auto_data_lock(&fdent_data_lock);
      if(!cachepath.empty()){
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

int FdEntity::Dup(bool lock_already_held)
{
  AutoLock auto_lock(&fdent_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);

  S3FS_PRN_DBG("[path=%s][fd=%d][refcnt=%d]", path.c_str(), fd, (-1 != fd ? refcnt + 1 : refcnt));

  if(-1 != fd){
    refcnt++;
  }
  return fd;
}

//
// Open mirror file which is linked cache file.
//
int FdEntity::OpenMirrorFile()
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

int FdEntity::Open(headers_t* pmeta, off_t size, time_t time, bool no_fd_lock_wait)
{
  AutoLock auto_lock(&fdent_lock, no_fd_lock_wait ? AutoLock::NO_WAIT : AutoLock::NONE);

  S3FS_PRN_DBG("[path=%s][fd=%d][size=%lld][time=%lld]", path.c_str(), fd, static_cast<long long>(size), static_cast<long long>(time));

  if (!auto_lock.isLockAcquired()) {
    // had to wait for fd lock, return
    return -EIO;
  }

  S3FS_PRN_DBG("[path=%s][fd=%d][size=%lld][time=%lld]", path.c_str(), fd, static_cast<long long>(size), static_cast<long long>(time));

  AutoLock auto_data_lock(&fdent_data_lock);
  if(-1 != fd){
    // already opened, needs to increment refcnt.
    Dup(/*lock_already_held=*/ true);

    // check only file size(do not need to save cfs and time.
    if(0 <= size && pagelist.Size() != size){
      // truncate temporary file size
      if(-1 == ftruncate(fd, size)){
        S3FS_PRN_ERR("failed to truncate temporary file(%d) by errno(%d).", fd, errno);
        if(0 < refcnt){
          refcnt--;
        }
        return -EIO;
      }
      // resize page list
      if(!pagelist.Resize(size, false, false)){
        S3FS_PRN_ERR("failed to truncate temporary file information(%d).", fd);
        if(0 < refcnt){
          refcnt--;
        }
        return -EIO;
      }
    }
    // set original headers and set size.
    off_t new_size = (0 <= size ? size : size_orgmeta);
    if(pmeta){
      orgmeta  = *pmeta;
      new_size = get_size(orgmeta);
    }
    if(new_size < size_orgmeta){
      size_orgmeta = new_size;
    }
    return 0;
  }

  bool  need_save_csf = false;  // need to save(reset) cache stat file
  bool  is_truncate   = false;  // need to truncate

  if(!cachepath.empty()){
    // using cache

    struct stat st;
    if(stat(cachepath.c_str(), &st) == 0){
      if(st.st_mtime < time){
        S3FS_PRN_DBG("cache file stale, removing: %s", cachepath.c_str());
        if(unlink(cachepath.c_str()) != 0){
          return (0 == errno ? -EIO : -errno);
        }
      }
    }

    // open cache and cache stat file, load page info.
    CacheFileStat cfstat(path.c_str());

    // try to open cache file
    if(-1 != (fd = open(cachepath.c_str(), O_RDWR)) && pagelist.Serialize(cfstat, false)){
      // succeed to open cache file and to load stats data
      memset(&st, 0, sizeof(struct stat));
      if(-1 == fstat(fd, &st)){
        S3FS_PRN_ERR("fstat is failed. errno(%d)", errno);
        fd = -1;
        return (0 == errno ? -EIO : -errno);
      }
      // check size, st_size, loading stat file
      if(-1 == size){
        if(st.st_size != pagelist.Size()){
          pagelist.Resize(st.st_size, false, false);
          need_save_csf = true;     // need to update page info
        }
        size = st.st_size;
      }else{
        if(size != pagelist.Size()){
          pagelist.Resize(size, false, false);
          need_save_csf = true;     // need to update page info
        }
        if(size != st.st_size){
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
        pagelist.Init(0, false, false);
      }else{
        pagelist.Resize(size, false, false);
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
      pagelist.Init(0, false, false);
    }else{
      pagelist.Resize(size, false, false);
      is_truncate = true;
    }
  }

  // truncate cache(tmp) file
  if(is_truncate){
    if(0 != ftruncate(fd, size) || 0 != fsync(fd)){
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
  refcnt = 1;

  // set original headers and size in it.
  if(pmeta){
    orgmeta      = *pmeta;
    size_orgmeta = get_size(orgmeta);
  }else{
    orgmeta.clear();
    size_orgmeta = 0;
  }

  // set mtime(set "x-amz-meta-mtime" in orgmeta)
  if(-1 != time){
    if(0 != SetMtime(time, /*lock_already_held=*/ true)){
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
bool FdEntity::OpenAndLoadAll(headers_t* pmeta, off_t* size, bool force_load)
{
  AutoLock auto_lock(&fdent_lock);
  int result;

  S3FS_PRN_INFO3("[path=%s][fd=%d]", path.c_str(), fd);

  if(-1 == fd){
    if(0 != Open(pmeta)){
      return false;
    }
  }
  AutoLock auto_data_lock(&fdent_data_lock);

  if(force_load){
    SetAllStatusUnloaded();
  }
  //
  // TODO: possibly do background for delay loading
  //
  if(0 != (result = Load(/*start=*/ 0, /*size=*/ 0, /*lock_already_held=*/ true))){
    S3FS_PRN_ERR("could not download, result(%d)", result);
    return false;
  }
  if(size){
    *size = pagelist.Size();
  }
  return true;
}

//
// Rename file path.
//
// This method sets the FdManager::fent map registration key to fentmapkey.
//
// [NOTE]
// This method changes the file path of FdEntity.
// Old file is deleted after linking to the new file path, and this works
// without problem because the file descriptor is not affected even if the
// cache file is open.
// The mirror file descriptor is also the same. The mirror file path does
// not need to be changed and will remain as it is.
//
bool FdEntity::RenamePath(const string& newpath, string& fentmapkey)
{
  if(!cachepath.empty()){
    // has cache path

    // make new cache path
    string newcachepath;
    if(!FdManager::MakeCachePath(newpath.c_str(), newcachepath, true)){
      S3FS_PRN_ERR("failed to make cache path for object(%s).", newpath.c_str());
      return false;
    }

    // link and unlink cache file
    if(-1 == link(cachepath.c_str(), newcachepath.c_str())){
      S3FS_PRN_ERR("failed to link old cache path(%s) to new cache path(%s) by errno(%d).", cachepath.c_str(), newcachepath.c_str(), errno);
      return false;
    }
    if(-1 == unlink(cachepath.c_str())){
      S3FS_PRN_ERR("failed to unlink old cache path(%s) by errno(%d).", cachepath.c_str(), errno);
      return false;
    }

    // link and unlink cache file stat
    if(!CacheFileStat::RenameCacheFileStat(path.c_str(), newpath.c_str())){
      S3FS_PRN_ERR("failed to rename cache file stat(%s to %s).", path.c_str(), newpath.c_str());
      return false;
    }
    fentmapkey = newpath;
    cachepath  = newcachepath;

  }else{
    // does not have cache path
    fentmapkey.erase();
    FdManager::MakeRandomTempPath(newpath.c_str(), fentmapkey);
  }
  // set new path
  path = newpath;

  return true;
}

bool FdEntity::GetStats(struct stat& st, bool lock_already_held)
{
  AutoLock auto_lock(&fdent_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);
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

int FdEntity::SetCtime(time_t time)
{
  if(-1 == time){
    return 0;
  }

  AutoLock auto_lock(&fdent_lock);
  orgmeta["x-amz-meta-ctime"] = str(time);
  return 0;
}

int FdEntity::SetMtime(time_t time, bool lock_already_held)
{
  AutoLock auto_lock(&fdent_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);

  S3FS_PRN_INFO3("[path=%s][fd=%d][time=%lld]", path.c_str(), fd, static_cast<long long>(time));

  if(-1 == time){
    return 0;
  }

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
  }else if(!cachepath.empty()){
    // not opened file yet.
    struct utimbuf n_mtime;
    n_mtime.modtime = time;
    n_mtime.actime  = time;
    if(-1 == utime(cachepath.c_str(), &n_mtime)){
      S3FS_PRN_ERR("utime failed. errno(%d)", errno);
      return -errno;
    }
  }
  orgmeta["x-amz-meta-ctime"] = str(time);
  orgmeta["x-amz-meta-mtime"] = str(time);

  return 0;
}

bool FdEntity::UpdateCtime()
{
  AutoLock auto_lock(&fdent_lock);
  struct stat st;
  if(!GetStats(st, /*lock_already_held=*/ true)){
    return false;
  }
  orgmeta["x-amz-meta-ctime"] = str(st.st_ctime);
  return true;
}

bool FdEntity::UpdateMtime()
{
  AutoLock auto_lock(&fdent_lock);
  struct stat st;
  if(!GetStats(st, /*lock_already_held=*/ true)){
    return false;
  }
  orgmeta["x-amz-meta-ctime"] = str(st.st_ctime);
  orgmeta["x-amz-meta-mtime"] = str(st.st_mtime);
  return true;
}

bool FdEntity::GetSize(off_t& size)
{
  AutoLock auto_lock(&fdent_lock);
  if(-1 == fd){
    return false;
  }

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
  pagelist.Init(st.st_size, is_loaded, false);

  return true;
}

int FdEntity::Load(off_t start, off_t size, bool lock_already_held)
{
  AutoLock auto_lock(&fdent_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);

  S3FS_PRN_DBG("[path=%s][fd=%d][offset=%lld][size=%lld]", path.c_str(), fd, static_cast<long long int>(start), static_cast<long long int>(size));

  if(-1 == fd){
    return -EBADF;
  }
  AutoLock auto_data_lock(&fdent_data_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);

  int result = 0;

  // check loaded area & load
  fdpage_list_t unloaded_list;
  if(0 < pagelist.GetUnloadedPages(unloaded_list, start, size)){
    for(fdpage_list_t::iterator iter = unloaded_list.begin(); iter != unloaded_list.end(); ++iter){
      if(0 != size && start + size <= iter->offset){
        // reached end
        break;
      }
      // check loading size
      off_t need_load_size = 0;
      if(iter->offset < size_orgmeta){
        // original file size(on S3) is smaller than request.
        need_load_size = (iter->next() <= size_orgmeta ? iter->bytes : (size_orgmeta - iter->offset));
      }

      // download
      if(S3fsCurl::GetMultipartSize() <= need_load_size && !nomultipart){
        // parallel request
        result = S3fsCurl::ParallelGetObjectRequest(path.c_str(), fd, iter->offset, need_load_size);
      }else{
        // single request
        if(0 < need_load_size){
          S3fsCurl s3fscurl;
          result = s3fscurl.GetObjectRequest(path.c_str(), fd, iter->offset, need_load_size);
        }else{
          result = 0;
        }
      }
      if(0 != result){
        break;
      }
      // Set loaded flag
      pagelist.SetPageLoadedStatus(iter->offset, iter->bytes, PageList::PAGE_LOADED);
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
int FdEntity::NoCacheLoadAndPost(off_t start, off_t size)
{
  int result = 0;

  S3FS_PRN_INFO3("[path=%s][fd=%d][offset=%lld][size=%lld]", path.c_str(), fd, static_cast<long long int>(start), static_cast<long long int>(size));

  if(-1 == fd){
    return -EBADF;
  }

  // [NOTE]
  // This method calling means that the cache file is never used no more.
  //
  if(!cachepath.empty()){
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
    if(iter->end() < start){
      continue;
    }
    if(0 != size && start + size <= iter->offset){
      break;
    }
    // download each multipart size(default 10MB) in unit
    for(off_t oneread = 0, totalread = (iter->offset < start ? start : 0); totalread < static_cast<off_t>(iter->bytes); totalread += oneread){
      int   upload_fd = fd;
      off_t offset    = iter->offset + totalread;
      oneread         = min(static_cast<off_t>(iter->bytes) - totalread, S3fsCurl::GetMultipartSize());

      // check rest size is over minimum part size
      //
      // [NOTE]
      // If the final part size is smaller than 5MB, it is not allowed by S3 API.
      // For this case, if the previous part of the final part is not over 5GB,
      // we incorporate the final part to the previous part. If the previous part
      // is over 5GB, we want to even out the last part and the previous part.
      //
      if((iter->bytes - totalread - oneread) < MIN_MULTIPART_SIZE){
        if(FIVE_GB < iter->bytes - totalread){
          oneread = (iter->bytes - totalread) / 2;
        }else{
          oneread = iter->bytes - totalread;
        }
      }

      if(!iter->loaded){
        //
        // loading or initializing
        //
        upload_fd = tmpfd;

        // load offset & size
        size_t need_load_size = 0;
        if(size_orgmeta <= offset){
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
            S3FS_PRN_ERR("failed to get object(start=%lld, size=%lld) for file(%d).", static_cast<long long int>(offset), static_cast<long long int>(oneread), tmpfd);
            break;
          }
        }
        // initialize fd without loading
        if(0 < over_size){
          if(0 != (result = FdEntity::FillFile(tmpfd, 0, over_size, offset + need_load_size))){
            S3FS_PRN_ERR("failed to fill rest bytes for fd(%d). errno(%d)", tmpfd, result);
            break;
          }
        }

      }else{
        // already loaded area
      }

      // single area upload by multipart post
      if(0 != (result = NoCacheMultipartPost(upload_fd, offset, oneread))){
        S3FS_PRN_ERR("failed to multipart post(start=%lld, size=%lld) for file(%d).", static_cast<long long int>(offset), static_cast<long long int>(oneread), upload_fd);
        break;
      }
    }
    if(0 != result){
      break;
    }

    // set loaded flag
    if(!iter->loaded){
      if(iter->offset < start){
        fdpage page(iter->offset, start - iter->offset, iter->loaded, false);
        iter->bytes -= (start - iter->offset);
        iter->offset = start;
        pagelist.pages.insert(iter, page);
      }
      if(0 != size && start + size < iter->next()){
        fdpage page(iter->offset, start + size - iter->offset, true, false);
        iter->bytes -= (start + size - iter->offset);
        iter->offset = start + size;
        pagelist.pages.insert(iter, page);
      }else{
        iter->loaded   = true;
        iter->modified = false;
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
int FdEntity::NoCachePreMultipartPost()
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
int FdEntity::NoCacheMultipartPost(int tgfd, off_t start, off_t size)
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
int FdEntity::NoCacheCompleteMultipartPost()
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

  std::string tmppath;
  headers_t tmporgmeta;
  {
    AutoLock auto_lock(&fdent_lock);
    tmppath = path;
    tmporgmeta = orgmeta;
  }

  S3FS_PRN_INFO3("[tpath=%s][path=%s][fd=%d]", SAFESTRPTR(tpath), tmppath.c_str(), fd);

  if(-1 == fd){
    return -EBADF;
  }
  AutoLock auto_lock(&fdent_data_lock);

  if(!force_sync && !pagelist.IsModified()){
    // nothing to update.
    return 0;
  }

  // If there is no loading all of the area, loading all area.
  off_t restsize = pagelist.GetTotalUnloadedPageSize();
  if(0 < restsize){
    if(0 == upload_id.length()){
      // check disk space
      if(ReserveDiskSpace(restsize)){
        // enough disk space
        // Load all uninitialized area(no mix multipart uploading)
        if(!FdEntity::mixmultipart){
          result = Load(/*start=*/ 0, /*size=*/ 0, /*lock_already_held=*/ true);
        }
        FdManager::FreeReservedDiskSpace(restsize);
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
    if(pagelist.Size() > MAX_MULTIPART_CNT * S3fsCurl::GetMultipartSize()){
      // close f ?
      S3FS_PRN_ERR("Part count exceeds %d.  Increase multipart size and try again.", MAX_MULTIPART_CNT);
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

    if(pagelist.Size() >= S3fsCurl::GetMultipartSize() && !nomultipart){
      if(FdEntity::mixmultipart){
        // multipart uploading can use copy api

        // This is to ensure that each part is 5MB or more.
        // If the part is less than 5MB, download it.
        fdpage_list_t dlpages;
        if(!pagelist.GetLoadPageListForMultipartUpload(dlpages)){
          S3FS_PRN_ERR("something error occurred during getting download pagelist.");
          return -1;
        }
        for(fdpage_list_t::const_iterator iter = dlpages.begin(); iter != dlpages.end(); ++iter){
          if(0 != (result = Load(iter->offset, iter->bytes, true))){
            S3FS_PRN_ERR("failed to get parts(start=%lld, size=%lld) before uploading.", static_cast<long long int>(iter->offset), static_cast<long long int>(iter->bytes));
            return result;
          }
        }

        // multipart uploading with copy api
        result = S3fsCurl::ParallelMixMultipartUploadRequest(tpath ? tpath : tmppath.c_str(), tmporgmeta, fd, pagelist);

      }else{
        // multipart uploading not using copy api
        result = S3fsCurl::ParallelMultipartUploadRequest(tpath ? tpath : tmppath.c_str(), tmporgmeta, fd);
      }
    }else{
      // If there are unloaded pages, they are loaded at here.
      if(0 != (result = Load(/*start=*/ 0, /*size=*/ 0, /*lock_already_held=*/ true))){
        S3FS_PRN_ERR("failed to load parts before uploading object(%d)", result);
        return result;
      }

      S3fsCurl s3fscurl(true);
      result = s3fscurl.PutRequest(tpath ? tpath : tmppath.c_str(), tmporgmeta, fd);
    }

    // seek to head of file.
    if(0 == result && 0 != lseek(fd, 0, SEEK_SET)){
      S3FS_PRN_ERR("lseek error(%d)", errno);
      return -errno;
    }

    // reset uploaded file size
    size_orgmeta = st.st_size;

  }else{
    // upload rest data
    if(0 < mp_size){
      if(0 != (result = NoCacheMultipartPost(fd, mp_start, mp_size))){
        S3FS_PRN_ERR("failed to multipart post(start=%lld, size=%lld) for file(%d).", static_cast<long long int>(mp_start), static_cast<long long int>(mp_size), fd);
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
    pagelist.ClearAllModified();
  }
  return result;
}

// [NOTICE]
// Need to lock before calling this method.
bool FdEntity::ReserveDiskSpace(off_t size)
{
  if(FdManager::ReserveDiskSpace(size)){
    return true;
  }

  if(!pagelist.IsModified()){
    // try to clear all cache for this fd.
    pagelist.Init(pagelist.Size(), false, false);
    if(-1 == ftruncate(fd, 0) || -1 == ftruncate(fd, pagelist.Size())){
      S3FS_PRN_ERR("failed to truncate temporary file(%d).", fd);
      return false;
    }

    if(FdManager::ReserveDiskSpace(size)){
      return true;
    }
  }

  FdManager::get()->CleanupCacheDir();

  return FdManager::ReserveDiskSpace(size);
}

ssize_t FdEntity::Read(char* bytes, off_t start, size_t size, bool force_load)
{
  S3FS_PRN_DBG("[path=%s][fd=%d][offset=%lld][size=%zu]", path.c_str(), fd, static_cast<long long int>(start), size);

  if(-1 == fd){
    return -EBADF;
  }
  AutoLock auto_lock(&fdent_data_lock);

  if(force_load){
    pagelist.SetPageLoadedStatus(start, size, PageList::PAGE_NOT_LOAD_MODIFIED);
  }

  ssize_t rsize;

  // check disk space
  if(0 < pagelist.GetTotalUnloadedPageSize(start, size)){
    // load size(for prefetch)
    size_t load_size = size;
    if(start + static_cast<ssize_t>(size) < pagelist.Size()){
      ssize_t prefetch_max_size = max(static_cast<off_t>(size), S3fsCurl::GetMultipartSize() * S3fsCurl::GetMaxParallelCount());

      if(start + prefetch_max_size < pagelist.Size()){
        load_size = prefetch_max_size;
      }else{
        load_size = pagelist.Size() - start;
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
      result = Load(start, load_size, /*lock_already_held=*/ true);
    }

    FdManager::FreeReservedDiskSpace(load_size);

    if(0 != result){
      S3FS_PRN_ERR("could not download. start(%lld), size(%zu), errno(%d)", static_cast<long long int>(start), size, result);
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
  S3FS_PRN_DBG("[path=%s][fd=%d][offset=%lld][size=%zu]", path.c_str(), fd, static_cast<long long int>(start), size);

  if(-1 == fd){
    return -EBADF;
  }
  // check if not enough disk space left BEFORE locking fd
  if(FdManager::IsCacheDir() && !FdManager::IsSafeDiskSpace(NULL, size)){
    FdManager::get()->CleanupCacheDir();
  }
  AutoLock auto_lock(&fdent_data_lock);

  // check file size
  if(pagelist.Size() < start){
    // grow file size
    if(-1 == ftruncate(fd, start)){
      S3FS_PRN_ERR("failed to truncate temporary file(%d).", fd);
      return -EIO;
    }
    // add new area
    pagelist.SetPageLoadedStatus(pagelist.Size(), start - pagelist.Size(), PageList::PAGE_MODIFIED);
  }

  int     result = 0;
  ssize_t wsize;

  if(0 == upload_id.length()){
    // check disk space
    off_t restsize = pagelist.GetTotalUnloadedPageSize(0, start) + size;
    if(ReserveDiskSpace(restsize)){
      // enough disk space

      // Load uninitialized area which starts from 0 to (start + size) before writing.
      if(!FdEntity::mixmultipart){
        if(0 < start){
          result = Load(0, start, /*lock_already_held=*/ true);
        }
      }

      FdManager::FreeReservedDiskSpace(restsize);
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
  if(0 < wsize){
    pagelist.SetPageLoadedStatus(start, wsize, PageList::PAGE_LOAD_MODIFIED);
  }

  // Load uninitialized area which starts from (start + size) to EOF after writing.
  if(!FdEntity::mixmultipart){
    if(pagelist.Size() > start + static_cast<off_t>(size)){
      result = Load(start + size, pagelist.Size(), /*lock_already_held=*/ true);
      if(0 != result){
        S3FS_PRN_ERR("failed to load uninitialized area after writing(errno=%d)", result);
        return static_cast<ssize_t>(result);
      }
    }
  }

  // check multipart uploading
  if(0 < upload_id.length()){
    mp_size += wsize;
    if(S3fsCurl::GetMultipartSize() <= mp_size){
      // over one multipart size
      if(0 != (result = NoCacheMultipartPost(fd, mp_start, mp_size))){
        S3FS_PRN_ERR("failed to multipart post(start=%lld, size=%lld) for file(%d).", static_cast<long long int>(mp_start), static_cast<long long int>(mp_size), fd);
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
string          FdManager::cache_dir;
bool            FdManager::check_cache_dir_exist(false);
off_t           FdManager::free_disk_space = 0;

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

bool FdManager::DeleteCacheDirectory()
{
  if(FdManager::cache_dir.empty()){
    return true;
  }

  string cache_path;
  if(!FdManager::MakeCachePath(NULL, cache_path, false)){
    return false;
  }
  if(!delete_files_in_dir(cache_path.c_str(), true)){
    return false;
  }

  string mirror_path = FdManager::cache_dir + "/." + bucket + ".mirror";
  if(!delete_files_in_dir(mirror_path.c_str(), true)){
    return false;
  }

  return true;
}

int FdManager::DeleteCacheFile(const char* path)
{
  S3FS_PRN_INFO3("[path=%s]", SAFESTRPTR(path));

  if(!path){
    return -EIO;
  }
  if(FdManager::cache_dir.empty()){
    return 0;
  }
  string cache_path;
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
  if(FdManager::cache_dir.empty()){
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

bool FdManager::CheckCacheTopDir()
{
  if(FdManager::cache_dir.empty()){
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

bool FdManager::CheckCacheDirExist()
{
  if(!FdManager::check_cache_dir_exist){
    return true;
  }
  if(FdManager::cache_dir.empty()){
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

off_t FdManager::GetEnsureFreeDiskSpace()
{
  AutoLock auto_lock(&FdManager::reserved_diskspace_lock);
  return FdManager::free_disk_space;
}

off_t FdManager::SetEnsureFreeDiskSpace(off_t size)
{
  AutoLock auto_lock(&FdManager::reserved_diskspace_lock);
  off_t old = FdManager::free_disk_space;
  FdManager::free_disk_space = size;
  return old;
}

off_t FdManager::GetFreeDiskSpace(const char* path)
{
  struct statvfs vfsbuf;
  string         ctoppath;
  if(!FdManager::cache_dir.empty()){
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

bool FdManager::IsSafeDiskSpace(const char* path, off_t size)
{
  off_t fsize = FdManager::GetFreeDiskSpace(path);
  return size + FdManager::GetEnsureFreeDiskSpace() <= fsize;
}

//------------------------------------------------
// FdManager methods
//------------------------------------------------
FdManager::FdManager()
{
  if(this == FdManager::get()){
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
    try{
      pthread_mutex_init(&FdManager::fd_manager_lock, &attr);
      pthread_mutex_init(&FdManager::cache_cleanup_lock, &attr);
      pthread_mutex_init(&FdManager::reserved_diskspace_lock, &attr);
      FdManager::is_lock_init = true;
    }catch(exception& e){
      FdManager::is_lock_init = false;
      S3FS_PRN_CRIT("failed to init mutex");
    }
  }else{
    abort();
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
    abort();
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
    iter->second->Dup();
    return (*iter).second;
  }

  if(-1 != existfd){
    for(iter = fent.begin(); iter != fent.end(); ++iter){
      if((*iter).second && (*iter).second->GetFd() == existfd){
        // found opened fd in map
        if(0 == strcmp((*iter).second->GetPath(), path)){
          iter->second->Dup();
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

FdEntity* FdManager::Open(const char* path, headers_t* pmeta, off_t size, time_t time, bool force_tmpfile, bool is_create, bool no_fd_lock_wait)
{
  S3FS_PRN_DBG("[path=%s][size=%lld][time=%lld]", SAFESTRPTR(path), static_cast<long long>(size), static_cast<long long>(time));

  if(!path || '\0' == path[0]){
    return NULL;
  }
  bool close = false;
  FdEntity* ent;

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
    ent->Dup();
    if(ent->IsModified()){
      // If the file is being modified, it will not be resized.
      size = -1;
    }
    close = true;

  }else if(is_create){
    // not found
    string cache_path;
    if(!force_tmpfile && !FdManager::MakeCachePath(path, cache_path, true)){
      S3FS_PRN_ERR("failed to make cache path for object(%s).", path);
      return NULL;
    }
    // make new obj
    ent = new FdEntity(path, cache_path.c_str());

    if(!cache_path.empty()){
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
      string tmppath;
      FdManager::MakeRandomTempPath(path, tmppath);
      fent[tmppath] = ent;
    }
  }else{
    return NULL;
  }

  // open
  if(0 != ent->Open(pmeta, size, time, no_fd_lock_wait)){
    if(close){
      ent->Close();
    }
    return NULL;
  }
  if(close){
    ent->Close();
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
  if(fent.end() == iter && !FdManager::IsCacheDir()){
    // If the cache directory is not specified, s3fs opens a temporary file
    // when the file is opened.
    // Then if it could not find a entity in map for the file, s3fs should
    // search a entity in all which opened the temporary file.
    //
    for(iter = fent.begin(); iter != fent.end(); ++iter){
      if((*iter).second && (*iter).second->IsOpen() && 0 == strcmp((*iter).second->GetPath(), from.c_str())){
        break;              // found opened fd in mapping
      }
    }
  }

  if(fent.end() != iter){
    // found
    S3FS_PRN_DBG("[from=%s][to=%s]", from.c_str(), to.c_str());

    FdEntity* ent = (*iter).second;

    // retrieve old fd entity from map
    fent.erase(iter);

    // rename path and caches in fd entity
    string fentmapkey;
    if(!ent->RenamePath(to, fentmapkey)){
      S3FS_PRN_ERR("Failed to rename FdEntity obejct for %s to %s", from.c_str(), to.c_str());
      return;
    }

    // set new fd entity to map
    fent[fentmapkey] = ent;
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

      string tmppath;
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
  //S3FS_PRN_DBG("cache cleanup requested");

  if(!FdManager::IsCacheDir()){
    return;
  }

  AutoLock auto_lock_no_wait(&FdManager::cache_cleanup_lock, AutoLock::NO_WAIT);

  if(auto_lock_no_wait.isLockAcquired()){
    //S3FS_PRN_DBG("cache cleanup started");
    CleanupCacheDirInternal("");
    //S3FS_PRN_DBG("cache cleanup ended");
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
      AutoLock auto_lock(&FdManager::fd_manager_lock, AutoLock::NO_WAIT);
      if (!auto_lock.isLockAcquired()) {
        S3FS_PRN_ERR("could not get fd_manager_lock when clean up file(%s)", next_path.c_str());
        continue;
      }
      fdent_map_t::iterator iter = fent.find(next_path);
      if(fent.end() == iter) {
        S3FS_PRN_DBG("cleaned up: %s", next_path.c_str());
        FdManager::DeleteCacheFile(next_path.c_str());
      }
    }
  }
  closedir(dp);
}

bool FdManager::ReserveDiskSpace(off_t size)
{
  if(IsSafeDiskSpace(NULL, size)){
    AutoLock auto_lock(&FdManager::reserved_diskspace_lock);
    free_disk_space += size;
    return true;
  }
  return false;
}

void FdManager::FreeReservedDiskSpace(off_t size)
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
