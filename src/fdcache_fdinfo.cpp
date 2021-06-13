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
#include <algorithm>

#include "common.h"
#include "s3fs.h"
#include "fdcache_fdinfo.h"
#include "fdcache_pseudofd.h"
#include "autolock.h"

//------------------------------------------------
// PseudoFdInfo methods
//------------------------------------------------
PseudoFdInfo::PseudoFdInfo(int fd, int open_flags) : pseudo_fd(-1), physical_fd(fd), flags(0) //, is_lock_init(false)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
    int result;
    if(0 != (result = pthread_mutex_init(&upload_list_lock, &attr))){
        S3FS_PRN_CRIT("failed to init upload_list_lock: %d", result);
        abort();
    }
    is_lock_init = true;

    if(-1 != physical_fd){
        pseudo_fd = PseudoFdManager::Get();
        flags     = open_flags;
    }
}

PseudoFdInfo::~PseudoFdInfo()
{
    if(is_lock_init){
      int result;
      if(0 != (result = pthread_mutex_destroy(&upload_list_lock))){
          S3FS_PRN_CRIT("failed to destroy upload_list_lock: %d", result);
          abort();
      }
      is_lock_init = false;
    }
    Clear();
}

bool PseudoFdInfo::Clear()
{
    if(-1 != pseudo_fd){
        PseudoFdManager::Release(pseudo_fd);
    }
    pseudo_fd   = -1;
    physical_fd = -1;

    return true;
}

bool PseudoFdInfo::Set(int fd, int open_flags)
{
    if(-1 == fd){
        return false;
    }
    Clear();
    physical_fd = fd;
    pseudo_fd   = PseudoFdManager::Get();
    flags       = open_flags;

    return true;
}

bool PseudoFdInfo::Writable() const
{
    if(-1 == pseudo_fd){
        return false;
    }
    if(0 == (flags & (O_WRONLY | O_RDWR))){
        return false;
    }
    return true;
}

bool PseudoFdInfo::Readable() const
{
    if(-1 == pseudo_fd){
        return false;
    }
    // O_RDONLY is 0x00, it means any pattern is readable.
    return true;
}

bool PseudoFdInfo::ClearUploadInfo(bool is_cancel_mp, bool lock_already_held)
{
    AutoLock auto_lock(&upload_list_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);

    if(is_cancel_mp){
        // [TODO]
        // If we have any uploaded parts, we should delete them here.
        // We haven't implemented it yet, but it will be implemented in the future.
        // (User can delete them in the utility mode of s3fs.)
        //
        S3FS_PRN_INFO("Implementation of cancellation process for multipart upload is awaited.");
    }

    upload_id.erase();
    upload_list.clear();
    ClearUntreated(true);

    return true;
}

bool PseudoFdInfo::InitialUploadInfo(const std::string& id)
{
    AutoLock auto_lock(&upload_list_lock);

    if(!ClearUploadInfo(true, true)){
        return false;
    }
    upload_id = id;
    return true;
}

bool PseudoFdInfo::GetUploadId(std::string& id) const
{
    if(IsUploading()){
        S3FS_PRN_ERR("Multipart Upload has not started yet.");
        return false;
    }
    id = upload_id;
    return true;
}

bool PseudoFdInfo::GetEtaglist(etaglist_t& list)
{
    if(IsUploading()){
        S3FS_PRN_ERR("Multipart Upload has not started yet.");
        return false;
    }

    AutoLock auto_lock(&upload_list_lock);

    list.clear();
    for(mppart_list_t::const_iterator iter = upload_list.begin(); iter != upload_list.end(); ++iter){
        list.push_back(iter->etag);
    }
    return !list.empty();
}

// [NOTE]
// This method adds a part for a multipart upload.
// The added new part must be an area that is exactly continuous with the
// immediately preceding part.
// An error will occur if it is discontinuous or if it overlaps with an
// existing area.
//
bool PseudoFdInfo::AppendUploadPart(off_t start, off_t size, bool is_copy, int* ppartnum, std::string** ppetag)
{
    if(IsUploading()){
        S3FS_PRN_ERR("Multipart Upload has not started yet.");
        return false;
    }

    AutoLock auto_lock(&upload_list_lock);
    off_t    next_start_pos = 0;
    if(!upload_list.empty()){
        next_start_pos = upload_list.back().start + upload_list.back().size;
    }
    if(start != next_start_pos){
        S3FS_PRN_ERR("The expected starting position for the next part is %lld, but %lld was specified.", static_cast<long long int>(next_start_pos), static_cast<long long int>(start));
        return false;
    }

    // add new part
    MPPART_INFO newpart(start, size, is_copy, NULL);
    upload_list.push_back(newpart);

    // set part number
    if(ppartnum){
        *ppartnum = static_cast<int>(upload_list.size());
    }

    // set etag pointer
    if(ppetag){
        *ppetag = &(upload_list.back().etag);
    }
    return true;
}

void PseudoFdInfo::ClearUntreated(bool lock_already_held)
{
    AutoLock auto_lock(&upload_list_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);

    untreated_start = 0;
    untreated_size  = 0;
}

bool PseudoFdInfo::GetUntreated(off_t& start, off_t& size)
{
    AutoLock auto_lock(&upload_list_lock);

    start = untreated_start;
    size  = untreated_size;

    return true;
}

bool PseudoFdInfo::SetUntreated(off_t start, off_t size)
{
    AutoLock auto_lock(&upload_list_lock);

    untreated_start = start;
    untreated_size  = size;

    return true;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
