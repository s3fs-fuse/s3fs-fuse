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
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "s3fs_logger.h"
#include "fdcache_fdinfo.h"
#include "fdcache_pseudofd.h"
#include "fdcache_entity.h"
#include "curl.h"
#include "string_util.h"
#include "threadpoolman.h"

//------------------------------------------------
// PseudoFdInfo class variables
//------------------------------------------------
int PseudoFdInfo::max_threads     = -1;
int PseudoFdInfo::opt_max_threads = -1;

//------------------------------------------------
// PseudoFdInfo class methods
//------------------------------------------------
//
// Worker function for uploading
//
void* PseudoFdInfo::MultipartUploadThreadWorker(void* arg)
{
    pseudofdinfo_thparam*   pthparam = static_cast<pseudofdinfo_thparam*>(arg);
    if(!pthparam || !(pthparam->ppseudofdinfo)){
        if(pthparam){
            delete pthparam;
        }
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Upload Part Thread [tpath=%s][start=%lld][size=%lld][part=%d]", pthparam->path.c_str(), static_cast<long long>(pthparam->start), static_cast<long long>(pthparam->size), pthparam->part_num);

    int       result;
    S3fsCurl* s3fscurl;
    {
        AutoLock auto_lock(&(pthparam->ppseudofdinfo->upload_list_lock));

        if(0 != (result = pthparam->ppseudofdinfo->last_result)){
            S3FS_PRN_DBG("Already occurred error, thus this thread worker is exiting.");

            if(!pthparam->ppseudofdinfo->CompleteInstruction(result, AutoLock::ALREADY_LOCKED)){    // result will be overwritten with the same value.
                result = -EIO;
            }
            delete pthparam;
            return reinterpret_cast<void*>(result);
        }
    }

    // setup and make curl object
    if(NULL == (s3fscurl = S3fsCurl::CreateParallelS3fsCurl(pthparam->path.c_str(), pthparam->upload_fd, pthparam->start, pthparam->size, pthparam->part_num, pthparam->is_copy, pthparam->petag, pthparam->upload_id, result))){
        S3FS_PRN_ERR("failed creating s3fs curl object for uploading [path=%s][start=%lld][size=%lld][part=%d]", pthparam->path.c_str(), static_cast<long long>(pthparam->start), static_cast<long long>(pthparam->size), pthparam->part_num);

        // set result for exiting
        if(!pthparam->ppseudofdinfo->CompleteInstruction(result, AutoLock::NONE)){
            result = -EIO;
        }
        delete pthparam;
        return reinterpret_cast<void*>(result);
    }

    // Send request and get result
    if(0 == (result = s3fscurl->RequestPerform())){
        S3FS_PRN_DBG("succeed uploading [path=%s][start=%lld][size=%lld][part=%d]", pthparam->path.c_str(), static_cast<long long>(pthparam->start), static_cast<long long>(pthparam->size), pthparam->part_num);
        if(!s3fscurl->MixMultipartPostComplete()){
            S3FS_PRN_ERR("failed completion uploading [path=%s][start=%lld][size=%lld][part=%d]", pthparam->path.c_str(), static_cast<long long>(pthparam->start), static_cast<long long>(pthparam->size), pthparam->part_num);
            result = -EIO;
        }
    }else{
        S3FS_PRN_ERR("failed uploading with error(%d) [path=%s][start=%lld][size=%lld][part=%d]", result, pthparam->path.c_str(), static_cast<long long>(pthparam->start), static_cast<long long>(pthparam->size), pthparam->part_num);
    }
    s3fscurl->DestroyCurlHandle(true, false);
    delete s3fscurl;

    // set result
    if(!pthparam->ppseudofdinfo->CompleteInstruction(result, AutoLock::NONE)){
        S3FS_PRN_WARN("This thread worker is about to end, so it doesn't return an EIO here and runs to the end.");
    }
    delete pthparam;

    return reinterpret_cast<void*>(result);
}

//------------------------------------------------
// PseudoFdInfo methods
//------------------------------------------------
PseudoFdInfo::PseudoFdInfo(int fd, int open_flags) : pseudo_fd(-1), physical_fd(fd), flags(0), upload_fd(-1), uploaded_sem(0), instruct_count(0), completed_count(0), last_result(0)
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
    Clear();        // call before destrying the mutex

    if(is_lock_init){
      int result;
      if(0 != (result = pthread_mutex_destroy(&upload_list_lock))){
          S3FS_PRN_CRIT("failed to destroy upload_list_lock: %d", result);
          abort();
      }
      is_lock_init = false;
    }
}

bool PseudoFdInfo::Clear()
{
    if(!CancelAllThreads() || !ResetUploadInfo(AutoLock::NONE)){
        return false;
    }
    CloseUploadFd();

    if(-1 != pseudo_fd){
        PseudoFdManager::Release(pseudo_fd);
    }
    pseudo_fd   = -1;
    physical_fd = -1;

    return true;
}

void PseudoFdInfo::CloseUploadFd()
{
    AutoLock auto_lock(&upload_list_lock);

    if(-1 != upload_fd){
        close(upload_fd);
    }
}

bool PseudoFdInfo::OpenUploadFd(AutoLock::Type type)
{
    AutoLock auto_lock(&upload_list_lock, type);

    if(-1 != upload_fd){
        // already initialized
        return true;
    }
    if(-1 == physical_fd){
        S3FS_PRN_ERR("physical_fd is not initialized yet.");
        return false;
    }

    // duplicate fd
    if(-1 == (upload_fd = dup(physical_fd)) || 0 != lseek(upload_fd, 0, SEEK_SET)){
        S3FS_PRN_ERR("Could not duplicate physical file descriptor(errno=%d)", errno);
        if(-1 != upload_fd){
            close(upload_fd);
        }
        return false;
    }
    struct stat st;
    if(-1 == fstat(upload_fd, &st)){
        S3FS_PRN_ERR("Invalid file descriptor for uploading(errno=%d)", errno);
        close(upload_fd);
        return false;
    }
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

bool PseudoFdInfo::ClearUploadInfo(bool is_cancel_mp)
{
    if(is_cancel_mp){
        if(!CancelAllThreads()){
            return false;
        }
    }
    return ResetUploadInfo(AutoLock::NONE);
}

bool PseudoFdInfo::ResetUploadInfo(AutoLock::Type type)
{
    AutoLock auto_lock(&upload_list_lock, type);

    upload_id.erase();
    upload_list.clear();
    instruct_count  = 0;
    completed_count = 0;
    last_result     = 0;

    return true;
}

bool PseudoFdInfo::RowInitialUploadInfo(const std::string& id, bool is_cancel_mp, AutoLock::Type type)
{
    if(is_cancel_mp && AutoLock::ALREADY_LOCKED == type){
        S3FS_PRN_ERR("Internal Error: Could not call this with type=AutoLock::ALREADY_LOCKED and is_cancel_mp=true");
        return false;
    }

    if(is_cancel_mp){
        if(!ClearUploadInfo(is_cancel_mp)){
            return false;
        }
    }else{
        if(!ResetUploadInfo(type)){
            return false;
        }
    }

    AutoLock auto_lock(&upload_list_lock, type);
    upload_id = id;
    return true;
}

bool PseudoFdInfo::CompleteInstruction(int result, AutoLock::Type type)
{
    AutoLock auto_lock(&upload_list_lock, type);

    if(0 != result){
        last_result = result;
    }

    if(0 >= instruct_count){
        S3FS_PRN_ERR("Internal error: instruct_count caused an underflow.");
        return false;
    }
    --instruct_count;
    ++completed_count;

    return true;
}

bool PseudoFdInfo::GetUploadId(std::string& id) const
{
    if(!IsUploading()){
        S3FS_PRN_ERR("Multipart Upload has not started yet.");
        return false;
    }
    id = upload_id;
    return true;
}

bool PseudoFdInfo::GetEtaglist(etaglist_t& list)
{
    if(!IsUploading()){
        S3FS_PRN_ERR("Multipart Upload has not started yet.");
        return false;
    }

    AutoLock auto_lock(&upload_list_lock);

    list.clear();
    for(filepart_list_t::const_iterator iter = upload_list.begin(); iter != upload_list.end(); ++iter){
        if(iter->petag){
            list.push_back(*(iter->petag));
        }else{
            S3FS_PRN_ERR("The pointer to the etag string is null(internal error).");
            return false;
        }
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
bool PseudoFdInfo::AppendUploadPart(off_t start, off_t size, bool is_copy, etagpair** ppetag)
{
    if(!IsUploading()){
        S3FS_PRN_ERR("Multipart Upload has not started yet.");
        return false;
    }

    AutoLock auto_lock(&upload_list_lock);
    off_t    next_start_pos = 0;
    if(!upload_list.empty()){
        next_start_pos = upload_list.back().startpos + upload_list.back().size;
    }
    if(start != next_start_pos){
        S3FS_PRN_ERR("The expected starting position for the next part is %lld, but %lld was specified.", static_cast<long long int>(next_start_pos), static_cast<long long int>(start));
        return false;
    }

    // make part number
    int partnumber = static_cast<int>(upload_list.size()) + 1;

    // add new part
    etagpair*   petag_entity = etag_entities.add(etagpair(NULL, partnumber));              // [NOTE] Create the etag entity and register it in the list.
    filepart    newpart(false, physical_fd, start, size, is_copy, petag_entity);
    upload_list.push_back(newpart);

    // set etag pointer
    if(ppetag){
        *ppetag = petag_entity;
    }

    return true;
}

//
// Utility for sorting upload list
//
static bool filepart_partnum_compare(const filepart& src1, const filepart& src2)
{
    return (src1.get_part_number() <= src2.get_part_number());
}

bool PseudoFdInfo::InsertUploadPart(off_t start, off_t size, int part_num, bool is_copy, etagpair** ppetag, AutoLock::Type type)
{
    //S3FS_PRN_DBG("[start=%lld][size=%lld][part_num=%d][is_copy=%s]", static_cast<long long int>(start), static_cast<long long int>(size), part_num, (is_copy ? "true" : "false"));

    if(!IsUploading()){
        S3FS_PRN_ERR("Multipart Upload has not started yet.");
        return false;
    }
    if(start < 0 || size <= 0 || part_num < 0 || !ppetag){
        S3FS_PRN_ERR("Parameters are wrong.");
        return false;
    }

    AutoLock auto_lock(&upload_list_lock, type);

    // insert new part
    etagpair*   petag_entity = etag_entities.add(etagpair(NULL, part_num));
    filepart    newpart(false, physical_fd, start, size, is_copy, petag_entity);
    upload_list.push_back(newpart);

    // sort by part number
    upload_list.sort(filepart_partnum_compare);

    // set etag pointer
    *ppetag = petag_entity;

    return true;
}

// [NOTE]
// This method only launches the upload thread.
// Check the maximum number of threads before calling.
//
bool PseudoFdInfo::ParallelMultipartUpload(const char* path, const mp_part_list_t& mplist, bool is_copy, AutoLock::Type type)
{
    //S3FS_PRN_DBG("[path=%s][mplist(%zu)]", SAFESTRPTR(path), mplist.size());

    AutoLock auto_lock(&upload_list_lock, type);

    if(mplist.empty()){
        // nothing to do
        return true;
    }
    if(!OpenUploadFd(AutoLock::ALREADY_LOCKED)){
        return false;
    }

    for(mp_part_list_t::const_iterator iter = mplist.begin(); iter != mplist.end(); ++iter){
        // Insert upload part
        etagpair* petag = NULL;
        if(!InsertUploadPart(iter->start, iter->size, iter->part_num, is_copy, &petag, AutoLock::ALREADY_LOCKED)){
            S3FS_PRN_ERR("Failed to insert insert upload part(path=%s, start=%lld, size=%lld, part=%d, copy=%s) to mplist", SAFESTRPTR(path), static_cast<long long int>(iter->start), static_cast<long long int>(iter->size), iter->part_num, (is_copy ? "true" : "false"));
            return false;
        }

        // make parameter for my thread
        pseudofdinfo_thparam* thargs = new pseudofdinfo_thparam;
        thargs->ppseudofdinfo        = this;
        thargs->path                 = SAFESTRPTR(path);
        thargs->upload_id            = upload_id;
        thargs->upload_fd            = upload_fd;
        thargs->start                = iter->start;
        thargs->size                 = iter->size;
        thargs->is_copy              = is_copy;
        thargs->part_num             = iter->part_num;
        thargs->petag                = petag;

        // make parameter for thread pool
        thpoolman_param* ppoolparam  = new thpoolman_param;
        ppoolparam->args             = thargs;
        ppoolparam->psem             = &uploaded_sem;
        ppoolparam->pfunc            = PseudoFdInfo::MultipartUploadThreadWorker;

        // setup instruction
        if(!ThreadPoolMan::Instruct(ppoolparam)){
            S3FS_PRN_ERR("failed setup instruction for uploading.");
            delete ppoolparam;
            delete thargs;
            return false;
        }
        ++instruct_count;
    }
    return true;
}

bool PseudoFdInfo::ParallelMultipartUploadAll(const char* path, const mp_part_list_t& upload_list, const mp_part_list_t& copy_list, int& result)
{
    S3FS_PRN_DBG("[path=%s][upload_list(%zu)][copy_list(%zu)]", SAFESTRPTR(path), upload_list.size(), copy_list.size());

    result = 0;

    if(!OpenUploadFd(AutoLock::NONE)){
        return false;
    }

    if(!ParallelMultipartUpload(path, upload_list, false, AutoLock::NONE) || !ParallelMultipartUpload(path, copy_list, true, AutoLock::NONE)){
        S3FS_PRN_ERR("Failed setup instruction for uploading(path=%s, upload_list=%zu, copy_list=%zu).", SAFESTRPTR(path), upload_list.size(), copy_list.size());
        return false;
    }

    // Wait for all thread exiting
    result = WaitAllThreadsExit();

    return true;
}

//
// Upload the last updated Untreated area
//
// [Overview]
// Uploads untreated areas with the maximum multipart upload size as the
// boundary.
//
// * The starting position of the untreated area is aligned with the maximum
//   multipart upload size as the boundary.
// * If there is an uploaded area that overlaps with the aligned untreated
//   area, that uploaded area is canceled and absorbed by the untreated area.
// * Upload only when the aligned untreated area exceeds the maximum multipart
//   upload size.
// * When the start position of the untreated area is changed to boundary
//   alignment(to backward), and if that gap area is remained, that area is
//   rest to untreated area.
//
ssize_t PseudoFdInfo::UploadBoundaryLastUntreatedArea(const char* path, headers_t& meta, FdEntity* pfdent)
{
    S3FS_PRN_DBG("[path=%s][pseudo_fd=%d][physical_fd=%d]", SAFESTRPTR(path), pseudo_fd, physical_fd);

    if(!path || -1 == physical_fd || -1 == pseudo_fd || !pfdent){
        S3FS_PRN_ERR("pseudo_fd(%d) to physical_fd(%d) for path(%s) is not opened or not writable, or pfdent is NULL.", pseudo_fd, physical_fd, path);
        return -EBADF;
    }
    AutoLock auto_lock(&upload_list_lock);

    //
    // Get last update untreated area
    //
    off_t last_untreated_start = 0;
    off_t last_untreated_size  = 0;
    if(!pfdent->GetLastUpdateUntreatedPart(last_untreated_start, last_untreated_size) || last_untreated_start < 0 || last_untreated_size <= 0){
        S3FS_PRN_WARN("Not found last update untreated area or it is empty, thus return without any error.");
        return 0;
    }

    //
    // Aligns the start position of the last updated raw area with the boundary
    //
    // * Align the last updated raw space with the maximum upload size boundary.
    // * The remaining size of the part before the boundary is will not be uploaded.
    //
    off_t max_mp_size     = S3fsCurl::GetMultipartSize();
    off_t aligned_start   = ((last_untreated_start / max_mp_size) + (0 < (last_untreated_start % max_mp_size) ? 1 : 0)) * max_mp_size;
    if((last_untreated_start + last_untreated_size) <= aligned_start){
        S3FS_PRN_INFO("After the untreated area(start=%lld, size=%lld) is aligned with the boundary, the aligned start(%lld) exceeds the untreated area, so there is nothing to do.", static_cast<long long int>(last_untreated_start), static_cast<long long int>(last_untreated_size), static_cast<long long int>(aligned_start));
        return 0;
    }

    off_t aligned_size    = (((last_untreated_start + last_untreated_size) - aligned_start) / max_mp_size) * max_mp_size;
    if(0 == aligned_size){
        S3FS_PRN_DBG("After the untreated area(start=%lld, size=%lld) is aligned with the boundary(start is %lld), the aligned size is empty, so nothing to do.", static_cast<long long int>(last_untreated_start), static_cast<long long int>(last_untreated_size), static_cast<long long int>(aligned_start));
        return 0;
    }

    off_t front_rem_start = last_untreated_start;                       // start of the remainder untreated area in front of the boundary
    off_t front_rem_size  = aligned_start - last_untreated_start;       // size of the remainder untreated area in front of the boundary

    //
    // Get the area for uploading, if last update treated area can be uploaded.
    //
    // [NOTE]
    // * Create the updoad area list, if the untreated area aligned with the boundary
    //   exceeds the maximum upload size.
    // * If it overlaps with an area that has already been uploaded(unloaded list),
    //   that area is added to the cancellation list and included in the untreated area.
    //
    mp_part_list_t  to_upload_list;
    filepart_list_t cancel_uploaded_list;
    if(!ExtractUploadPartsFromUntreatedArea(aligned_start, aligned_size, to_upload_list, cancel_uploaded_list, S3fsCurl::GetMultipartSize())){
        S3FS_PRN_ERR("Failed to extract upload parts from last untreated area.");
        return -EIO;
    }
    if(to_upload_list.empty()){
        S3FS_PRN_INFO("There is nothing to upload. In most cases, the untreated area does not meet the upload size.");
        return 0;
    }

    //
    // Has multipart uploading already started?
    //
    if(!IsUploading()){
        // Multipart uploading hasn't started yet, so start it.
        //
        S3fsCurl    s3fscurl(true);
        std::string tmp_upload_id;
        int         result;
        if(0 != (result = s3fscurl.PreMultipartPostRequest(path, meta, tmp_upload_id, true))){
            S3FS_PRN_ERR("failed to setup multipart upload(create upload id) by errno(%d)", result);
            return result;
        }
        if(!RowInitialUploadInfo(tmp_upload_id, false/* not need to cancel */, AutoLock::ALREADY_LOCKED)){
            S3FS_PRN_ERR("failed to setup multipart upload(set upload id to object)");
            return result;
        }
    }

    //
    // Output debug level information
    //
    // When canceling(overwriting) a part that has already been uploaded, output it.
    //
    if(S3fsLog::IsS3fsLogDbg()){
        for(filepart_list_t::const_iterator cancel_iter = cancel_uploaded_list.begin(); cancel_iter != cancel_uploaded_list.end(); ++cancel_iter){
            S3FS_PRN_DBG("Cancel uploaded: start(%lld), size(%lld), part number(%d)", static_cast<long long int>(cancel_iter->startpos), static_cast<long long int>(cancel_iter->size), (cancel_iter->petag ? cancel_iter->petag->part_num : -1));
        }
    }

    //
    // Upload Multipart parts
    //
    if(!ParallelMultipartUpload(path, to_upload_list, false, AutoLock::ALREADY_LOCKED)){
        S3FS_PRN_ERR("Failed to upload multipart parts.");
        return -EIO;
    }

    //
    // Exclude the uploaded Untreated area and update the last Untreated area.
    //
    off_t behind_rem_start = aligned_start + aligned_size;
    off_t behind_rem_size  = (last_untreated_start + last_untreated_size) - behind_rem_start;

    if(!pfdent->ReplaceLastUpdateUntreatedPart(front_rem_start, front_rem_size, behind_rem_start, behind_rem_size)){
        S3FS_PRN_WARN("The last untreated area could not be detected and the uploaded area could not be excluded from it, but continue because it does not affect the overall processing.");
    }

    return 0;
}

int PseudoFdInfo::WaitAllThreadsExit()
{
    int  result;
    bool is_loop = true;
    {
        AutoLock auto_lock(&upload_list_lock);
        if(0 == instruct_count && 0 == completed_count){
            result  = last_result;
            is_loop = false;
        }
    }

    while(is_loop){
        // need to wait the worker exiting
        uploaded_sem.wait();
        {
            AutoLock auto_lock(&upload_list_lock);
            if(0 < completed_count){
                --completed_count;
            }
            if(0 == instruct_count && 0 == completed_count){
                // break loop
                result  = last_result;
                is_loop = false;
            }
        }
    }

    return result;
}

bool PseudoFdInfo::CancelAllThreads()
{
    bool need_cancel = false;
    {
        AutoLock auto_lock(&upload_list_lock);
        if(0 < instruct_count && 0 < completed_count){
            S3FS_PRN_INFO("The upload thread is running, so cancel them and wait for the end.");
            need_cancel = true;
            last_result = -ECANCELED;   // to stop thread running
        }
    }
    if(need_cancel){
        WaitAllThreadsExit();
    }
    return true;
}

//
// Extract the list for multipart upload from the Unteated Area
//
// The untreated_start parameter must be set aligning it with the boundaries
// of the maximum multipart upload size. This method expects it to be bounded.
//
// This method creates the upload area aligned from the untreated area by
// maximum size and creates the required list.
// If it overlaps with an area that has already been uploaded, the overlapped
// upload area will be canceled and absorbed by the untreated area.
// If the list creation process is complete and areas smaller than the maximum
// size remain, those area will be reset to untreated_start and untreated_size
// and returned to the caller.
// If the called untreated area is smaller than the maximum size of the
// multipart upload, no list will be created.
//
// [NOTE]
// Maximum multipart upload size must be uploading boundary.
//
bool PseudoFdInfo::ExtractUploadPartsFromUntreatedArea(off_t& untreated_start, off_t& untreated_size, mp_part_list_t& to_upload_list, filepart_list_t& cancel_upload_list, off_t max_mp_size)
{
    if(untreated_start < 0 || untreated_size <= 0){
        S3FS_PRN_ERR("Paramters are wrong(untreated_start=%lld, untreated_size=%lld).", static_cast<long long int>(untreated_start), static_cast<long long int>(untreated_size));
        return false;
    }

    // Initiliaze lists
    to_upload_list.clear();
    cancel_upload_list.clear();

    //
    // Align start position with maximum multipart upload boundaries
    //
    off_t aligned_start = (untreated_start / max_mp_size) * max_mp_size;
    off_t aligned_size  = untreated_size + (untreated_start - aligned_start);

    //
    // Check aligned untreated size
    //
    if(aligned_size < max_mp_size){
        S3FS_PRN_INFO("untreated area(start=%lld, size=%lld) to aligned boundary(start=%lld, size=%lld) is smaller than max mp size(%lld), so nothing to do.", static_cast<long long int>(untreated_start), static_cast<long long int>(untreated_size), static_cast<long long int>(aligned_start), static_cast<long long int>(aligned_size), static_cast<long long int>(max_mp_size));
        return true;    // successful termination
    }

    //
    // Check each unloaded area in list
    //
    // [NOTE]
    // The uploaded area must be to be aligned by boundary.
    // Also, it is assumed that it must not be a copy area.
    // So if the areas overlap, include uploaded area as an untreated area.
    //
    for(filepart_list_t::iterator cur_iter = upload_list.begin(); cur_iter != upload_list.end(); /* ++cur_iter */){
        // Check overlap
        if((cur_iter->startpos + cur_iter->size - 1) < aligned_start || (aligned_start + aligned_size - 1) < cur_iter->startpos){
            // Areas do not overlap
            ++cur_iter;

        }else{
            // The areas overlap
            //
            // Since the start position of the uploaded area is aligned with the boundary,
            // it is not necessary to check the start position.
            // If the uploaded area exceeds the untreated area, expand the untreated area.
            //
            if((aligned_start + aligned_size - 1) < (cur_iter->startpos + cur_iter->size - 1)){
                aligned_size += (cur_iter->startpos + cur_iter->size) - (aligned_start + aligned_size);
            }

            //
            // Add this to cancel list
            //
            cancel_upload_list.push_back(*cur_iter);            // Copy and Push to cancel list
            cur_iter = upload_list.erase(cur_iter);
        }
    }

    //
    // Add upload area to the list
    //
    while(max_mp_size <= aligned_size){
        int part_num = (aligned_start / max_mp_size) + 1;
        to_upload_list.push_back(mp_part(aligned_start, max_mp_size, part_num));

        aligned_start += max_mp_size;
        aligned_size  -= max_mp_size;
    }

    return true;
}

//
// Extract the area lists to be uploaded/downloaded for the entire file.
//
// [Parameters]
// to_upload_list       : A list of areas to upload in multipart upload.
// to_copy_list         : A list of areas for copy upload in multipart upload.
// to_download_list     : A list of areas that must be downloaded before multipart upload.
// cancel_upload_list : A list of areas that have already been uploaded and will be canceled(overwritten).
// file_size            : The size of the upload file.
// use_copy             : Specify true if copy multipart upload is available.
//
// [NOTE]
// The untreated_list in fdentity does not change, but upload_list is changed.
// (If you want to restore it, you can use cancel_upload_list.)
//
bool PseudoFdInfo::ExtractUploadPartsFromAllArea(UntreatedParts& untreated_list, mp_part_list_t& to_upload_list, mp_part_list_t& to_copy_list, mp_part_list_t& to_download_list, filepart_list_t& cancel_upload_list, off_t max_mp_size, off_t file_size, bool use_copy)
{
    AutoLock auto_lock(&upload_list_lock);

    // Initiliaze lists
    to_upload_list.clear();
    to_copy_list.clear();
    to_download_list.clear();
    cancel_upload_list.clear();

    // Duplicate untreated list
    untreated_list_t dup_untreated_list;
    untreated_list.Duplicate(dup_untreated_list);

    // Initialize the iterator of each list first
    untreated_list_t::iterator dup_untreated_iter = dup_untreated_list.begin();
    filepart_list_t::iterator  uploaded_iter      = upload_list.begin();

    //
    // Loop to extract areas to upload and download
    //
    // Check at the boundary of the maximum upload size from the beginning of the file
    //
    for(off_t cur_start = 0, cur_size = 0; cur_start < file_size; cur_start += cur_size){
        //
        // Set part size
        // (To avoid confusion, the area to be checked is called the "current area".)
        //
        cur_size = ((cur_start + max_mp_size) <= file_size ? max_mp_size : (file_size - cur_start));

        //
        // Extract the untreated erea that overlaps this current area.
        // (The extracted area is deleted from dup_untreated_list.)
        //
        untreated_list_t cur_untreated_list;
        for(cur_untreated_list.clear(); dup_untreated_iter != dup_untreated_list.end(); ){
            if((dup_untreated_iter->start < (cur_start + cur_size)) && (cur_start < (dup_untreated_iter->start + dup_untreated_iter->size))){
                // this untreated area is overlap
                off_t tmp_untreated_start;
                off_t tmp_untreated_size;
                if(dup_untreated_iter->start < cur_start){
                    // [NOTE]
                    // This untreated area overlaps with the current area, but starts
                    // in front of the target area.
                    // This state should not be possible, but if this state is detected,
                    // the part before the target area will be deleted.
                    //
                    tmp_untreated_start = cur_start;
                    tmp_untreated_size  = dup_untreated_iter->size - (cur_start - dup_untreated_iter->start);
                }else{
                    tmp_untreated_start = dup_untreated_iter->start;
                    tmp_untreated_size  = dup_untreated_iter->size;
                }

                //
                // Check the end of the overlapping untreated area.
                //
                if((tmp_untreated_start + tmp_untreated_size) <= (cur_start + cur_size)){
                    //
                    // All of untreated areas are within the current area
                    //
                    // - Add this untreated area to cur_untreated_list
                    // - Delete this from dup_untreated_list
                    //
                    cur_untreated_list.push_back(untreatedpart(tmp_untreated_start, tmp_untreated_size));
                    dup_untreated_iter = dup_untreated_list.erase(dup_untreated_iter);
                }else{
                    //
                    // The untreated area exceeds the end of the current area
                    //

                    // Ajust untreated area
                    tmp_untreated_size  = (cur_start + cur_size) - tmp_untreated_start;

                    // Add ajusted untreated area to cur_untreated_list
                    cur_untreated_list.push_back(untreatedpart(tmp_untreated_start, tmp_untreated_size));

                    // Remove this ajusted untreated area from the area pointed
                    // to by dup_untreated_iter.
                    dup_untreated_iter->size  = (dup_untreated_iter->start + dup_untreated_iter->size) - (cur_start + cur_size);
                    dup_untreated_iter->start = tmp_untreated_start + tmp_untreated_size;
                }

            }else if((cur_start + cur_size - 1) < dup_untreated_iter->start){
                // this untreated area is over the current area, thus break loop.
                break;
            }else{
                ++dup_untreated_iter;
            }
        }

        //
        // Check uploaded area
        //
        // [NOTE]
        // The uploaded area should be aligned with the maximum upload size boundary.
        // It also assumes that each size of uploaded area must be a maximum upload
        // size.
        //
        filepart_list_t::iterator overlap_uploaded_iter = upload_list.end();
        for(; uploaded_iter != upload_list.end(); ++uploaded_iter){
            if((cur_start < (uploaded_iter->startpos + uploaded_iter->size)) && (uploaded_iter->startpos < (cur_start + cur_size))){
                if(overlap_uploaded_iter != upload_list.end()){
                    //
                    // Something wrong in this unloaded area.
                    //
                    // This area is not aligned with the boundary, then this condition
                    // is unrecoverable and return failure.
                    //
                    S3FS_PRN_ERR("The uploaded list may not be the boundary for the maximum multipart upload size. No further processing is possible.");
                    return false;
                }
                // Set this iterator to overlap iter
                overlap_uploaded_iter = uploaded_iter;

            }else if((cur_start + cur_size - 1) < uploaded_iter->startpos){
                break;
            }
        }

        //
        // Create upload/download/cancel/copy list for this current area
        //
        int part_num = (cur_start / max_mp_size) + 1;
        if(cur_untreated_list.empty()){
            //
            // No untreated area was detected in this current area
            //
            if(overlap_uploaded_iter != upload_list.end()){
                //
                // This current area already uploaded, then nothing to add to lists.
                //
                S3FS_PRN_DBG("Already uploaded: start=%lld, size=%lld", static_cast<long long int>(cur_start), static_cast<long long int>(cur_size));

            }else{
                //
                // This current area has not been uploaded
                // (neither an uploaded area nor an untreated area.)
                //
                if(use_copy){
                    //
                    // Copy multipart upload available
                    //
                    S3FS_PRN_DBG("To copy: start=%lld, size=%lld", static_cast<long long int>(cur_start), static_cast<long long int>(cur_size));
                    to_copy_list.push_back(mp_part(cur_start, cur_size, part_num));
                }else{
                    //
                    // This current area needs to be downloaded and uploaded
                    //
                    S3FS_PRN_DBG("To download and upload: start=%lld, size=%lld", static_cast<long long int>(cur_start), static_cast<long long int>(cur_size));
                    to_download_list.push_back(mp_part(cur_start, cur_size));
                    to_upload_list.push_back(mp_part(cur_start, cur_size, part_num));
                }
            }
        }else{
            //
            // Found untreated area in this current area
            //
            if(overlap_uploaded_iter != upload_list.end()){
                //
                // This current area is also the uploaded area
                //
                // [NOTE]
                // The uploaded area is aligned with boundary, there are all data in
                // this current area locally(which includes all data of untreated area).
                // So this current area only needs to be uploaded again.
                //
                S3FS_PRN_DBG("Cancel upload: start=%lld, size=%lld", static_cast<long long int>(overlap_uploaded_iter->startpos), static_cast<long long int>(overlap_uploaded_iter->size));
                cancel_upload_list.push_back(*overlap_uploaded_iter);               // add this uploaded area to cancel_upload_list
                uploaded_iter = upload_list.erase(overlap_uploaded_iter);           // remove it from upload_list

                S3FS_PRN_DBG("To upload: start=%lld, size=%lld", static_cast<long long int>(cur_start), static_cast<long long int>(cur_size));
                to_upload_list.push_back(mp_part(cur_start, cur_size, part_num));   // add new uploading area to list

            }else{
                //
                // No uploaded area overlap this current area
                // (Areas other than the untreated area must be downloaded.)
                //
                // [NOTE]
                // Need to consider the case where there is a gap between the start
                // of the current area and the untreated area.
                // This gap is the area that should normally be downloaded.
                // But it is the area that can be copied if we can use copy multipart
                // upload. Then If we can use copy multipart upload and the previous
                // area is used copy multipart upload, this gap will be absorbed by
                // the previous area.
                // Unifying the copy multipart upload area can reduce the number of
                // upload requests.
                //
                off_t tmp_cur_start = cur_start;
                off_t tmp_cur_size  = cur_size;
                off_t changed_start = cur_start;
                off_t changed_size  = cur_size;
                bool  first_area    = true;
                for(untreated_list_t::const_iterator tmp_cur_untreated_iter = cur_untreated_list.begin(); tmp_cur_untreated_iter != cur_untreated_list.end(); ++tmp_cur_untreated_iter, first_area = false){
                    if(tmp_cur_start < tmp_cur_untreated_iter->start){
                        //
                        // Detected a gap at the start of area
                        //
                        bool include_prev_copy_part = false;
                        if(first_area && use_copy && !to_copy_list.empty()){
                            //
                            // Make sure that the area of the last item in to_copy_list
                            // is contiguous with this current area.
                            //
                            // [NOTE]
                            // Areas can be unified if the total size of the areas is
                            // within 5GB and the remaining area after unification is
                            // larger than the minimum multipart upload size.
                            //
                            mp_part_list_t::reverse_iterator copy_riter = to_copy_list.rbegin();

                            if( (copy_riter->start + copy_riter->size) == tmp_cur_start &&
                                (copy_riter->size + (tmp_cur_untreated_iter->start - tmp_cur_start)) <= FIVE_GB &&
                                ((tmp_cur_start + tmp_cur_size) - (tmp_cur_untreated_iter->start - tmp_cur_start)) >= MIN_MULTIPART_SIZE )
                            {
                                //
                                // Unify to this area to previouse copy area.
                                //
                                copy_riter->size += tmp_cur_untreated_iter->start - tmp_cur_start;
                                S3FS_PRN_DBG("Resize to copy: start=%lld, size=%lld", static_cast<long long int>(copy_riter->start), static_cast<long long int>(copy_riter->size));

                                changed_size  -= (tmp_cur_untreated_iter->start - changed_start);
                                changed_start  = tmp_cur_untreated_iter->start;
                                include_prev_copy_part = true;
                            }
                        }
                        if(!include_prev_copy_part){
                            //
                            // If this area is not unified, need to download this area
                            //
                            S3FS_PRN_DBG("To download: start=%lld, size=%lld", static_cast<long long int>(tmp_cur_start), static_cast<long long int>(tmp_cur_untreated_iter->start - tmp_cur_start));
                            to_download_list.push_back(mp_part(tmp_cur_start, tmp_cur_untreated_iter->start - tmp_cur_start));
                        }
                    }
                    //
                    // Set next start position
                    //
                    tmp_cur_size  = (tmp_cur_start + tmp_cur_size) - (tmp_cur_untreated_iter->start + tmp_cur_untreated_iter->size);
                    tmp_cur_start = tmp_cur_untreated_iter->start + tmp_cur_untreated_iter->size;
                }

                //
                // Add download area to list, if remaining size
                //
                if(0 < tmp_cur_size){
                    S3FS_PRN_DBG("To download: start=%lld, size=%lld", static_cast<long long int>(tmp_cur_start), static_cast<long long int>(tmp_cur_size));
                    to_download_list.push_back(mp_part(tmp_cur_start, tmp_cur_size));
                }

                //
                // Set upload area(whole of area) to list
                //
                S3FS_PRN_DBG("To upload: start=%lld, size=%lld", static_cast<long long int>(changed_start), static_cast<long long int>(changed_size));
                to_upload_list.push_back(mp_part(changed_start, changed_size, part_num));
            }
        }
    }
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
