/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2007 Randy Rizun <rrizun@gmail.com>
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

#ifndef S3FS_FDCACHE_FDINFO_H_
#define S3FS_FDCACHE_FDINFO_H_

#include <memory>
#include <mutex>
#include <string>

#include "common.h"
#include "fdcache_entity.h"
#include "psemaphore.h"
#include "metaheader.h"
#include "types.h"

class UntreatedParts;

//------------------------------------------------
// Class PseudoFdInfo
//------------------------------------------------
class PseudoFdInfo
{
    private:
        int                     pseudo_fd;
        int                     physical_fd;
        int                     flags;              // flags at open
        mutable std::mutex      upload_list_lock;   // protects upload_id/fd, upload_list, etc.
        std::string             upload_id       GUARDED_BY(upload_list_lock);   //
        int                     upload_fd       GUARDED_BY(upload_list_lock);   // duplicated fd for uploading
        filepart_list_t         upload_list     GUARDED_BY(upload_list_lock);
        petagpool               etag_entities   GUARDED_BY(upload_list_lock);   // list of etag string and part number entities(to maintain the etag entity even if MPPART_INFO is destroyed)
        int                     instruct_count  GUARDED_BY(upload_list_lock);   // number of instructions for processing by threads
        int                     completed_count GUARDED_BY(upload_list_lock);   // number of completed processes by thread
        int                     last_result     GUARDED_BY(upload_list_lock);   // the result of thread processing
        Semaphore               uploaded_sem;                                   // use a semaphore to trigger an upload completion like event flag

    private:
        static void* MultipartUploadThreadWorker(void* arg);

        bool Clear();
        void CloseUploadFd();
        bool OpenUploadFd();
        bool ResetUploadInfo() REQUIRES(upload_list_lock);
        bool RowInitialUploadInfo(const std::string& id, bool is_cancel_mp);
        void IncreaseInstructionCount();
        bool CompleteInstruction(int result) REQUIRES(upload_list_lock);
        bool GetUploadInfo(std::string& id, int& fd) const;
        bool ParallelMultipartUpload(const char* path, const mp_part_list_t& mplist, bool is_copy);
        bool InsertUploadPart(off_t start, off_t size, int part_num, bool is_copy, etagpair** ppetag);
        bool PreMultipartUploadRequest(const std::string& strpath, const headers_t& meta);
        bool CancelAllThreads();
        bool ExtractUploadPartsFromUntreatedArea(off_t untreated_start, off_t untreated_size, mp_part_list_t& to_upload_list, filepart_list_t& cancel_upload_list, off_t max_mp_size);
        bool IsUploadingHasLock() const REQUIRES(upload_list_lock);

    public:
        explicit PseudoFdInfo(int fd = -1, int open_flags = 0);
        ~PseudoFdInfo();
        PseudoFdInfo(const PseudoFdInfo&) = delete;
        PseudoFdInfo(PseudoFdInfo&&) = delete;
        PseudoFdInfo& operator=(const PseudoFdInfo&) = delete;
        PseudoFdInfo& operator=(PseudoFdInfo&&) = delete;

        int GetPhysicalFd() const { return physical_fd; }
        int GetPseudoFd() const { return pseudo_fd; }
        int GetFlags() const { return flags; }
        bool Writable() const;
        bool Readable() const;

        bool Set(int fd, int open_flags);
        bool ClearUploadInfo(bool is_cancel_mp = false);
        bool InitialUploadInfo(const std::string& id){ return RowInitialUploadInfo(id, true); }

        bool IsUploading() const;
        bool GetUploadId(std::string& id) const;
        bool GetEtaglist(etaglist_t& list) const;

        bool AppendUploadPart(off_t start, off_t size, bool is_copy = false, etagpair** ppetag = nullptr);

        bool ParallelMultipartUploadAll(const char* path, const mp_part_list_t& to_upload_list, const mp_part_list_t& copy_list, int& result);

        int WaitAllThreadsExit();
        ssize_t UploadBoundaryLastUntreatedArea(const char* path, headers_t& meta, FdEntity* pfdent) REQUIRES(pfdent->GetMutex());
        bool ExtractUploadPartsFromAllArea(UntreatedParts& untreated_list, mp_part_list_t& to_upload_list, mp_part_list_t& to_copy_list, mp_part_list_t& to_download_list, filepart_list_t& cancel_upload_list, bool& wait_upload_complete, off_t max_mp_size, off_t file_size, bool use_copy);
};

typedef std::map<int, std::unique_ptr<PseudoFdInfo>> fdinfo_map_t;

#endif // S3FS_FDCACHE_FDINFO_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
