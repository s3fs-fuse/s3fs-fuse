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

#include "psemaphore.h"
#include "metaheader.h"
#include "autolock.h"
#include "types.h"

class FdEntity;
class UntreatedParts;

//------------------------------------------------
// Structure of parameters to pass to thread
//------------------------------------------------
class PseudoFdInfo;

struct pseudofdinfo_thparam
{
    PseudoFdInfo* ppseudofdinfo;
    std::string   path;
    std::string   upload_id;
    int           upload_fd;
    off_t         start;
    off_t         size;
    bool          is_copy;
    int           part_num;
    etagpair*     petag;

    pseudofdinfo_thparam() : ppseudofdinfo(NULL), path(""), upload_id(""), upload_fd(-1), start(0), size(0), is_copy(false), part_num(-1), petag(NULL) {}
};

//------------------------------------------------
// Class PseudoFdInfo
//------------------------------------------------
class PseudoFdInfo
{
    private:
        static int              max_threads;
        static int              opt_max_threads;    // for option value

        int                     pseudo_fd;
        int                     physical_fd;
        int                     flags;              // flags at open
        std::string             upload_id;
        int                     upload_fd;          // duplicated fd for uploading
        filepart_list_t         upload_list;
        petagpool               etag_entities;      // list of etag string and part number entities(to maintain the etag entity even if MPPART_INFO is destroyed)
        bool                    is_lock_init;
        pthread_mutex_t         upload_list_lock;   // protects upload_id and upload_list
        Semaphore               uploaded_sem;       // use a semaphore to trigger an upload completion like event flag
        volatile int            instruct_count;     // number of instructions for processing by threads
        volatile int            completed_count;    // number of completed processes by thread
        int                     last_result;        // the result of thread processing

    private:
        static void* MultipartUploadThreadWorker(void* arg);

        bool Clear();
        void CloseUploadFd();
        bool OpenUploadFd(AutoLock::Type type = AutoLock::NONE);
        bool ResetUploadInfo(AutoLock::Type type);
        bool RowInitialUploadInfo(const std::string& id, bool is_cancel_mp, AutoLock::Type type);
        bool CompleteInstruction(int result, AutoLock::Type type = AutoLock::NONE);
        bool ParallelMultipartUpload(const char* path, const mp_part_list_t& mplist, bool is_copy, AutoLock::Type type = AutoLock::NONE);
        bool InsertUploadPart(off_t start, off_t size, int part_num, bool is_copy, etagpair** ppetag, AutoLock::Type type = AutoLock::NONE);
        int WaitAllThreadsExit();
        bool CancelAllThreads();
        bool ExtractUploadPartsFromUntreatedArea(off_t& untreated_start, off_t& untreated_size, mp_part_list_t& to_upload_list, filepart_list_t& cancel_upload_list, off_t max_mp_size);

    public:
        PseudoFdInfo(int fd = -1, int open_flags = 0);
        ~PseudoFdInfo();

        int GetPhysicalFd() const { return physical_fd; }
        int GetPseudoFd() const { return pseudo_fd; }
        int GetFlags() const { return flags; }
        bool Writable() const;
        bool Readable() const;

        bool Set(int fd, int open_flags);
        bool ClearUploadInfo(bool is_cancel_mp = false);
        bool InitialUploadInfo(const std::string& id){ return RowInitialUploadInfo(id, true, AutoLock::NONE); }

        bool IsUploading() const { return !upload_id.empty(); }
        bool GetUploadId(std::string& id) const;
        bool GetEtaglist(etaglist_t& list);

        bool AppendUploadPart(off_t start, off_t size, bool is_copy = false, etagpair** ppetag = NULL);

        bool ParallelMultipartUploadAll(const char* path, const mp_part_list_t& upload_list, const mp_part_list_t& copy_list, int& result);

        ssize_t UploadBoundaryLastUntreatedArea(const char* path, headers_t& meta, FdEntity* pfdent);
        bool ExtractUploadPartsFromAllArea(UntreatedParts& untreated_list, mp_part_list_t& to_upload_list, mp_part_list_t& to_copy_list, mp_part_list_t& to_download_list, filepart_list_t& cancel_upload_list, off_t max_mp_size, off_t file_size, bool use_copy);
};

typedef std::map<int, class PseudoFdInfo*> fdinfo_map_t;

#endif // S3FS_FDCACHE_FDINFO_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
