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

//------------------------------------------------
// Structure
//------------------------------------------------
typedef struct _mppart_info
{
    off_t       start;
    size_t      size;
    bool        is_copy;
    std::string etag;

    _mppart_info(off_t part_start = -1, off_t part_size = 0, bool is_copy_part = false, const char* petag = NULL) : start(part_start), size(part_size), is_copy(is_copy_part), etag(NULL == petag ? "" : petag) {}

}MPPART_INFO;

typedef std::list<MPPART_INFO> mppart_list_t;

//------------------------------------------------
// Class PseudoFdInfo
//------------------------------------------------
class PseudoFdInfo
{
    private:
        int             pseudo_fd;
        int             physical_fd;
        int             flags;              // flags at open
        std::string     upload_id;
        mppart_list_t   upload_list;
        off_t           untreated_start;    // untreated start position
        off_t           untreated_size;     // untreated size

        bool            is_lock_init;
        pthread_mutex_t upload_list_lock;   // protects upload_id and upload_list

    private:
        bool Clear();

    public:
        PseudoFdInfo(int fd = -1, int open_flags = 0);
        ~PseudoFdInfo();

        int GetPhysicalFd() const { return physical_fd; }
        int GetPseudoFd() const { return pseudo_fd; }
        int GetFlags() const { return flags; }
        bool Writable() const;
        bool Readable() const;

        bool Set(int fd, int open_flags);
        bool ClearUploadInfo(bool is_clear_part = false, bool lock_already_held = false);
        bool InitialUploadInfo(const std::string& id);

        bool IsUploading() const { return !upload_id.empty(); }
        bool GetUploadId(std::string& id) const;
        bool GetEtaglist(etaglist_t& list);

        bool AppendUploadPart(off_t start, off_t size, bool is_copy = false, int* ppartnum = NULL, std::string** ppetag = NULL);

        void ClearUntreated(bool lock_already_held = false);
        bool GetUntreated(off_t& start, off_t& size);
        bool SetUntreated(off_t start, off_t size);
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
