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

#ifndef SYNCFILLER_H_
#define SYNCFILLER_H_

#include <string>
#include <mutex>
#include <vector>
#include <set>

#include "s3fs.h"

//----------------------------------------------
// class SyncFiller
//----------------------------------------------
//
// A synchronous class that calls the fuse_fill_dir_t
// function that processes the readdir data
//
class SyncFiller
{
    private:
        mutable std::mutex      filler_lock;
        void*                   filler_buff;
        fuse_fill_dir_t         filler_func;
        std::set<std::string>   filled;

    public:
        explicit SyncFiller(void* buff = nullptr, fuse_fill_dir_t filler = nullptr);
        ~SyncFiller() = default;
        SyncFiller(const SyncFiller&) = delete;
        SyncFiller(SyncFiller&&) = delete;
        SyncFiller& operator=(const SyncFiller&) = delete;
        SyncFiller& operator=(SyncFiller&&) = delete;

        int Fill(const std::string& name, const struct stat *stbuf, off_t off);
        int SufficiencyFill(const std::vector<std::string>& pathlist);
};

#endif // SYNCFILLER_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
