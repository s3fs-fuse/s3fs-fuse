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

#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
#include <sys/stat.h>

#include "s3fs.h"  // NOLINT(misc-include-cleaner)

//----------------------------------------------
// class SyncFiller
//----------------------------------------------
//
// Collects the entries of a readdir from several threads and passes
// them to the fuse_fill_dir_t function in name order.
//
// [NOTE]
// The order must not depend on which HEAD request finishes first.
// FUSE-T calls readdir again for each NFS READDIR reply and takes the
// entries after the position the previous reply ended at, so listings
// in different orders lose and repeat entries.
// See https://github.com/macos-fuse-t/fuse-t/issues/136
//
class SyncFiller
{
    private:
        mutable std::mutex                                  filler_lock;
        void*                                               filler_buff;
        fuse_fill_dir_t                                     filler_func;
        std::map<std::string, std::optional<struct stat>>   entries;

    public:
        explicit SyncFiller(void* buff = nullptr, fuse_fill_dir_t filler = nullptr);
        ~SyncFiller() = default;
        SyncFiller(const SyncFiller&) = delete;
        SyncFiller(SyncFiller&&) = delete;
        SyncFiller& operator=(const SyncFiller&) = delete;
        SyncFiller& operator=(SyncFiller&&) = delete;

        void Fill(const std::string& name, const struct stat *stbuf);
        void SufficiencyFill(const std::vector<std::string>& pathlist);
        [[nodiscard]] int Flush();
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
