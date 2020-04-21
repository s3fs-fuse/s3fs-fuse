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

#ifndef S3FS_FDCACHE_UNTREATED_H_
#define S3FS_FDCACHE_UNTREATED_H_

#include "common.h"
#include "types.h"

//------------------------------------------------
// Class UntreatedParts
//------------------------------------------------
class UntreatedParts
{
    private:
        pthread_mutex_t  untreated_list_lock;   // protects untreated_list
        bool             is_lock_init;

        untreated_list_t untreated_list;
        long             last_tag;              // [NOTE] Use this to identify the latest updated part.

    private:
        bool RowGetPart(off_t& start, off_t& size, off_t max_size, off_t min_size, bool lastpart);

    public:
        UntreatedParts();
        ~UntreatedParts();

        bool empty();

        bool AddPart(off_t start, off_t size);

        // [NOTE]
        // The following method does not return parts smaller than mini_size.
        // You can avoid it by setting min_size to 0.
        //
        bool GetPart(off_t& start, off_t& size, off_t max_size, off_t min_size = MIN_MULTIPART_SIZE) { return RowGetPart(start, size, max_size, min_size, false); }
        bool GetLastUpdatedPart(off_t& start, off_t& size, off_t max_size, off_t min_size = MIN_MULTIPART_SIZE) { return RowGetPart(start, size, max_size, min_size, true); }

        bool TakeoutPart(off_t& start, off_t& size, off_t max_size, off_t min_size = MIN_MULTIPART_SIZE);
        bool TakeoutPartFromBegin(off_t& start, off_t& size, off_t max_size);

        bool ClearParts(off_t start, off_t size);
        bool ClearAll() { return ClearParts(0, 0); }
};

#endif // S3FS_FDCACHE_UNTREATED_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
