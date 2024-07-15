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

#include <cstdio>
#include <cstdlib>

#include "s3fs_logger.h"
#include "syncfiller.h"

//-------------------------------------------------------------------
// Class SyncFiller
//-------------------------------------------------------------------
SyncFiller::SyncFiller(void* buff, fuse_fill_dir_t filler) : filler_buff(buff), filler_func(filler)
{
    if(!filler_buff || !filler_func){
        S3FS_PRN_CRIT("Internal error: SyncFiller constructor parameter is critical value.");
        abort();
    }
}

//
// See. prototype fuse_fill_dir_t in fuse.h
//
int SyncFiller::Fill(const std::string& name, const struct stat *stbuf, off_t off)
{
    const std::lock_guard<std::mutex> lock(filler_lock);

    int result = 0;
    if(filled.insert(name).second){
        result = filler_func(filler_buff, name.c_str(), stbuf, off);
    }
    return result;
}

int SyncFiller::SufficiencyFill(const std::vector<std::string>& pathlist)
{
    const std::lock_guard<std::mutex> lock(filler_lock);

    int result = 0;
    for(auto it = pathlist.cbegin(); it != pathlist.cend(); ++it) {
        if(filled.insert(*it).second){
            if(0 != filler_func(filler_buff, it->c_str(), nullptr, 0)){
                result = 1;
            }
        }
    }
    return result;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
