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

#include <cerrno>

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

// The first entry added for a name is kept.
void SyncFiller::Fill(const std::string& name, const struct stat *stbuf)
{
    const std::lock_guard<std::mutex> lock(filler_lock);

    if(stbuf){
        entries.emplace(name, *stbuf);
    }else{
        entries.emplace(name, std::nullopt);
    }
}

void SyncFiller::SufficiencyFill(const std::vector<std::string>& pathlist)
{
    const std::lock_guard<std::mutex> lock(filler_lock);

    for(const auto& path : pathlist){
        entries.emplace(path, std::nullopt);
    }
}

//
// See. prototype fuse_fill_dir_t in fuse.h
//
int SyncFiller::Flush()
{
    const std::lock_guard<std::mutex> lock(filler_lock);

    for(const auto& [name, st] : entries){
        // The non-seekable readdir filler only fails when it cannot allocate memory.
        if(0 != filler_func(filler_buff, name.c_str(), st.has_value() ? &st.value() : nullptr, 0, S3FS_FUSE_FILL_DIR_DEFAULTS)){
            return -ENOMEM;
        }
    }
    entries.clear();
    return 0;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
