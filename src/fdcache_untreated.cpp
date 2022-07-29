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

#include <cstdlib>

#include "s3fs_logger.h"
#include "fdcache_untreated.h"
#include "autolock.h"

//------------------------------------------------
// UntreatedParts methods
//------------------------------------------------
UntreatedParts::UntreatedParts() : last_tag(0) //, is_lock_init(false)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif

    int result;
    if(0 != (result = pthread_mutex_init(&untreated_list_lock, &attr))){
        S3FS_PRN_CRIT("failed to init untreated_list_lock: %d", result);
        abort();
    }
    is_lock_init = true;
}

UntreatedParts::~UntreatedParts()
{
    if(is_lock_init){
        int result;
        if(0 != (result = pthread_mutex_destroy(&untreated_list_lock))){
            S3FS_PRN_CRIT("failed to destroy untreated_list_lock: %d", result);
            abort();
        }
        is_lock_init = false;
    }
}

bool UntreatedParts::empty()
{
    AutoLock auto_lock(&untreated_list_lock);
    return untreated_list.empty();
}

bool UntreatedParts::AddPart(off_t start, off_t size)
{
    if(start < 0 || size <= 0){
        S3FS_PRN_ERR("Paramter are wrong(start=%lld, size=%lld).", static_cast<long long int>(start), static_cast<long long int>(size));
        return false;
    }
    AutoLock auto_lock(&untreated_list_lock);

    ++last_tag;

    // Check the overlap with the existing part and add the part.
    for(untreated_list_t::iterator iter = untreated_list.begin(); iter != untreated_list.end(); ++iter){
        if(iter->stretch(start, size, last_tag)){
            // the part was stretched, thus check if it overlaps with next parts
            untreated_list_t::iterator niter = iter;
            for(++niter; niter != untreated_list.end(); ){
                if(!iter->stretch(niter->start, niter->size, last_tag)){
                    // This next part does not overlap with the current part
                    break;
                }
                // Since the parts overlap and the current part is stretched, delete this next part.
                niter = untreated_list.erase(niter);
            }
            // success to stretch and compress existed parts
            return true;

        }else if((start + size) < iter->start){
            // The part to add should be inserted before the current part.
            untreated_list.insert(iter, untreatedpart(start, size, last_tag));
            // success to stretch and compress existed parts
            return true;
        }
    }
    // There are no overlapping parts in the untreated_list, then add the part at end of list
    untreated_list.push_back(untreatedpart(start, size, last_tag));
    return true;
}

bool UntreatedParts::RowGetPart(off_t& start, off_t& size, off_t max_size, off_t min_size, bool lastpart)
{
    if(max_size <= 0 || min_size < 0 || max_size < min_size){
        S3FS_PRN_ERR("Paramter are wrong(max_size=%lld, min_size=%lld).", static_cast<long long int>(max_size), static_cast<long long int>(min_size));
        return false;
    }
    AutoLock auto_lock(&untreated_list_lock);

    // Check the overlap with the existing part and add the part.
    for(untreated_list_t::iterator iter = untreated_list.begin(); iter != untreated_list.end(); ++iter){
        if(!lastpart || iter->untreated_tag == last_tag){
            if(min_size <= iter->size){
                if(iter->size <= max_size){
                    // whole part( min <= part size <= max )
                    start = iter->start;
                    size  = iter->size;
                }else{
                    // Partially take out part( max < part size )
                    start = iter->start;
                    size  = max_size;
                }
                return true;
            }else{
                if(lastpart){
                    return false;
                }
            }
        }
    }
    return false;
}

// [NOTE]
// If size is specified as 0, all areas(parts) after start will be deleted.
//
bool UntreatedParts::ClearParts(off_t start, off_t size)
{
    if(start < 0 || size < 0){
        S3FS_PRN_ERR("Paramter are wrong(start=%lld, size=%lld).", static_cast<long long int>(start), static_cast<long long int>(size));
        return false;
    }
    AutoLock auto_lock(&untreated_list_lock);

    if(untreated_list.empty()){
        return true;
    }

    // Check the overlap with the existing part.
    for(untreated_list_t::iterator iter = untreated_list.begin(); iter != untreated_list.end(); ){
        if(0 != size && (start + size) <= iter->start){
            // clear area is in front of iter area, no more to do.
            break;
        }else if(start <= iter->start){
            if(0 != size && (start + size) <= (iter->start + iter->size)){
                // clear area overlaps with iter area(on the start side)
                iter->size  = (iter->start + iter->size) - (start + size);
                iter->start = start + size;
                if(0 == iter->size){
                    iter = untreated_list.erase(iter);
                }
            }else{
                // clear area overlaps with all of iter area
                iter = untreated_list.erase(iter);
            }
        }else if(start < (iter->start + iter->size)){
            // clear area overlaps with iter area(on the end side)
            if(0 == size || (iter->start + iter->size) <= (start + size)){
                // start to iter->end is clear
                iter->size = start - iter->start;
            }else{
                // parse current part
                iter->size = start - iter->start;

                // add new part
                off_t next_start = start + size;
                off_t next_size  = (iter->start + iter->size) - (start + size);
                long  next_tag   = iter->untreated_tag;
                ++iter;
                iter = untreated_list.insert(iter, untreatedpart(next_start, next_size, next_tag));
                ++iter;
            }
        }else{
            // clear area is in behind of iter area
            ++iter;
        }
    }
    return true;
}

//
// Update the last updated Untreated part
//
bool UntreatedParts::GetLastUpdatePart(off_t& start, off_t& size)
{
    AutoLock auto_lock(&untreated_list_lock);

    for(untreated_list_t::const_iterator iter = untreated_list.begin(); iter != untreated_list.end(); ++iter){
        if(iter->untreated_tag == last_tag){
            start = iter->start;
            size  = iter->size;
            return true;
        }
    }
    return false;
}

//
// Replaces the last updated Untreated part.
//
// [NOTE]
// If size <= 0, delete that part
//
bool UntreatedParts::ReplaceLastUpdatePart(off_t start, off_t size)
{
    AutoLock auto_lock(&untreated_list_lock);

    for(untreated_list_t::iterator iter = untreated_list.begin(); iter != untreated_list.end(); ++iter){
        if(iter->untreated_tag == last_tag){
            if(0 < size){
                iter->start = start;
                iter->size  = size;
            }else{
                iter = untreated_list.erase(iter);
            }
            return true;
        }
    }
    return false;
}

//
// Remove the last updated Untreated part.
//
bool UntreatedParts::RemoveLastUpdatePart()
{
    AutoLock auto_lock(&untreated_list_lock);

    for(untreated_list_t::iterator iter = untreated_list.begin(); iter != untreated_list.end(); ++iter){
        if(iter->untreated_tag == last_tag){
            untreated_list.erase(iter);
            return true;
        }
    }
    return false;
}

//
// Duplicate the internally untreated_list.
//
bool UntreatedParts::Duplicate(untreated_list_t& list)
{
    AutoLock auto_lock(&untreated_list_lock);

    list = untreated_list;
    return true;
}

void UntreatedParts::Dump()
{
    AutoLock auto_lock(&untreated_list_lock);

    S3FS_PRN_DBG("untreated list = [");
    for(untreated_list_t::const_iterator iter = untreated_list.begin(); iter != untreated_list.end(); ++iter){
        S3FS_PRN_DBG("    {%014lld - %014lld : tag=%ld}", static_cast<long long int>(iter->start), static_cast<long long int>(iter->size), iter->untreated_tag);
    }
    S3FS_PRN_DBG("]");
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
