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
#include <cerrno>

#include "autolock.h"
#include "s3fs_logger.h"

//-------------------------------------------------------------------
// Class AutoLock
//-------------------------------------------------------------------
AutoLock::AutoLock(pthread_mutex_t* pmutex, Type type) : auto_mutex(pmutex)
{
    if (type == ALREADY_LOCKED) {
        is_lock_acquired = false;
    } else if (type == NO_WAIT) {
        int result = pthread_mutex_trylock(auto_mutex);
        if(result == 0){
            is_lock_acquired = true;
        }else if(result == EBUSY){
            is_lock_acquired = false;
        }else{
            S3FS_PRN_CRIT("pthread_mutex_trylock returned: %d", result);
            abort();
        }
    } else {
        int result = pthread_mutex_lock(auto_mutex);
        if(result == 0){
            is_lock_acquired = true;
        }else{
            S3FS_PRN_CRIT("pthread_mutex_lock returned: %d", result);
            abort();
        }
    }
}

bool AutoLock::isLockAcquired() const
{
    return is_lock_acquired;
}

AutoLock::~AutoLock()
{
    if (is_lock_acquired) {
        int result = pthread_mutex_unlock(auto_mutex);
        if(result != 0){
            S3FS_PRN_CRIT("pthread_mutex_unlock returned: %d", result);
            abort();
        }
    }
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
