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

#include <algorithm>
#include <cstdlib>
#include <vector>

#include "s3fs_logger.h"
#include "fdcache_pseudofd.h"
#include "autolock.h"

//------------------------------------------------
// Symbols
//------------------------------------------------
// [NOTE]
// The minimum pseudo fd value starts 2.
// This is to avoid mistakes for 0(stdout) and 1(stderr), which are usually used.
//
#define MIN_PSEUDOFD_NUMBER     2

//------------------------------------------------
// PseudoFdManager class methods
//------------------------------------------------
PseudoFdManager& PseudoFdManager::GetManager()
{
    static PseudoFdManager singleton;
    return singleton;
}

int PseudoFdManager::Get()
{
    return (PseudoFdManager::GetManager()).CreatePseudoFd();
}

bool PseudoFdManager::Release(int fd)
{
    return (PseudoFdManager::GetManager()).ReleasePseudoFd(fd);
}

//------------------------------------------------
// PseudoFdManager methods
//------------------------------------------------
PseudoFdManager::PseudoFdManager() : is_lock_init(false)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
    int result;
    if(0 != (result = pthread_mutex_init(&pseudofd_list_lock, &attr))){
        S3FS_PRN_CRIT("failed to init pseudofd_list_lock: %d", result);
        abort();
    }
    is_lock_init = true;
}

PseudoFdManager::~PseudoFdManager()
{
    if(is_lock_init){
      int result;
      if(0 != (result = pthread_mutex_destroy(&pseudofd_list_lock))){
          S3FS_PRN_CRIT("failed to destroy pseudofd_list_lock: %d", result);
          abort();
      }
      is_lock_init = false;
    }
}

int PseudoFdManager::GetUnusedMinPseudoFd() const
{
    int min_fd = MIN_PSEUDOFD_NUMBER;

    // Look for the first discontinuous value.
    for(pseudofd_list_t::const_iterator iter = pseudofd_list.begin(); iter != pseudofd_list.end(); ++iter){
        if(min_fd == (*iter)){
            ++min_fd;
        }else if(min_fd < (*iter)){
            break;
        }
    }
    return min_fd;
}

int PseudoFdManager::CreatePseudoFd()
{
    AutoLock auto_lock(&pseudofd_list_lock);

    int new_fd = PseudoFdManager::GetUnusedMinPseudoFd();
    pseudofd_list.push_back(new_fd);
    std::sort(pseudofd_list.begin(), pseudofd_list.end());

    return new_fd;
}

bool PseudoFdManager::ReleasePseudoFd(int fd)
{
    AutoLock auto_lock(&pseudofd_list_lock);

    for(pseudofd_list_t::iterator iter = pseudofd_list.begin(); iter != pseudofd_list.end(); ++iter){
        if(fd == (*iter)){
            pseudofd_list.erase(iter);
            return true;
        }
    }
    return false;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
