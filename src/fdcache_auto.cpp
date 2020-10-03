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

#include <cstdio>
#include <cstdlib>

#include "common.h"
#include "s3fs.h"
#include "fdcache_auto.h"
#include "fdcache.h"

//------------------------------------------------
// AutoFdEntity methods
//------------------------------------------------
AutoFdEntity::AutoFdEntity() : pFdEntity(NULL)
{
}

// [NOTE]
// The copy constructor should not be called, then this is private method.
// Even if it is called, the consistency of the number of
// references can be maintained, but this case is not assumed.
//
AutoFdEntity::AutoFdEntity(AutoFdEntity& other) : pFdEntity(NULL)
{
    S3FS_PRN_WARN("This method should not be called. Please check the caller.");

    if(other.pFdEntity){
        other.pFdEntity->Dup();
        pFdEntity = other.pFdEntity;
    }
}

AutoFdEntity::~AutoFdEntity()
{
    Close();
}

bool AutoFdEntity::Close()
{
    if(pFdEntity){
        if(!FdManager::get()->Close(pFdEntity)){
            S3FS_PRN_ERR("Failed to close fdentity.");
            return false;
        }
        pFdEntity = NULL;
    }
    return true;
}

// [NOTE]
// This method touches the internal fdentity with.
// This is used to keep the file open.
//
bool AutoFdEntity::Detach()
{
    if(!pFdEntity){
        S3FS_PRN_ERR("Does not have a associated FdEntity.");
        return false;
    }
    pFdEntity = NULL;
    return true;
}

// [NOTE]
// This method calls the FdManager method without incrementing the
// reference count.
// This means that it will only be used to map to a file descriptor
// that was already open.
//
FdEntity* AutoFdEntity::GetFdEntity(const char* path, int existfd, bool increase_ref)
{
    Close();

    if(NULL == (pFdEntity = FdManager::get()->GetFdEntity(path, existfd, increase_ref))){
        S3FS_PRN_DBG("Could not find fd(file=%s, existfd=%d)", path, existfd);
        return NULL;
    }
    return pFdEntity;
}

FdEntity* AutoFdEntity::Open(const char* path, headers_t* pmeta, off_t size, time_t time, bool force_tmpfile, bool is_create, bool no_fd_lock_wait)
{
    Close();

    if(NULL == (pFdEntity = FdManager::get()->Open(path, pmeta, size, time, force_tmpfile, is_create, no_fd_lock_wait))){
        return NULL;
    }
    return pFdEntity;
}

FdEntity* AutoFdEntity::ExistOpen(const char* path, int existfd, bool ignore_existfd)
{
    Close();

    if(NULL == (pFdEntity = FdManager::get()->ExistOpen(path, existfd, ignore_existfd))){
        return NULL;
    }
    return pFdEntity;
}

// [NOTE]
// This operator should not be called, then this is private method.
// Even if it is called, the consistency of the number of
// references can be maintained, but this case is not assumed.
//
bool AutoFdEntity::operator=(AutoFdEntity& other)
{
    S3FS_PRN_WARN("This method should not be called. Please check the caller.");

    Close();

    if(other.pFdEntity){
        other.pFdEntity->Dup();
        pFdEntity = other.pFdEntity;
    }
    return true;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
