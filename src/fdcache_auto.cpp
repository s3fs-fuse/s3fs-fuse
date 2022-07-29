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

#include "s3fs_logger.h"
#include "fdcache_auto.h"
#include "fdcache.h"

//------------------------------------------------
// AutoFdEntity methods
//------------------------------------------------
AutoFdEntity::AutoFdEntity() : pFdEntity(NULL), pseudo_fd(-1)
{
}

// [NOTE]
// The copy constructor should not be called, then this is private method.
// Even if it is called, the consistency of the number of
// references can be maintained, but this case is not assumed.
//
AutoFdEntity::AutoFdEntity(AutoFdEntity& other) : pFdEntity(NULL), pseudo_fd(-1)
{
    S3FS_PRN_WARN("This method should not be called. Please check the caller.");

    if(other.pFdEntity){
        if(-1 != (pseudo_fd = other.pFdEntity->Dup(other.pseudo_fd))){
            pFdEntity = other.pFdEntity;
        }else{
            S3FS_PRN_ERR("Failed duplicating fd in AutoFdEntity.");
        }
    }
}

AutoFdEntity::~AutoFdEntity()
{
    Close();
}

bool AutoFdEntity::Close()
{
    if(pFdEntity){
        if(!FdManager::get()->Close(pFdEntity, pseudo_fd)){
            S3FS_PRN_ERR("Failed to close fdentity.");
            return false;
        }
        pFdEntity = NULL;
        pseudo_fd = -1;
    }
    return true;
}

// [NOTE]
// This method touches the internal fdentity with.
// This is used to keep the file open.
//
int AutoFdEntity::Detach()
{
    if(!pFdEntity){
        S3FS_PRN_ERR("Does not have a associated FdEntity.");
        return -1;
    }
    int fd    = pseudo_fd;
    pseudo_fd = -1;
    pFdEntity = NULL;

    return fd;
}

FdEntity* AutoFdEntity::Attach(const char* path, int existfd)
{
    Close();

    if(NULL == (pFdEntity = FdManager::get()->GetFdEntity(path, existfd, false))){
        S3FS_PRN_DBG("Could not find fd entity object(file=%s, pseudo_fd=%d)", path, existfd);
        return NULL;
    }
    pseudo_fd = existfd;
    return pFdEntity;
}

FdEntity* AutoFdEntity::Open(const char* path, headers_t* pmeta, off_t size, const struct timespec& ts_mctime, int flags, bool force_tmpfile, bool is_create, bool ignore_modify, AutoLock::Type type)
{
    Close();

    if(NULL == (pFdEntity = FdManager::get()->Open(pseudo_fd, path, pmeta, size, ts_mctime, flags, force_tmpfile, is_create, ignore_modify, type))){
        pseudo_fd = -1;
        return NULL;
    }
    return pFdEntity;
}

// [NOTE]
// the fd obtained by this method is not a newly created pseudo fd.
//
FdEntity* AutoFdEntity::GetExistFdEntity(const char* path, int existfd)
{
    Close();

    FdEntity* ent;
    if(NULL == (ent = FdManager::get()->GetExistFdEntity(path, existfd))){
        return NULL;
    }
    return ent;
}

FdEntity* AutoFdEntity::OpenExistFdEntity(const char* path, int flags)
{
    Close();

    if(NULL == (pFdEntity = FdManager::get()->OpenExistFdEntity(path, pseudo_fd, flags))){
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
        if(-1 != (pseudo_fd = other.pFdEntity->Dup(other.pseudo_fd))){
            pFdEntity = other.pFdEntity;
        }else{
            S3FS_PRN_ERR("Failed duplicating fd in AutoFdEntity.");
            return false;
        }
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
