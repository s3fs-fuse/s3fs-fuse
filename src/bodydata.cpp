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
#include <cstring>

#include "s3fs_logger.h"
#include "bodydata.h"

//-------------------------------------------------------------------
// Variables
//-------------------------------------------------------------------
static const int BODYDATA_RESIZE_APPEND_MIN = 1024;
static const int BODYDATA_RESIZE_APPEND_MID = 1024 * 1024;
static const int BODYDATA_RESIZE_APPEND_MAX = 10 * 1024 * 1024;

//-------------------------------------------------------------------
// Utility Functions
//-------------------------------------------------------------------
static size_t adjust_block(size_t bytes, size_t block)
{
    return ((bytes / block) + ((bytes % block) ? 1 : 0)) * block;
}

//-------------------------------------------------------------------
// Class BodyData
//-------------------------------------------------------------------
bool BodyData::Resize(size_t addbytes)
{
    if(IsSafeSize(addbytes)){
        return true;
    }

    // New size
    size_t need_size = adjust_block((lastpos + addbytes + 1) - bufsize, sizeof(off_t));

    if(BODYDATA_RESIZE_APPEND_MAX < bufsize){
        need_size = (BODYDATA_RESIZE_APPEND_MAX < need_size ? need_size : BODYDATA_RESIZE_APPEND_MAX);
    }else if(BODYDATA_RESIZE_APPEND_MID < bufsize){
        need_size = (BODYDATA_RESIZE_APPEND_MID < need_size ? need_size : BODYDATA_RESIZE_APPEND_MID);
    }else if(BODYDATA_RESIZE_APPEND_MIN < bufsize){
        need_size = ((bufsize * 2) < need_size ? need_size : (bufsize * 2));
    }else{
        need_size = (BODYDATA_RESIZE_APPEND_MIN < need_size ? need_size : BODYDATA_RESIZE_APPEND_MIN);
    }
    // realloc
    char* newtext;
    if(NULL == (newtext = reinterpret_cast<char*>(realloc(text, (bufsize + need_size))))){
        S3FS_PRN_CRIT("not enough memory (realloc returned NULL)");
        free(text);
        text = NULL;
        return false;
    }
    text     = newtext;
    bufsize += need_size;

    return true;
}

void BodyData::Clear()
{
    if(text){
        free(text);
        text = NULL;
    }
    lastpos = 0;
    bufsize = 0;
}

bool BodyData::Append(void* ptr, size_t bytes)
{
    if(!ptr){
        return false;
    }
    if(0 == bytes){
        return true;
    }
    if(!Resize(bytes)){
        return false;
    }
    memcpy(&text[lastpos], ptr, bytes);
    lastpos += bytes;
    text[lastpos] = '\0';

    return true;
}

const char* BodyData::str() const
{
    if(!text){
        static const char strnull[] = "";
        return strnull;
    }
    return text;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
