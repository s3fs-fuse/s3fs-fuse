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

#include "s3fs_logger.h"
#include "curl_handlerpool.h"

//-------------------------------------------------------------------
// Class CurlHandlerPool
//-------------------------------------------------------------------
bool CurlHandlerPool::Init()
{
    for(int cnt = 0; cnt < mMaxHandlers; ++cnt){
        CURL* hCurl = curl_easy_init();
        if(!hCurl){
            S3FS_PRN_ERR("Init curl handlers pool failed");
            Destroy();
            return false;
        }
        mPool.push_back(hCurl);
    }
    return true;
}

bool CurlHandlerPool::Destroy()
{
    const std::lock_guard<std::mutex> lock(mLock);

    while(!mPool.empty()){
        CURL* hCurl = mPool.back();
        mPool.pop_back();
        if(hCurl){
            curl_easy_cleanup(hCurl);
        }
    }
    return true;
}

CURL* CurlHandlerPool::GetHandler(bool only_pool)
{
    const std::lock_guard<std::mutex> lock(mLock);

    CURL* hCurl = nullptr;

    if(!mPool.empty()){
        hCurl = mPool.back();
        mPool.pop_back();
        S3FS_PRN_DBG("Get handler from pool: rest = %d", static_cast<int>(mPool.size()));
    }
    if(only_pool){
        return hCurl;
    }
    if(!hCurl){
        S3FS_PRN_INFO("Pool empty: force to create new handler");
        hCurl = curl_easy_init();
    }
    return hCurl;
}

void CurlHandlerPool::ReturnHandler(CURL* hCurl, bool restore_pool)
{
    if(!hCurl){
      return;
    }
    const std::lock_guard<std::mutex> lock(mLock);

    if(restore_pool){
        S3FS_PRN_DBG("Return handler to pool");
        mPool.push_back(hCurl);

        while(mMaxHandlers < static_cast<int>(mPool.size())){
            CURL* hOldCurl = mPool.front();
            mPool.pop_front();
            if(hOldCurl){
                S3FS_PRN_INFO("Pool full: destroy the oldest handler");
                curl_easy_cleanup(hOldCurl);
            }
        }
    }else{
        S3FS_PRN_INFO("Pool full: destroy the handler");
        curl_easy_cleanup(hCurl);
    }
}

void CurlHandlerPool::ResetHandler(CURL* hCurl)
{
    if(!hCurl){
      return;
    }
    const std::lock_guard<std::mutex> lock(mLock);

    curl_easy_reset(hCurl);
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
