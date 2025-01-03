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

#include "common.h"
#include "s3fs.h"
#include "s3fs_logger.h"
#include "curl_share.h"

//-------------------------------------------------------------------
// Class S3fsCurlShare
//-------------------------------------------------------------------
bool                                     S3fsCurlShare::is_dns_cache = true;    // default
bool                                     S3fsCurlShare::is_ssl_cache = true;    // default
std::mutex                               S3fsCurlShare::curl_share_lock;
std::map<std::thread::id, CurlSharePtr>  S3fsCurlShare::ShareHandles;
std::map<std::thread::id, ShareLocksPtr> S3fsCurlShare::ShareLocks;

//-------------------------------------------------------------------
// Class methods for S3fsCurlShare
//-------------------------------------------------------------------
bool S3fsCurlShare::SetDnsCache(bool isCache)
{
    bool old = S3fsCurlShare::is_dns_cache;
    S3fsCurlShare::is_dns_cache = isCache;
    return old;
}

bool S3fsCurlShare::SetSslSessionCache(bool isCache)
{
    bool old = S3fsCurlShare::is_ssl_cache;
    S3fsCurlShare::is_ssl_cache = isCache;
    return old;
}

void S3fsCurlShare::LockCurlShare(CURL* handle, curl_lock_data nLockData, curl_lock_access laccess, void* useptr)
{
    auto* pLocks  = static_cast<curl_share_locks*>(useptr);

    if(CURL_LOCK_DATA_DNS == nLockData){
        pLocks->lock_dns.lock();
    }else if(CURL_LOCK_DATA_SSL_SESSION == nLockData){
        pLocks->lock_session.lock();
    }
}

void S3fsCurlShare::UnlockCurlShare(CURL* handle, curl_lock_data nLockData, void* useptr)
{
    auto* pLocks  = static_cast<curl_share_locks*>(useptr);

    if(CURL_LOCK_DATA_DNS == nLockData){
        pLocks->lock_dns.unlock();
    }else if(CURL_LOCK_DATA_SSL_SESSION == nLockData){
        pLocks->lock_session.unlock();
    }
}

bool S3fsCurlShare::SetCurlShareHandle(CURL* hCurl)
{
    if(!hCurl){
        S3FS_PRN_ERR("Curl handle is null");
        return false;
    }

    // get curl share handle
    S3fsCurlShare CurlShareObj;
    CURLSH*       hCurlShare = CurlShareObj.GetCurlShareHandle();
    if(!hCurlShare){
        // a case of not to use CurlShare
        return true;
    }

    // set share handle to curl handle
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_SHARE, hCurlShare)){
        S3FS_PRN_ERR("Failed to set Curl share handle to curl handle.");
        return false;
    }
    return true;
}

bool S3fsCurlShare::DestroyCurlShareHandleForThread()
{
    S3fsCurlShare CurlShareObj;
    CurlShareObj.DestroyCurlShareHandle();
    return true;
}

bool S3fsCurlShare::InitializeCurlShare(const CurlSharePtr& hShare, const ShareLocksPtr& ShareLock)
{
    CURLSHcode nSHCode;

    // set lock handlers
    if(CURLSHE_OK != (nSHCode = curl_share_setopt(hShare.get(), CURLSHOPT_LOCKFUNC, S3fsCurlShare::LockCurlShare))){
        S3FS_PRN_ERR("curl_share_setopt(LOCKFUNC) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
        return false;
    }
    if(CURLSHE_OK != (nSHCode = curl_share_setopt(hShare.get(), CURLSHOPT_UNLOCKFUNC, S3fsCurlShare::UnlockCurlShare))){
        S3FS_PRN_ERR("curl_share_setopt(UNLOCKFUNC) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
        return false;
    }

    // set user data for lock functions
    if(CURLSHE_OK != (nSHCode = curl_share_setopt(hShare.get(), CURLSHOPT_USERDATA, ShareLock.get()))){
        S3FS_PRN_ERR("curl_share_setopt(USERDATA) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
        return false;
    }

    // set share type
    if(S3fsCurlShare::is_dns_cache){
        nSHCode = curl_share_setopt(hShare.get(), CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
        if(CURLSHE_OK != nSHCode && CURLSHE_BAD_OPTION != nSHCode && CURLSHE_NOT_BUILT_IN != nSHCode){
            S3FS_PRN_ERR("curl_share_setopt(DNS) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
            return false;
        }else if(CURLSHE_BAD_OPTION == nSHCode || CURLSHE_NOT_BUILT_IN == nSHCode){
            S3FS_PRN_WARN("curl_share_setopt(DNS) returns %d(%s), but continue without shared dns data.", nSHCode, curl_share_strerror(nSHCode));
        }
    }
    if(S3fsCurlShare::is_ssl_cache){
        nSHCode = curl_share_setopt(hShare.get(), CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
        if(CURLSHE_OK != nSHCode && CURLSHE_BAD_OPTION != nSHCode && CURLSHE_NOT_BUILT_IN != nSHCode){
            S3FS_PRN_ERR("curl_share_setopt(SSL SESSION) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
            return false;
        }else if(CURLSHE_BAD_OPTION == nSHCode || CURLSHE_NOT_BUILT_IN == nSHCode){
            S3FS_PRN_WARN("curl_share_setopt(SSL SESSION) returns %d(%s), but continue without shared ssl session data.", nSHCode, curl_share_strerror(nSHCode));
        }
    }

    return true;
}

//-------------------------------------------------------------------
// Methods for S3fsCurlShare
//-------------------------------------------------------------------
// [NOTE]
// set current thread id(std style) to ThreadId
//
S3fsCurlShare::S3fsCurlShare() : ThreadId(std::this_thread::get_id())
{
}

void S3fsCurlShare::DestroyCurlShareHandle()
{
    if(!S3fsCurlShare::is_dns_cache && !S3fsCurlShare::is_ssl_cache){
        // Any curl share handle does not exist
        return;
    }

    const std::lock_guard<std::mutex> lock(S3fsCurlShare::curl_share_lock);

    // find existed handle and cleanup it
    auto handle_iter = S3fsCurlShare::ShareHandles.find(ThreadId);
    if(handle_iter == S3fsCurlShare::ShareHandles.end()){
        S3FS_PRN_WARN("Not found curl share handle");
    }else{
        S3fsCurlShare::ShareHandles.erase(handle_iter);
    }

    // find lock and cleanup it
    auto locks_iter = S3fsCurlShare::ShareLocks.find(ThreadId);
    if(locks_iter == S3fsCurlShare::ShareLocks.end()){
        S3FS_PRN_WARN("Not found locks of curl share handle");
    }else{
        S3fsCurlShare::ShareLocks.erase(locks_iter);
    }
}

CURLSH* S3fsCurlShare::GetCurlShareHandle()
{
    if(!S3fsCurlShare::is_dns_cache && !S3fsCurlShare::is_ssl_cache){
        // Any curl share handle does not exist
        return nullptr;
    }

    const std::lock_guard<std::mutex> lock(S3fsCurlShare::curl_share_lock);

    // find existed handle
    auto handle_iter = S3fsCurlShare::ShareHandles.find(ThreadId);
    if(handle_iter != S3fsCurlShare::ShareHandles.end()){
        // Already created share handle for this thread.
        return handle_iter->second.get();
    }

    // create new curl share handle and locks
    CurlSharePtr hShare = {nullptr, curl_share_cleanup};
    hShare.reset(curl_share_init());
    if(!hShare){
        S3FS_PRN_ERR("Failed to create curl share handle");
        return nullptr;
    }
    ShareLocksPtr pLocks(new curl_share_locks);

    // Initialize curl share handle
    if(!S3fsCurlShare::InitializeCurlShare(hShare, pLocks)){
        S3FS_PRN_ERR("Failed to initialize curl share handle");
        return nullptr;
    }

    // set map
    S3fsCurlShare::ShareHandles.emplace(ThreadId, std::move(hShare));
    S3fsCurlShare::ShareLocks.emplace(ThreadId, std::move(pLocks));

    // For clang-tidy measures
    handle_iter = S3fsCurlShare::ShareHandles.find(ThreadId);
    if(handle_iter == S3fsCurlShare::ShareHandles.end()){
        S3FS_PRN_ERR("Failed to insert curl share to map.");
        return nullptr;
    }
    return handle_iter->second.get();
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
