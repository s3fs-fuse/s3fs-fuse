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

#ifndef S3FS_CURL_SHARE_H_
#define S3FS_CURL_SHARE_H_

#include <curl/curl.h>
#include <map>
#include <memory>
#include <mutex>
#include <thread>

#include "common.h"

//----------------------------------------------
// Structure / Typedefs
//----------------------------------------------
struct curl_share_locks {
    std::mutex lock_dns;
    std::mutex lock_session;
};

typedef std::unique_ptr<CURLSH, decltype(&curl_share_cleanup)> CurlSharePtr;
typedef std::unique_ptr<curl_share_locks>                      ShareLocksPtr;

//----------------------------------------------
// class S3fsCurlShare
//----------------------------------------------
class S3fsCurlShare
{
    private:
        static bool                                     is_dns_cache;
        static bool                                     is_ssl_cache;
        static std::mutex                               curl_share_lock;
        static std::map<std::thread::id, CurlSharePtr>  ShareHandles GUARDED_BY(curl_share_lock);
        static std::map<std::thread::id, ShareLocksPtr> ShareLocks GUARDED_BY(curl_share_lock);

        std::thread::id                                 ThreadId;

    private:
        static void LockCurlShare(CURL* handle, curl_lock_data nLockData, curl_lock_access laccess, void* useptr) NO_THREAD_SAFETY_ANALYSIS;
        static void UnlockCurlShare(CURL* handle, curl_lock_data nLockData, void* useptr) NO_THREAD_SAFETY_ANALYSIS;
        static bool InitializeCurlShare(const CurlSharePtr& hShare, const ShareLocksPtr& ShareLock) REQUIRES(curl_share_lock);

        void DestroyCurlShareHandle();
        CURLSH* GetCurlShareHandle();

    public:
        static bool SetDnsCache(bool isCache);
        static bool SetSslSessionCache(bool isCache);
        static bool SetCurlShareHandle(CURL* hCurl);
        static bool DestroyCurlShareHandleForThread();

        // constructor/destructor
        explicit S3fsCurlShare();
        ~S3fsCurlShare() = default;
        S3fsCurlShare(const S3fsCurlShare&) = delete;
        S3fsCurlShare(S3fsCurlShare&&) = delete;
        S3fsCurlShare& operator=(const S3fsCurlShare&) = delete;
        S3fsCurlShare& operator=(S3fsCurlShare&&) = delete;
};

#endif // S3FS_CURL_SHARE_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
