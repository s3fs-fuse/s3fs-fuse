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
#include <cerrno>
#include <vector>

#include "s3fs.h"
#include "s3fs_logger.h"
#include "curl_multi.h"
#include "curl.h"
#include "autolock.h"
#include "psemaphore.h"

//-------------------------------------------------------------------
// Class S3fsMultiCurl 
//-------------------------------------------------------------------
S3fsMultiCurl::S3fsMultiCurl(int maxParallelism) : maxParallelism(maxParallelism), SuccessCallback(NULL), RetryCallback(NULL), pSuccessCallbackParam(NULL)
{
    int result;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
    if (0 != (result = pthread_mutex_init(&completed_tids_lock, &attr))) {
        S3FS_PRN_ERR("could not initialize completed_tids_lock: %i", result);
        abort();
    }
}

S3fsMultiCurl::~S3fsMultiCurl()
{
    Clear();
    int result;
    if(0 != (result = pthread_mutex_destroy(&completed_tids_lock))){
        S3FS_PRN_ERR("could not destroy completed_tids_lock: %i", result);
    }
}

bool S3fsMultiCurl::ClearEx(bool is_all)
{
    s3fscurllist_t::iterator iter;
    for(iter = clist_req.begin(); iter != clist_req.end(); ++iter){
        S3fsCurl* s3fscurl = *iter;
        if(s3fscurl){
            s3fscurl->DestroyCurlHandle();
            delete s3fscurl;  // with destroy curl handle.
        }
    }
    clist_req.clear();

    if(is_all){
        for(iter = clist_all.begin(); iter != clist_all.end(); ++iter){
            S3fsCurl* s3fscurl = *iter;
            s3fscurl->DestroyCurlHandle();
            delete s3fscurl;
        }
        clist_all.clear();
    }

    S3FS_MALLOCTRIM(0);

    return true;
}

S3fsMultiSuccessCallback S3fsMultiCurl::SetSuccessCallback(S3fsMultiSuccessCallback function)
{
    S3fsMultiSuccessCallback old = SuccessCallback;
    SuccessCallback = function;
    return old;
}
  
S3fsMultiRetryCallback S3fsMultiCurl::SetRetryCallback(S3fsMultiRetryCallback function)
{
    S3fsMultiRetryCallback old = RetryCallback;
    RetryCallback = function;
    return old;
}

void* S3fsMultiCurl::SetSuccessCallbackParam(void* param)
{
    void* old = pSuccessCallbackParam;
    pSuccessCallbackParam = param;
    return old;
}
  
bool S3fsMultiCurl::SetS3fsCurlObject(S3fsCurl* s3fscurl)
{
    if(!s3fscurl){
        return false;
    }
    clist_all.push_back(s3fscurl);

    return true;
}

int S3fsMultiCurl::MultiPerform()
{
    std::vector<pthread_t>   threads;
    bool                     success = true;
    bool                     isMultiHead = false;
    Semaphore                sem(GetMaxParallelism());
    int                      rc;

    for(s3fscurllist_t::iterator iter = clist_req.begin(); iter != clist_req.end(); ++iter) {
        pthread_t   thread;
        S3fsCurl*   s3fscurl = *iter;
        if(!s3fscurl){
            continue;
        }

        sem.wait();

        {
            AutoLock lock(&completed_tids_lock);
            for(std::vector<pthread_t>::iterator it = completed_tids.begin(); it != completed_tids.end(); ++it){
                void*   retval;
    
                rc = pthread_join(*it, &retval);
                if (rc) {
                    success = false;
                    S3FS_PRN_ERR("failed pthread_join - rc(%d) %s", rc, strerror(rc));
                } else {
                    long int_retval = reinterpret_cast<long>(retval);
                    if (int_retval && !(int_retval == -ENOENT && isMultiHead)) {
                        S3FS_PRN_WARN("thread terminated with non-zero return code: %ld", int_retval);
                    }
                }
            }
            completed_tids.clear();
        }
        s3fscurl->sem = &sem;
        s3fscurl->completed_tids_lock = &completed_tids_lock;
        s3fscurl->completed_tids = &completed_tids;

        isMultiHead |= s3fscurl->GetOp() == "HEAD";

        rc = pthread_create(&thread, NULL, S3fsMultiCurl::RequestPerformWrapper, static_cast<void*>(s3fscurl));
        if (rc != 0) {
            success = false;
            S3FS_PRN_ERR("failed pthread_create - rc(%d)", rc);
            break;
        }
        threads.push_back(thread);
    }

    for(int i = 0; i < sem.get_value(); ++i){
        sem.wait();
    }

    AutoLock lock(&completed_tids_lock);
    for (std::vector<pthread_t>::iterator titer = completed_tids.begin(); titer != completed_tids.end(); ++titer) {
        void*   retval;

        rc = pthread_join(*titer, &retval);
        if (rc) {
            success = false;
            S3FS_PRN_ERR("failed pthread_join - rc(%d)", rc);
        } else {
            long int_retval = reinterpret_cast<long>(retval);
            if (int_retval && !(int_retval == -ENOENT && isMultiHead)) {
                S3FS_PRN_WARN("thread terminated with non-zero return code: %ld", int_retval);
            }
        }
    }
    completed_tids.clear();

    return success ? 0 : -EIO;
}

int S3fsMultiCurl::MultiRead()
{
    int result = 0;

    for(s3fscurllist_t::iterator iter = clist_req.begin(); iter != clist_req.end(); ){
        S3fsCurl* s3fscurl = *iter;

        bool isRetry = false;
        bool isPostpone = false;
        bool isNeedResetOffset = true;
        long responseCode = S3fsCurl::S3FSCURL_RESPONSECODE_NOTSET;
        CURLcode curlCode = s3fscurl->GetCurlCode();

        if(s3fscurl->GetResponseCode(responseCode, false) && curlCode == CURLE_OK){
            if(S3fsCurl::S3FSCURL_RESPONSECODE_NOTSET == responseCode){
                // This is a case where the processing result has not yet been updated (should be very rare).
                isPostpone = true;
            }else if(400 > responseCode){
                // add into stat cache
                if(SuccessCallback && !SuccessCallback(s3fscurl, pSuccessCallbackParam)){
                    S3FS_PRN_WARN("error from callback function(%s).", s3fscurl->url.c_str());
                }
            }else if(400 == responseCode){
                // as possibly in multipart
                S3FS_PRN_WARN("failed a request(%ld: %s)", responseCode, s3fscurl->url.c_str());
                isRetry = true;
            }else if(404 == responseCode){
                // not found
                // HEAD requests on readdir_multi_head can return 404
                if(s3fscurl->GetOp() != "HEAD"){
                    S3FS_PRN_WARN("failed a request(%ld: %s)", responseCode, s3fscurl->url.c_str());
                }
            }else if(500 == responseCode){
                // case of all other result, do retry.(11/13/2013)
                // because it was found that s3fs got 500 error from S3, but could success
                // to retry it.
                S3FS_PRN_WARN("failed a request(%ld: %s)", responseCode, s3fscurl->url.c_str());
                isRetry = true;
            }else{
                // Retry in other case.
                S3FS_PRN_WARN("failed a request(%ld: %s)", responseCode, s3fscurl->url.c_str());
                isRetry = true;
            }
        }else{
            S3FS_PRN_ERR("failed a request(Unknown response code: %s)", s3fscurl->url.c_str());
            // Reuse partical file
            switch(curlCode){
                case CURLE_OPERATION_TIMEDOUT:
                    isRetry = true;
                    isNeedResetOffset = false;
                    break; 

                case CURLE_PARTIAL_FILE:
                    isRetry = true;
                    isNeedResetOffset = false;
                    break; 

                default:
                    S3FS_PRN_ERR("###curlCode: %d  msg: %s", curlCode, curl_easy_strerror(curlCode));
                    isRetry = true;
                    break;
            }
        }

        if(isPostpone){
            clist_req.erase(iter);
            clist_req.push_back(s3fscurl);    // Re-evaluate at the end
            iter = clist_req.begin();
        }else{
            if(!isRetry || 0 != result){
                // If an EIO error has already occurred, it will be terminated
                // immediately even if retry processing is required. 
                s3fscurl->DestroyCurlHandle();
                delete s3fscurl;
            }else{
                S3fsCurl* retrycurl = NULL;

                // Reset offset
                if(isNeedResetOffset){
                    S3fsCurl::ResetOffset(s3fscurl);
                }

                // For retry
                if(RetryCallback){
                    retrycurl = RetryCallback(s3fscurl);
                    if(NULL != retrycurl){
                        clist_all.push_back(retrycurl);
                    }else{
                        // set EIO and wait for other parts.
                        result = -EIO;
                    }
                }
                if(s3fscurl != retrycurl){
                    s3fscurl->DestroyCurlHandle();
                    delete s3fscurl;
                }
            }
            iter = clist_req.erase(iter);
        }
    }
    clist_req.clear();

    if(0 != result){
        // If an EIO error has already occurred, clear all retry objects.
        for(s3fscurllist_t::iterator iter = clist_all.begin(); iter != clist_all.end(); ++iter){
            S3fsCurl* s3fscurl = *iter;
            s3fscurl->DestroyCurlHandle();
            delete s3fscurl;
        }
        clist_all.clear();
    }
    return result;
}

int S3fsMultiCurl::Request()
{
    S3FS_PRN_INFO3("[count=%zu]", clist_all.size());

    // Make request list.
    //
    // Send multi request loop( with retry )
    // (When many request is sends, sometimes gets "Couldn't connect to server")
    //
    while(!clist_all.empty()){
        // set curl handle to multi handle
        int                      result;
        s3fscurllist_t::iterator iter;
        for(iter = clist_all.begin(); iter != clist_all.end(); ++iter){
            S3fsCurl* s3fscurl = *iter;
            clist_req.push_back(s3fscurl);
        }
        clist_all.clear();

        // Send multi request.
        if(0 != (result = MultiPerform())){
            Clear();
            return result;
        }

        // Read the result
        if(0 != (result = MultiRead())){
            Clear();
            return result;
        }

        // Cleanup curl handle in multi handle
        ClearEx(false);
    }
    return 0;
}

//
// thread function for performing an S3fsCurl request
//
void* S3fsMultiCurl::RequestPerformWrapper(void* arg)
{
    S3fsCurl* s3fscurl= static_cast<S3fsCurl*>(arg);
    void*     result  = NULL;
    if(!s3fscurl){
        return reinterpret_cast<void*>(static_cast<intptr_t>(-EIO));
    }
    if(s3fscurl->fpLazySetup){
        if(!s3fscurl->fpLazySetup(s3fscurl)){
            S3FS_PRN_ERR("Failed to lazy setup, then respond EIO.");
            result  = reinterpret_cast<void*>(static_cast<intptr_t>(-EIO));
        }
    }

    if(!result){
        result = reinterpret_cast<void*>(static_cast<intptr_t>(s3fscurl->RequestPerform()));
        s3fscurl->DestroyCurlHandle(true, false);
    }

    AutoLock  lock(s3fscurl->completed_tids_lock);
    s3fscurl->completed_tids->push_back(pthread_self());
    s3fscurl->sem->post();

    return result;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
