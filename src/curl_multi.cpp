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

#include "common.h"
#include "s3fs.h"
#include "curl_multi.h"
#include "curl.h"
#include "autolock.h"

//-------------------------------------------------------------------
// Class S3fsMultiCurl 
//-------------------------------------------------------------------
S3fsMultiCurl::S3fsMultiCurl(int maxParallelism) : maxParallelism(maxParallelism), exit_thread(true), PrecheckCallback(NULL), SuccessCallback(NULL), RetryCallback(NULL), running_threads(0)
{
    int result;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
    if (0 != (result = pthread_mutex_init(&clist_lock, &attr))) {
        S3FS_PRN_ERR("could not initialize clist_lock: %i", result);
    }
    if (0 != (result = pthread_mutex_init(&completed_tids_lock, &attr))) {
        S3FS_PRN_ERR("could not initialize completed_tids_lock: %i", result);
    }
}

S3fsMultiCurl::~S3fsMultiCurl()
{
    Clear();
    int result;
    if(0 != (result = pthread_mutex_destroy(&completed_tids_lock))){
        S3FS_PRN_ERR("could not destroy completed_tids_lock: %i", result);
    }
    if(0 != (result = pthread_mutex_destroy(&clist_lock))){
        S3FS_PRN_ERR("could not destroy clist_lock: %i", result);
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

    for(iter = clist_res.begin(); iter != clist_res.end(); ++iter){
        S3fsCurl* s3fscurl = *iter;
        if(s3fscurl){
            s3fscurl->DestroyCurlHandle();
            delete s3fscurl;  // with destroy curl handle.
        }
    }
    clist_res.clear();

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

S3fsMultiPrecheckCallback S3fsMultiCurl::SetPrecheckCallback(S3fsMultiPrecheckCallback function)
{
    S3fsMultiPrecheckCallback old = PrecheckCallback;
    PrecheckCallback = function;
    return old;
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
  
bool S3fsMultiCurl::SetS3fsCurlObject(S3fsCurl* s3fscurl)
{
    if(!s3fscurl){
        return false;
    }
    AutoLock    lock(&clist_lock);
    clist_all.push_back(s3fscurl);

    return true;
}

bool S3fsMultiCurl::StartParallelThread()
{
    if(!exit_thread){
        S3FS_PRN_ERR("already run parallel thread.");
        return false;
    }
    // initialize thread count(not need to lock here)
    running_threads = 0;
    exit_thread     = false;

    int rc;
    if(0 != (rc = pthread_create(&parallel_thread, NULL, S3fsMultiCurl::ParallelProcessingWorker, static_cast<void*>(this)))){
        exit_thread = true;
        S3FS_PRN_ERR("failed pthread_create - rc(%d)", rc);
        return false;
    }
    return true;
}

int S3fsMultiCurl::WaitParallelThread()
{
    if(!exit_thread){
        exit_thread = true;
    }
    int     rc;
    void*   retval = NULL;
    if(0 != (rc = pthread_join(parallel_thread, &retval))){
        S3FS_PRN_ERR("failed pthread_join - rc(%d)", rc);
        return -EIO;
    }

    int int_retval = (int)(intptr_t)(retval);
    if(0 != int_retval){
        S3FS_PRN_WARN("thread result is somthing error - %d", int_retval);
    }
    return int_retval;
}

// [NOTE]
// In this method, do not lock the clist_lock and the completed_tids_lock
// at the same time. And it also free lock object frequently so as not to
// hold the lock for a long time.
// Also, clist_req/clist_res and running_threads are the end conditions
// of the Loop of ParallelProcessingWorker thread, so there is no moment
// when they become 0. (Therefore, if we push it into the list first and
// the processing fails, it will be removed after that soon.)
//
int S3fsMultiCurl::MultiPrePerform(Semaphore& sem, bool& has_headreq, bool trywait)
{
    bool    success            = true;
    bool    need_sem_post      = false;
    bool    need_decrement_tid = false;

    while(true){
        // If the processing fails, release semaphore at this any unlocked location.
        if(need_sem_post){
            sem.post();
            need_sem_post = false;
        }

        // Nothing to handle
        {
            AutoLock  lock(&clist_lock);    // only this scope area
            if(clist_req.empty()){
                break;
            }
        }

        // Wait semaphore
        if(trywait){
            if(!sem.trywait()){
                break;
            }
        }else{
            sem.wait();
        }

        // Threads that have already completed processing will immediately call pthread_join.
        if(0 != MultiPostPerform(has_headreq)){
            S3FS_PRN_WARN("MultiPostPerform is failure, but continue...");
            success = false;
        }

        S3fsCurl* s3fscurl;
        {
            AutoLock  lock(&clist_lock);    // only this scope area

            // get front of request list
            s3fscurl = clist_req.front();
            if(!s3fscurl){
                S3FS_PRN_WARN("An empty S3fsCurl object was found in the clist_req. But delete it and continue...");
                clist_req.pop_front();

                need_sem_post = true;
                continue;
            }

            // Pre-check
            if(PrecheckCallback && !PrecheckCallback(s3fscurl)){
                // already this object is set in cache, so skip this.
                clist_req.pop_front();
                s3fscurl->DestroyCurlHandle();
                delete s3fscurl;

                need_sem_post = true;
                continue;
            }

            // [NOTE]
            // Register s3fscurl object to clist_res first from clist_req.
            // If an error occurs, it will be deleted soon after that.
            clist_res.push_back(s3fscurl);
            clist_req.pop_front();
        }

        // check head request
        has_headreq |= s3fscurl->GetOp() == "HEAD";

        {
            // [NOTE]
            // Before starting a thread, increment the number of running threads.
            // This value will be decremented immediately if it fails.
            //
            AutoLock tid_lock(&completed_tids_lock);    // only this scope area
            ++running_threads;
        }

        // Create thread
        {
            AutoLock  lock(&clist_lock);    // only this scope area

            int         rc;
            pthread_t   thread;
            MCTH_PARAM* thparam = new MCTH_PARAM(this, s3fscurl, &sem);
            if(0 != (rc = pthread_create(&thread, NULL, S3fsMultiCurl::RequestPerformWrapper, static_cast<void*>(thparam)))){
                S3FS_PRN_ERR("failed pthread_create - rc(%d)", rc);
                success = false;

                // remove s3fscurl object from clist_res
                for(s3fscurllist_t::iterator iter = clist_res.begin(); iter != clist_res.end(); ++iter){
                    S3fsCurl* s3fscurl_res = *iter;
                    if(s3fscurl_res == s3fscurl){
                        clist_res.erase(iter);
                        break;
                    }
                }
                s3fscurl->DestroyCurlHandle();
                delete s3fscurl;
                delete thparam;

                need_sem_post      = true;
                need_decrement_tid = true;
                break;
            }
        }
    }

    if(need_sem_post){
        sem.post();
    }
    if(need_decrement_tid){
        AutoLock tid_lock(&completed_tids_lock);    // only this scope area
        --running_threads;
    }

    return success ? 0 : -EIO;
}

int S3fsMultiCurl::MultiPostPerform(bool has_headreq)
{
    bool    success = true;

    AutoLock lock(&completed_tids_lock);
    for(s3fsthreadlist_t::iterator titer = completed_tids.begin(); titer != completed_tids.end(); ++titer){
        void*   retval = NULL;
        int     rc     = pthread_join(*titer, &retval);
        if(rc){
            S3FS_PRN_ERR("failed pthread_join - rc(%d)", rc);
            success = false;
        }else{
            int int_retval = (int)(intptr_t)(retval);
            if (int_retval && !(int_retval == -ENOENT && has_headreq)) {
                S3FS_PRN_WARN("thread failed - rc(%d)", int_retval);
            }
        }
    }
    completed_tids.clear();

    return success ? 0 : -EIO;
}

//
// MultiPerform
//
// [NOTE]
// The request list is executed by the thread in order, and then
// the thread is waited for completion.
// Requests are processed in parallel, but this method waits for
// the environment of those requests as synchronous processing.
//
int S3fsMultiCurl::MultiPerform()
{
    bool        success = true;
    bool        isMultiHead = false;
    Semaphore   sem(GetMaxParallelism());

    // initialize thread count(not need to lock here)
    running_threads = 0;

    // Perform all request with thread
    if(0 != MultiPrePerform(sem, isMultiHead, false)){
        success = false;
    }

    // Wait for all requests to finish
    for(int i = 0; i < sem.get_value(); ++i){
        sem.wait();
    }

    // Handles thread termination for all requests.
    if(0 != MultiPostPerform(isMultiHead)){
        success = false;
    }

    return success ? 0 : -EIO;
}

int S3fsMultiCurl::MultiRead(bool is_parallel)
{
    int result = 0;

    AutoLock  lock(&clist_lock);
    for(s3fscurllist_t::iterator iter = clist_res.begin(); iter != clist_res.end(); ){
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
                if(SuccessCallback && !SuccessCallback(s3fscurl)){
                    S3FS_PRN_WARN("error from callback function(%s).", s3fscurl->url.c_str());
                }
            }else if(400 == responseCode){
                // HEAD request : if object has x-amz-server-side-encryption, may get 400.
                if(s3fscurl->GetOp() != "HEAD"){
                    // as possibly in multipart
                    S3FS_PRN_WARN("failed a request(%ld: %s)", responseCode, s3fscurl->url.c_str());
                    isRetry = true;
                }
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
            if(is_parallel){
                // in parallel, skip this
                ++iter;
            }else{
                // not in parallel
                clist_res.push_back(s3fscurl);    // Re-evaluate at the end
                iter = clist_res.erase(iter);
            }
        }else{
            if(0 != result){
                // If an EIO error is set, the request for a retry will be
                // completed immediately without retrying.
                // An EIO error is set if the retry process prior to this
                // request fails.
                //
                isRetry = false;
            }
            if(isRetry && RetryCallback){
                // Reset offset
                if(isNeedResetOffset){
                    S3fsCurl::ResetOffset(s3fscurl);
                }
                // create object for retry
                S3fsCurl* retrycurl = RetryCallback(s3fscurl);
                if(retrycurl){
                    // add new request
                    clist_all.push_back(retrycurl);
                }else{
                    // set EIO and wait for other parts.
                    S3FS_PRN_ERR("Could not make s3fscurl object for retry.");
                    result = -EIO;
                }

                if(s3fscurl != retrycurl){
                    s3fscurl->DestroyCurlHandle();
                    delete s3fscurl;
                }
            }else{
                // This request has been processed
                s3fscurl->DestroyCurlHandle();
                delete s3fscurl;
            }
            iter = clist_res.erase(iter);
        }
    }
    // [NOTE]
    // For parallel, clist_res may not be empty when the above loop completes.
    // If not parallel, clist_res is always empty.

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
    while(true){
        int result;
        {
            AutoLock  lock(&clist_lock);
            if(clist_all.empty()){
                break;
            }
            // move and append list from all to req
            s3fscurllist_t::iterator iter;
            for(iter = clist_all.begin(); iter != clist_all.end(); ++iter){
                S3fsCurl* s3fscurl = *iter;
                clist_req.push_back(s3fscurl);
            }
            clist_all.clear();
        }

        // Setup and run all request in threads and wait for all thread exiting.
        if(0 != (result = MultiPerform())){
            Clear();
            return result;
        }

        // Read the result
        if(0 != (result = MultiRead(false))){
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
    MCTH_PARAM* thparam = static_cast<MCTH_PARAM*>(arg);
    void*       result  = NULL;

    if(!thparam || !(thparam->s3fsmulticurl) || !(thparam->s3fscurl) || !(thparam->sem)){
        if(thparam){
            if(thparam->sem){
                thparam->sem->post();
            }
            delete thparam;
        }
        return (void*)(intptr_t)(-EIO);
    }
    if(thparam->s3fscurl->fpLazySetup){
        if(!thparam->s3fscurl->fpLazySetup(thparam->s3fscurl)){
            S3FS_PRN_ERR("Failed to lazy setup, then respond EIO.");
            result = (void*)(intptr_t)(-EIO);
        }
    }

    if(!result){
        result = (void*)(intptr_t)(thparam->s3fscurl->RequestPerform());
    }

    {
        AutoLock  lock(&(thparam->s3fsmulticurl->completed_tids_lock));     // only this scope area
        if(0 < thparam->s3fsmulticurl->running_threads){
            --(thparam->s3fsmulticurl->running_threads);
        }
        thparam->s3fsmulticurl->completed_tids.push_back(pthread_self());
    }
    thparam->sem->post();
    delete thparam;

    return result;
}

void* S3fsMultiCurl::ParallelProcessingWorker(void* arg)
{
    const static struct timespec waittime = {0L, 100};  // 100ns

    S3fsMultiCurl* pmcurl = static_cast<S3fsMultiCurl*>(arg);
    if(!pmcurl){
        return (void*)(intptr_t)(-EIO);
    }

    Semaphore   sem(pmcurl->GetMaxParallelism());
    int         result      = 0;
    bool        isMultiHead = false;
    bool        remaining   = true;

    while(!pmcurl->exit_thread || remaining){
        // If there is no remaining job but not allow thread exiting, so wait here.
        if(!remaining){
            nanosleep(&waittime, NULL);
        }
        remaining = false;

        {
            AutoLock    lock(&pmcurl->clist_lock);          // only this scope area

            // copy all to request list
            for(s3fscurllist_t::iterator iter = pmcurl->clist_all.begin(); iter != pmcurl->clist_all.end(); ++iter){
                S3fsCurl* s3fscurl = *iter;
                pmcurl->clist_req.push_back(s3fscurl);
            }
            pmcurl->clist_all.clear();

            if(!pmcurl->clist_req.empty() || !pmcurl->clist_res.empty()){
                remaining = true;
            }
        }
        if(!remaining){
            AutoLock lock(&pmcurl->completed_tids_lock);    // only this scope area
            if(0 != pmcurl->running_threads || !pmcurl->completed_tids.empty()){
                remaining = true;
            }
        }
        if(!remaining){
            continue;
        }

        // Perform requests in threads up to the number of semaphores
        if(0 != pmcurl->MultiPrePerform(sem, isMultiHead, true)){
            result = -EIO;
        }

        // Handles thread termination for requests.
        if(0 != pmcurl->MultiPostPerform(isMultiHead)){
            result = -EIO;
        }

        // Read the result of request
        if(0 != pmcurl->MultiRead(true)){
            result = -EIO;
        }
    }
    return (void*)(intptr_t)(result);
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
