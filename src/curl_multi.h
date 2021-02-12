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

#ifndef S3FS_CURL_MULTI_H_
#define S3FS_CURL_MULTI_H_

#include "psemaphore.h"

//----------------------------------------------
// Typedef
//----------------------------------------------
class S3fsCurl;
class S3fsMultiCurl;

typedef std::list<S3fsCurl*>   s3fscurllist_t;
typedef std::vector<pthread_t> s3fsthreadlist_t;

typedef bool (*S3fsMultiPrecheckCallback)(S3fsCurl* s3fscurl);   // callback for pre-check to start
typedef bool (*S3fsMultiSuccessCallback)(S3fsCurl* s3fscurl);    // callback for succeed multi request
typedef S3fsCurl* (*S3fsMultiRetryCallback)(S3fsCurl* s3fscurl); // callback for failure and retrying

typedef struct mcurl_thread_param
{
    S3fsMultiCurl*  s3fsmulticurl;
    S3fsCurl*       s3fscurl;
    Semaphore*      sem;

    mcurl_thread_param(S3fsMultiCurl* ps3fsmulticurl = NULL, S3fsCurl* ps3fscurl = NULL, Semaphore* psem = NULL) : s3fsmulticurl(ps3fsmulticurl), s3fscurl(ps3fscurl), sem(psem) {}
}MCTH_PARAM;

//----------------------------------------------
// class S3fsMultiCurl
//----------------------------------------------
class S3fsMultiCurl
{
    private:
        const int                   maxParallelism;
        volatile bool               exit_thread;

        S3fsMultiPrecheckCallback   PrecheckCallback;
        S3fsMultiSuccessCallback    SuccessCallback;
        S3fsMultiRetryCallback      RetryCallback;

        s3fscurllist_t              clist_all;           // all of curl requests
        s3fscurllist_t              clist_req;           // curl requests are sent
        s3fscurllist_t              clist_res;           // list of responses received
        pthread_mutex_t             clist_lock;          // for clist_all, clist_req and clist_res
        long                        running_threads;     // running thread count
        s3fsthreadlist_t            completed_tids;      // waiting list for pthread_join
        pthread_mutex_t             completed_tids_lock; // for completed_tids and running_threads
        pthread_t                   parallel_thread;

    private:
        bool ClearEx(bool is_all);
        int MultiPrePerform(Semaphore& sem, bool& has_headreq, bool trywait);
        int MultiPostPerform(bool has_headreq);
        int MultiPerform();
        int MultiRead(bool is_parallel);

        static void* RequestPerformWrapper(void* arg);
        static void* ParallelProcessingWorker(void* arg);

    public:
        explicit S3fsMultiCurl(int maxParallelism);
        ~S3fsMultiCurl();

        int GetMaxParallelism() { return maxParallelism; }

        S3fsMultiPrecheckCallback SetPrecheckCallback(S3fsMultiPrecheckCallback function);
        S3fsMultiSuccessCallback SetSuccessCallback(S3fsMultiSuccessCallback function);
        S3fsMultiRetryCallback SetRetryCallback(S3fsMultiRetryCallback function);

        bool Clear() { return ClearEx(true); }
        bool SetS3fsCurlObject(S3fsCurl* s3fscurl);
        bool StartParallelThread();
        int WaitParallelThread();
        int Request();
};

#endif // S3FS_CURL_MULTI_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
