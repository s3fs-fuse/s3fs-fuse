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

//----------------------------------------------
// Typedef
//----------------------------------------------
class S3fsCurl;

typedef std::vector<S3fsCurl*>       s3fscurllist_t;
typedef bool (*S3fsMultiSuccessCallback)(S3fsCurl* s3fscurl, void* param);  // callback for succeed multi request
typedef S3fsCurl* (*S3fsMultiRetryCallback)(S3fsCurl* s3fscurl);            // callback for failure and retrying

//----------------------------------------------
// class S3fsMultiCurl
//----------------------------------------------
class S3fsMultiCurl
{
    private:
        const int maxParallelism;

        s3fscurllist_t clist_all;  // all of curl requests
        s3fscurllist_t clist_req;  // curl requests are sent

        S3fsMultiSuccessCallback SuccessCallback;
        S3fsMultiRetryCallback   RetryCallback;
        void*                    pSuccessCallbackParam;

        pthread_mutex_t completed_tids_lock;
        std::vector<pthread_t> completed_tids;

    private:
        bool ClearEx(bool is_all);
        int MultiPerform();
        int MultiRead();

        static void* RequestPerformWrapper(void* arg);

    public:
        explicit S3fsMultiCurl(int maxParallelism);
        ~S3fsMultiCurl();

        int GetMaxParallelism() { return maxParallelism; }

        S3fsMultiSuccessCallback SetSuccessCallback(S3fsMultiSuccessCallback function);
        S3fsMultiRetryCallback SetRetryCallback(S3fsMultiRetryCallback function);
        void* SetSuccessCallbackParam(void* param);
        bool Clear() { return ClearEx(true); }
        bool SetS3fsCurlObject(S3fsCurl* s3fscurl);
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
