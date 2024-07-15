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
#include "s3fs_threadreqs.h"
#include "threadpoolman.h"
#include "curl_util.h"
#include "s3fs_logger.h"
#include "s3fs_util.h"
#include "cache.h"
#include "string_util.h"

//-------------------------------------------------------------------
// Thread Worker functions for MultiThread Request
//-------------------------------------------------------------------
//
// Thread Worker function for head request
//
void* head_req_threadworker(void* arg)
{
    auto* pthparam = static_cast<head_req_thparam*>(arg);
    if(!pthparam || !pthparam->pmeta){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Head Request [path=%s][pmeta=%p]", pthparam->path.c_str(), pthparam->pmeta);

    S3fsCurl s3fscurl;
    pthparam->result = s3fscurl.HeadRequest(pthparam->path.c_str(), *(pthparam->pmeta));

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Thread Worker function for multi head request
//
void* multi_head_req_threadworker(void* arg)
{
    std::unique_ptr<multi_head_req_thparam> pthparam(static_cast<multi_head_req_thparam*>(arg));
    if(!pthparam || !pthparam->psyncfiller || !pthparam->pthparam_lock || !pthparam->pretrycount || !pthparam->pnotfound_list || !pthparam->presult){
        return reinterpret_cast<void*>(-EIO);
    }

    // Check retry max count and print debug message
    {
        const std::lock_guard<std::mutex> lock(*(pthparam->pthparam_lock));

        S3FS_PRN_INFO3("Multi Head Request [filler=%p][thparam_lock=%p][retrycount=%d][notfound_list=%p][wtf8=%s][path=%s]", pthparam->psyncfiller, pthparam->pthparam_lock, *(pthparam->pretrycount), pthparam->pnotfound_list, pthparam->use_wtf8 ? "true" : "false", pthparam->path.c_str());

        if(S3fsCurl::GetRetries() < *(pthparam->pretrycount)){
            S3FS_PRN_ERR("Head request(%s) reached the maximum number of retry count(%d).", pthparam->path.c_str(), *(pthparam->pretrycount));
            return reinterpret_cast<void*>(-EIO);
        }
    }

    // loop for head request
    S3fsCurl  s3fscurl;
    int       result = 0;
    headers_t meta;         // this value is not used
    while(true){
        // Request
        result = s3fscurl.HeadRequest(pthparam->path.c_str(), meta);

        // Check result
        bool     isResetOffset= true;
        CURLcode curlCode     = s3fscurl.GetCurlCode();
        long     responseCode = S3fsCurl::S3FSCURL_RESPONSECODE_NOTSET;
        s3fscurl.GetResponseCode(responseCode, false);

        if(CURLE_OK == curlCode){
            if(responseCode < 400){
                // add into stat cache
                if(StatCache::getStatCacheData()->AddStat(pthparam->path, *(s3fscurl.GetResponseHeaders()))){
                    // Get stats from stats cache(for converting from meta), and fill
                    std::string bpath = mybasename(pthparam->path);
                    if(pthparam->use_wtf8){
                        bpath = s3fs_wtf8_decode(bpath);
                    }

                    struct stat st;
                    if(StatCache::getStatCacheData()->GetStat(pthparam->path, &st)){
                        pthparam->psyncfiller->Fill(bpath, &st, 0);
                    }else{
                        S3FS_PRN_INFO2("Could not find %s file in stat cache.", pthparam->path.c_str());
                        pthparam->psyncfiller->Fill(bpath, nullptr, 0);
                    }
                    result = 0;
                }else{
                    S3FS_PRN_ERR("failed adding stat cache [path=%s]", pthparam->path.c_str());
                    if(0 == result){
                        result = -EIO;
                    }
                }
                break;

            }else if(responseCode == 400){
                // as possibly in multipart
                S3FS_PRN_WARN("Head Request(%s) got 400 response code.", pthparam->path.c_str());

            }else if(responseCode == 404){
                // set path to not found list
                S3FS_PRN_INFO("Head Request(%s) got NotFound(404), it maybe only the path exists and the object does not exist.", pthparam->path.c_str());
                {
                    const std::lock_guard<std::mutex> lock(*(pthparam->pthparam_lock));
                    pthparam->pnotfound_list->push_back(pthparam->path);
                }
                break;

            }else if(responseCode == 500){
                // case of all other result, do retry.(11/13/2013)
                // because it was found that s3fs got 500 error from S3, but could success
                // to retry it.
                S3FS_PRN_WARN("Head Request(%s) got 500 response code.", pthparam->path.c_str());

            // cppcheck-suppress unmatchedSuppression
            // cppcheck-suppress knownConditionTrueFalse
            }else if(responseCode == S3fsCurl::S3FSCURL_RESPONSECODE_NOTSET){
                // This is a case where the processing result has not yet been updated (should be very rare).
                S3FS_PRN_WARN("Head Request(%s) could not get any response code.", pthparam->path.c_str());

            }else{  // including S3fsCurl::S3FSCURL_RESPONSECODE_FATAL_ERROR
                // Retry in other case.
                S3FS_PRN_WARN("Head Request(%s) got fatal response code.", pthparam->path.c_str());
            }

        }else if(CURLE_OPERATION_TIMEDOUT == curlCode){
            S3FS_PRN_ERR("Head Request(%s) is timeouted.", pthparam->path.c_str());
            isResetOffset= false;

        }else if(CURLE_PARTIAL_FILE == curlCode){
            S3FS_PRN_WARN("Head Request(%s) is recieved data does not match the given size.", pthparam->path.c_str());
            isResetOffset= false;

        }else{
            S3FS_PRN_WARN("Head Request(%s) got the result code(%d: %s)", pthparam->path.c_str(), curlCode, curl_easy_strerror(curlCode));
        }

        // Check retry max count
        {
            const std::lock_guard<std::mutex> lock(*(pthparam->pthparam_lock));

            ++(*(pthparam->pretrycount));
            if(S3fsCurl::GetRetries() < *(pthparam->pretrycount)){
                S3FS_PRN_ERR("Head request(%s) reached the maximum number of retry count(%d).", pthparam->path.c_str(), *(pthparam->pretrycount));
                if(0 == result){
                    result = -EIO;
                }
                break;
            }
        }

        // Setup for retry
        if(isResetOffset){
            S3fsCurl::ResetOffset(&s3fscurl);
        }
    }

    // Set result code
    {
        const std::lock_guard<std::mutex> lock(*(pthparam->pthparam_lock));
        if(0 == *(pthparam->presult) && 0 != result){
            // keep first error
            *(pthparam->presult) = result;
        }
    }

    // [NOTE]
    // The return value of a Multi Head request thread will always be 0(nullptr).
    // This is because the expected value of a Head request will always be a
    // response other than 200, such as 400/404/etc.
    // In those error cases, this function simply outputs a message. And those
    // errors(the first one) will be set to pthparam->presult and can be referenced
    // by the caller.
    //
    return nullptr;
}

//
// Thread Worker function for delete request
//
void* delete_req_threadworker(void* arg)
{
    auto* pthparam = static_cast<delete_req_thparam*>(arg);
    if(!pthparam){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Delete Request [path=%s]", pthparam->path.c_str());

    S3fsCurl s3fscurl;
    pthparam->result = s3fscurl.DeleteRequest(pthparam->path.c_str());

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Thread Worker function for put head request
//
void* put_head_req_threadworker(void* arg)
{
    auto* pthparam = static_cast<put_head_req_thparam*>(arg);
    if(!pthparam){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Put Head Request [path=%s][meta count=%lu][is copy=%s]", pthparam->path.c_str(), pthparam->meta.size(), (pthparam->isCopy ? "true" : "false"));

    S3fsCurl s3fscurl(true);
    pthparam->result = s3fscurl.PutHeadRequest(pthparam->path.c_str(), pthparam->meta, pthparam->isCopy);

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Thread Worker function for put request
//
void* put_req_threadworker(void* arg)
{
    auto* pthparam = static_cast<put_req_thparam*>(arg);
    if(!pthparam){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Put Request [path=%s][meta count=%lu][fd=%d][use_ahbe=%s]", pthparam->path.c_str(), pthparam->meta.size(), pthparam->fd, (pthparam->ahbe ? "true" : "false"));

    S3fsCurl s3fscurl(pthparam->ahbe);
    pthparam->result = s3fscurl.PutRequest(pthparam->path.c_str(), pthparam->meta, pthparam->fd);

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Thread Worker function for list bucket request
//
void* list_bucket_req_threadworker(void* arg)
{
    auto* pthparam = static_cast<list_bucket_req_thparam*>(arg);
    if(!pthparam || !(pthparam->presponseBody)){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("List Bucket Request [path=%s][query=%s]", pthparam->path.c_str(), pthparam->query.c_str());

    S3fsCurl s3fscurl;
    if(0 == (pthparam->result = s3fscurl.ListBucketRequest(pthparam->path.c_str(), pthparam->query.c_str()))){
        *(pthparam->presponseBody) = s3fscurl.GetBodyData();
    }
    return reinterpret_cast<void*>(pthparam->result);
}

//
// Thread Worker function for check service request
//
void* check_service_req_threadworker(void* arg)
{
    auto* pthparam = static_cast<check_service_req_thparam*>(arg);
    if(!pthparam || !(pthparam->presponseCode) || !(pthparam->presponseBody)){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Check Service Request [path=%s][support compat dir=%s][force No SSE=%s]", pthparam->path.c_str(), (pthparam->support_compat_dir ? "true" : "false"), (pthparam->forceNoSSE ? "true" : "false"));

    S3fsCurl s3fscurl;
    if(0 == (pthparam->result = s3fscurl.CheckBucket(pthparam->path.c_str(), pthparam->support_compat_dir, pthparam->forceNoSSE))){
        *(pthparam->presponseCode) = s3fscurl.GetLastResponseCode();
        *(pthparam->presponseBody) = s3fscurl.GetBodyData();
    }
    return reinterpret_cast<void*>(pthparam->result);
}

//
// Worker function for pre multipart upload request
//
void* pre_multipart_upload_req_threadworker(void* arg)
{
    auto* pthparam = static_cast<pre_multipart_upload_req_thparam*>(arg);
    if(!pthparam){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Pre Multipart Upload Request [path=%s][meta count=%lu]", pthparam->path.c_str(), pthparam->meta.size());

    S3fsCurl s3fscurl(true);
    pthparam->result = s3fscurl.PreMultipartUploadRequest(pthparam->path.c_str(), pthparam->meta, pthparam->upload_id);

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Worker function for complete multipart upload request
//
void* complete_multipart_upload_threadworker(void* arg)
{
    auto* pthparam = static_cast<complete_multipart_upload_req_thparam*>(arg);
    if(!pthparam){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Complete Multipart Upload Request [path=%s][upload id=%s][etaglist=%lu]", pthparam->path.c_str(), pthparam->upload_id.c_str(), pthparam->etaglist.size());

    S3fsCurl s3fscurl(true);
    pthparam->result = s3fscurl.MultipartUploadComplete(pthparam->path.c_str(), pthparam->upload_id, pthparam->etaglist);

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Worker function for abort multipart upload request
//
void* abort_multipart_upload_req_threadworker(void* arg)
{
    auto* pthparam = static_cast<abort_multipart_upload_req_thparam*>(arg);
    if(!pthparam){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Abort Multipart Upload Request [path=%s][upload id=%s]", pthparam->path.c_str(), pthparam->upload_id.c_str());

    S3fsCurl s3fscurl(true);
    pthparam->result = s3fscurl.AbortMultipartUpload(pthparam->path.c_str(), pthparam->upload_id);

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Thread Worker function for get object request
//
void* get_object_req_threadworker(void* arg)
{
    auto* pthparam = static_cast<get_object_req_thparam*>(arg);
    if(!pthparam){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Get Object Request [path=%s][fd=%d][start=%lld][size=%lld]", pthparam->path.c_str(), pthparam->fd, static_cast<long long>(pthparam->start), static_cast<long long>(pthparam->size));

    sse_type_t  ssetype = sse_type_t::SSE_DISABLE;
    std::string ssevalue;
    if(!get_object_sse_type(pthparam->path.c_str(), ssetype, ssevalue)){
        S3FS_PRN_WARN("Failed to get SSE type for file(%s).", pthparam->path.c_str());
    }

    S3fsCurl    s3fscurl;
    pthparam->result = s3fscurl.GetObjectRequest(pthparam->path.c_str(), pthparam->fd, pthparam->start, pthparam->size, ssetype, ssevalue);

    return reinterpret_cast<void*>(pthparam->result);
}

//-------------------------------------------------------------------
// Utility functions
//-------------------------------------------------------------------
//
// Calls S3fsCurl::HeadRequest via head_req_threadworker
//
int head_request(const std::string& strpath, headers_t& header)
{
    // parameter for thread worker
    head_req_thparam thargs;
    thargs.path   = strpath;
    thargs.pmeta  = &header;
    thargs.result = 0;

    // make parameter for thread pool
    thpoolman_param  ppoolparam;
    ppoolparam.args  = &thargs;
    ppoolparam.psem  = nullptr;         // case await
    ppoolparam.pfunc = head_req_threadworker;

    // send request by thread
    if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
        S3FS_PRN_ERR("failed to setup Await Head Request Thread Worker [path=%s]", strpath.c_str());
        return -EIO;
    }
    if(0 != thargs.result){
        S3FS_PRN_DBG("Await Head Request by error(%d) [path=%s]", thargs.result, strpath.c_str());
        return thargs.result;
    }

    return 0;
}

//
// Calls S3fsCurl::DeleteRequest via delete_req_threadworker
//
int delete_request(const std::string& strpath)
{
    // parameter for thread worker
    delete_req_thparam thargs;
    thargs.path   = strpath;
    thargs.result = 0;

    // make parameter for thread pool
    thpoolman_param  ppoolparam;
    ppoolparam.args  = &thargs;
    ppoolparam.psem  = nullptr;         // case await
    ppoolparam.pfunc = delete_req_threadworker;

    // send request by thread
    if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
        S3FS_PRN_ERR("failed to setup Await Delete Request Thread Worker [path=%s]", strpath.c_str());
        return -EIO;
    }
    if(0 != thargs.result){
        S3FS_PRN_DBG("Await Delete Request by error(%d) [path=%s]", thargs.result, strpath.c_str());
        return thargs.result;
    }
    return 0;
}

//
// Calls S3fsCurl::PutHeadRequest via put_head_req_threadworker
//
int put_head_request(const std::string& strpath, const headers_t& meta, bool is_copy)
{
    // parameter for thread worker
    put_head_req_thparam thargs;
    thargs.path   = strpath;
    thargs.meta   = meta;               // copy
    thargs.isCopy = is_copy;
    thargs.result = 0;

    // make parameter for thread pool
    thpoolman_param  ppoolparam;
    ppoolparam.args  = &thargs;
    ppoolparam.psem  = nullptr;         // case await
    ppoolparam.pfunc = put_head_req_threadworker;

    // send request by thread
    if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
        S3FS_PRN_ERR("failed to setup Await Put Head Request Thread Worker [path=%s][meta count=%lu][is copy=%s]", strpath.c_str(), meta.size(), (is_copy ? "true" : "false"));
        return -EIO;
    }
    if(0 != thargs.result){
        S3FS_PRN_ERR("Await Put Head Request by error(%d) [path=%s][meta count=%lu][is copy=%s]", thargs.result, strpath.c_str(), meta.size(), (is_copy ? "true" : "false"));
        return thargs.result;
    }
    return 0;
}

//
// Calls S3fsCurl::PutRequest via put_req_threadworker
//
int put_request(const std::string& strpath, const headers_t& meta, int fd, bool ahbe)
{
    // parameter for thread worker
    put_req_thparam thargs;
    thargs.path   = strpath;
    thargs.meta   = meta;               // copy
    thargs.fd     = fd;                 // fd=-1 means for creating zero byte object.
    thargs.ahbe   = ahbe;
    thargs.result = 0;

    // make parameter for thread pool
    thpoolman_param  ppoolparam;
    ppoolparam.args  = &thargs;
    ppoolparam.psem  = nullptr;         // case await
    ppoolparam.pfunc = put_req_threadworker;

    // send request by thread
    if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
        S3FS_PRN_ERR("failed to setup Await Put Request Thread Worker [path=%s][meta count=%lu][fd=%d][use_ahbe=%s]", strpath.c_str(), meta.size(), fd, (ahbe ? "true" : "false"));
        return -EIO;
    }
    if(0 != thargs.result){
        S3FS_PRN_ERR("Await Put Request by error(%d) [path=%s][meta count=%lu][fd=%d][use_ahbe=%s]", thargs.result, strpath.c_str(), meta.size(), fd, (ahbe ? "true" : "false"));
        return thargs.result;
    }
    return 0;
}

//
// Calls S3fsCurl::ListBucketRequest via list_bucket_req_threadworker
//
int list_bucket_request(const std::string& strpath, const std::string& query, std::string& responseBody)
{
    // parameter for thread worker
    list_bucket_req_thparam thargs;
    thargs.path          = strpath;
    thargs.query         = query;
    thargs.presponseBody = &responseBody;
    thargs.result        = 0;

    // make parameter for thread pool
    thpoolman_param  ppoolparam;
    ppoolparam.args  = &thargs;
    ppoolparam.psem  = nullptr;         // case await
    ppoolparam.pfunc = list_bucket_req_threadworker;

    // send request by thread
    if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
        S3FS_PRN_ERR("failed to setup Await List Bucket Request Thread Worker [path=%s][query=%s]", strpath.c_str(), query.c_str());
        return -EIO;
    }
    if(0 != thargs.result){
        S3FS_PRN_ERR("Await List Bucket Request by error(%d) [path=%s][query=%s]", thargs.result, strpath.c_str(), query.c_str());
        return thargs.result;
    }
    return 0;
}

//
// Calls S3fsCurl::CheckBucket via check_service_req_threadworker
//
int check_service_request(const std::string& strpath, bool forceNoSSE, bool support_compat_dir, long& responseCode, std::string& responseBody)
{
    // parameter for thread worker
    check_service_req_thparam thargs;
    thargs.path               = strpath;
    thargs.forceNoSSE         = forceNoSSE;
    thargs.support_compat_dir = support_compat_dir;
    thargs.presponseCode      = &responseCode;
    thargs.presponseBody      = &responseBody;
    thargs.result             = 0;

    // make parameter for thread pool
    thpoolman_param  ppoolparam;
    ppoolparam.args  = &thargs;
    ppoolparam.psem  = nullptr;         // case await
    ppoolparam.pfunc = check_service_req_threadworker;

    // send request by thread
    if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
        S3FS_PRN_ERR("failed to setup Await Check Service Request Thread Worker [path=%s][support compat dir=%s][force No SSE=%s]", strpath.c_str(), (support_compat_dir ? "true" : "false"), (forceNoSSE ? "true" : "false"));
        return -EIO;
    }
    if(0 != thargs.result){
        S3FS_PRN_ERR("Await Check Service Request by error(%d) [path=%s][support compat dir=%s][force No SSE=%s]", thargs.result, strpath.c_str(), (support_compat_dir ? "true" : "false"), (forceNoSSE ? "true" : "false"));
        return thargs.result;
    }
    return 0;
}

//
// Calls S3fsCurl::PreMultipartUploadRequest via pre_multipart_upload_req_threadworker
//
// [NOTE]
// If the request is successful, sets upload_id.
//
int pre_multipart_upload_request(const std::string& path, const headers_t& meta, std::string& upload_id)
{
    // parameter for thread worker
    pre_multipart_upload_req_thparam thargs;
    thargs.path    = path;
    thargs.meta    = meta;              // copy
    thargs.upload_id.clear();           // clear
    thargs.result  = 0;

    // make parameter for thread pool
    thpoolman_param  ppoolparam;
    ppoolparam.args  = &thargs;
    ppoolparam.psem  = nullptr;         // case await
    ppoolparam.pfunc = pre_multipart_upload_req_threadworker;

    // send request by thread
    if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
        S3FS_PRN_ERR("failed to setup Pre Multipart Upload Request Thread Worker");
        return -EIO;
    }
    if(0 != thargs.result){
        S3FS_PRN_ERR("Pre Multipart Upload Request(path=%s) returns with error(%d)", path.c_str(), thargs.result);
        return thargs.result;
    }
    // set upload_id
    upload_id = thargs.upload_id;

    return 0;
}

//
// Calls S3fsCurl::MultipartUploadComplete via complete_multipart_upload_threadworker
//
int complete_multipart_upload_request(const std::string& path, const std::string& upload_id, const etaglist_t& parts)
{
    // parameter for thread worker
    complete_multipart_upload_req_thparam thargs;
    thargs.path      = path;
    thargs.upload_id = upload_id;
    thargs.etaglist  = parts;           // copy
    thargs.result    = 0;

    // make parameter for thread pool
    thpoolman_param  ppoolparam;
    ppoolparam.args  = &thargs;
    ppoolparam.psem  = nullptr;         // case await
    ppoolparam.pfunc = complete_multipart_upload_threadworker;

    // send request by thread
    if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
        S3FS_PRN_ERR("failed to setup Complete Multipart Upload Request Thread Worker");
        return -EIO;
    }
    if(0 != thargs.result){
        S3FS_PRN_ERR("Complete Multipart Upload Request(path=%s) returns with error(%d)", path.c_str(), thargs.result);
        return thargs.result;
    }
    return 0;
}

//
// Calls S3fsCurl::AbortMultipartUpload via abort_multipart_upload_req_threadworker
//
int abort_multipart_upload_request(const std::string& path, const std::string& upload_id)
{
    // parameter for thread worker
    abort_multipart_upload_req_thparam thargs;
    thargs.path      = path;
    thargs.upload_id = upload_id;
    thargs.result    = 0;

    // make parameter for thread pool
    thpoolman_param  ppoolparam;
    ppoolparam.args  = &thargs;
    ppoolparam.psem  = nullptr;         // case await
    ppoolparam.pfunc = abort_multipart_upload_req_threadworker;

    // send request by thread
    if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
        S3FS_PRN_ERR("failed to setup Abort Multipart Upload Request Thread Worker");
        return -EIO;
    }
    if(0 != thargs.result){
        S3FS_PRN_ERR("Abort Multipart Upload Request(path=%s) returns with error(%d)", path.c_str(), thargs.result);
        return thargs.result;
    }
    return 0;
}

//
// Calls S3fsCurl::GetObjectRequest via get_object_req_threadworker
//
int get_object_request(const std::string& path, int fd, off_t start, off_t size)
{
    // parameter for thread worker
    get_object_req_thparam thargs;
    thargs.path   = path;
    thargs.fd     = fd;
    thargs.start  = start;
    thargs.size   = size;
    thargs.result = 0;

    // make parameter for thread pool
    thpoolman_param  ppoolparam;
    ppoolparam.args  = &thargs;
    ppoolparam.psem  = nullptr;         // case await
    ppoolparam.pfunc = get_object_req_threadworker;

    // send request by thread
    if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
        S3FS_PRN_ERR("failed to setup Await Get Object Request Thread Worker [path=%s][fd=%d][start=%lld][size=%lld]", path.c_str(), fd, static_cast<long long int>(start), static_cast<long long int>(size));
        return -EIO;
    }
    if(0 != thargs.result){
        S3FS_PRN_ERR("Await Get Object Request by error(%d) [path=%s][fd=%d][start=%lld][size=%lld]", thargs.result, path.c_str(), fd, static_cast<long long int>(start), static_cast<long long int>(size));
        return thargs.result;
    }
    return 0;
}

//-------------------------------------------------------------------
// Direct Call Utility Functions
//-------------------------------------------------------------------
// These functions (mainly IAM token-related) are not called from
// a thread.
//
// [NOTE]
// The request for IAM token calls are called from S3fsCurl::RequestPerform
// method if the IAM token needs to be updated during each request
// processing. (NOTE: Each request is already executed in a thread.)
// If the number of threads has reached the limit when these functions
// are called, they will block until a thread that can execute this
// process is found.
// This may result in all processing being blocked.
// Therefore, the following functions(IAM token requests) will not be
// processed by a thread worker, but will process the request directly.
//
// If it is a different request called from within a thread worker,
// please process it like this.
//

//
// Directly calls S3fsCurl::GetIAMv2ApiToken
//
int get_iamv2api_token_request(const std::string& strurl, int tokenttl, const std::string& strttlhdr, std::string& token)
{
    S3FS_PRN_INFO3("Get IAMv2 API Toekn Request directly [url=%s][token ttl=%d][ttl header=%s]", strurl.c_str(), tokenttl, strttlhdr.c_str());

    S3fsCurl s3fscurl;

    return s3fscurl.GetIAMv2ApiToken(strurl.c_str(), tokenttl, strttlhdr.c_str(), token);
}

//
// Directly calls S3fsCurl::GetIAMRoleFromMetaData
//
int get_iamrole_request(const std::string& strurl, const std::string& striamtoken, std::string& token)
{
    S3FS_PRN_INFO3("Get IAM Role Request directly [url=%s][iam token=%s]", strurl.c_str(), striamtoken.c_str());

    S3fsCurl s3fscurl;
    int      result = 0;
    if(!s3fscurl.GetIAMRoleFromMetaData(strurl.c_str(), (striamtoken.empty() ? nullptr : striamtoken.c_str()), token)){
        S3FS_PRN_ERR("Something error occurred during getting IAM Role from MetaData.");
        result = -EIO;
    }
    return result;
}

//
// Directly calls S3fsCurl::GetIAMCredentials
//
int get_iamcred_request(const std::string& strurl, const std::string& striamtoken, const std::string& stribmsecret, std::string& cred)
{
    S3FS_PRN_INFO3("Get IAM Credentials Request directly [url=%s][iam token=%s][ibm secrect access key=%s]", strurl.c_str(), striamtoken.c_str(), stribmsecret.c_str());

    S3fsCurl s3fscurl;
    int      result = 0;
    if(!s3fscurl.GetIAMCredentials(strurl.c_str(), (striamtoken.empty() ? nullptr : striamtoken.c_str()), (stribmsecret.empty() ? nullptr : stribmsecret.c_str()), cred)){
        S3FS_PRN_ERR("Something error occurred during getting IAM Credentials.");
        result = -EIO;
    }
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
