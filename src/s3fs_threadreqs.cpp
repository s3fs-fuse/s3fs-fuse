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

#include <sstream>

#include "s3fs_threadreqs.h"
#include "threadpoolman.h"
#include "curl_util.h"
#include "s3fs_logger.h"
#include "s3fs_util.h"
#include "s3fs_xml.h"
#include "cache.h"
#include "string_util.h"

//-------------------------------------------------------------------
// Thread Worker functions for MultiThread Request
//-------------------------------------------------------------------
//
// Thread Worker function for head request
//
void* head_req_threadworker(S3fsCurl& s3fscurl, void* arg)
{
    auto* pthparam = static_cast<head_req_thparam*>(arg);
    if(!pthparam || !pthparam->pmeta){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Head Request [path=%s][pmeta=%p]", pthparam->path.c_str(), pthparam->pmeta);

    s3fscurl.SetUseAhbe(false);

    pthparam->result = s3fscurl.HeadRequest(pthparam->path.c_str(), *(pthparam->pmeta));

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Thread Worker function for multi head request
//
void* multi_head_req_threadworker(S3fsCurl& s3fscurl, void* arg)
{
    std::unique_ptr<multi_head_req_thparam> pthparam(static_cast<multi_head_req_thparam*>(arg));
    if(!pthparam || !pthparam->psyncfiller || !pthparam->pthparam_lock || !pthparam->pretrycount || !pthparam->pnotfound_list || !pthparam->presult){
        return reinterpret_cast<void*>(-EIO);
    }

    s3fscurl.SetUseAhbe(false);

    // loop for head request
    int       result = 0;
    headers_t meta;         // this value is not used
    while(true){
        // Request
        result = s3fscurl.HeadRequest(pthparam->path.c_str(), meta);

        // Check result
        bool     isResetOffset= true;
        CURLcode curlCode     = s3fscurl.GetCurlCode();
        long     responseCode = S3fsCurl::S3FSCURL_RESPONSECODE_NOTSET;
        if(!s3fscurl.GetResponseCode(responseCode, false)){
            result = -EIO;
            break;
        }

        if(CURLE_OK == curlCode){
            if(responseCode < 400){
                std::string bpath = mybasename(pthparam->path);
                if(pthparam->use_wtf8){
                     bpath = s3fs_wtf8_decode(bpath);
                }

                // set stat structure
                struct stat stbuf;
                if(convert_header_to_stat(pthparam->path, *(s3fscurl.GetResponseHeaders()), stbuf, false)){
                    // fill stat
                    pthparam->psyncfiller->Fill(bpath, &stbuf, 0);

                    // objet type
                    objtype_t ObjType = pthparam->objtype;
                    if(objtype_t::UNKNOWN == ObjType){
                        if(is_reg_fmt(*(s3fscurl.GetResponseHeaders()))){
                            ObjType = objtype_t::FILE;
                        }else if(is_symlink_fmt(*(s3fscurl.GetResponseHeaders()))){
                            ObjType = objtype_t::SYMLINK;
                        }else if(is_dir_fmt(*(s3fscurl.GetResponseHeaders()))){
                            S3FS_PRN_WARN("The path(%s) has a directory type headers, so we determine the precise directory type here. But it might not be the exact directory type.", pthparam->path.c_str());
                            if('/' != *(pthparam->path.rbegin())){
                                ObjType = objtype_t::DIR_NOT_TERMINATE_SLASH;
                            }else if(std::string::npos != pthparam->path.find("_$folder$", 0)){
                                ObjType = objtype_t::DIR_FOLDER_SUFFIX;
                            }else{
                                ObjType = objtype_t::DIR_NORMAL;
                            }
                        }else{
                            S3FS_PRN_WARN("The objtype of the path(%s) could not be determined, and the type is re-checked again after AddStat is called.", pthparam->path.c_str());
                        }
                    }

                    // add stat cache
                    if(!StatCache::getStatCacheData()->AddStat(pthparam->path, stbuf, *(s3fscurl.GetResponseHeaders()), ObjType, false)){
                        S3FS_PRN_ERR("failed add new stat cache[path=%s]", pthparam->path.c_str());
                        if(0 == result){
                            result = -EIO;
                        }
                    }
                }else{
                    S3FS_PRN_INFO2("Could not convert headers to stat[path=%s]", pthparam->path.c_str());
                    pthparam->psyncfiller->Fill(bpath, nullptr, 0);
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
            S3FS_PRN_ERR("Head Request(%s) is timed out.", pthparam->path.c_str());
            isResetOffset= false;

        }else if(CURLE_PARTIAL_FILE == curlCode){
            S3FS_PRN_WARN("Head Request(%s) is received data does not match the given size.", pthparam->path.c_str());
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
void* delete_req_threadworker(S3fsCurl& s3fscurl, void* arg)
{
    auto* pthparam = static_cast<delete_req_thparam*>(arg);
    if(!pthparam){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Delete Request [path=%s]", pthparam->path.c_str());

    s3fscurl.SetUseAhbe(false);

    pthparam->result = s3fscurl.DeleteRequest(pthparam->path.c_str());

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Thread Worker function for put head request
//
void* put_head_req_threadworker(S3fsCurl& s3fscurl, void* arg)
{
    auto* pthparam = static_cast<put_head_req_thparam*>(arg);
    if(!pthparam){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Put Head Request [path=%s][meta count=%zu][is copy=%s]", pthparam->path.c_str(), pthparam->meta.size(), (pthparam->isCopy ? "true" : "false"));

    s3fscurl.SetUseAhbe(true);

    pthparam->result = s3fscurl.PutHeadRequest(pthparam->path.c_str(), pthparam->meta, pthparam->isCopy);

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Thread Worker function for put request
//
void* put_req_threadworker(S3fsCurl& s3fscurl, void* arg)
{
    auto* pthparam = static_cast<put_req_thparam*>(arg);
    if(!pthparam){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Put Request [path=%s][meta count=%zu][fd=%d][use_ahbe=%s]", pthparam->path.c_str(), pthparam->meta.size(), pthparam->fd, (pthparam->ahbe ? "true" : "false"));

    s3fscurl.SetUseAhbe(pthparam->ahbe);

    pthparam->result = s3fscurl.PutRequest(pthparam->path.c_str(), pthparam->meta, pthparam->fd);

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Thread Worker function for list bucket request
//
void* list_bucket_req_threadworker(S3fsCurl& s3fscurl, void* arg)
{
    auto* pthparam = static_cast<list_bucket_req_thparam*>(arg);
    if(!pthparam || !(pthparam->presponseBody)){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("List Bucket Request [path=%s][query=%s]", pthparam->path.c_str(), pthparam->query.c_str());

    s3fscurl.SetUseAhbe(false);

    if(0 == (pthparam->result = s3fscurl.ListBucketRequest(pthparam->path.c_str(), pthparam->query.c_str()))){
        *(pthparam->presponseBody) = s3fscurl.GetBodyData();
    }
    return reinterpret_cast<void*>(pthparam->result);
}

//
// Thread Worker function for check service request
//
void* check_service_req_threadworker(S3fsCurl& s3fscurl, void* arg)
{
    auto* pthparam = static_cast<check_service_req_thparam*>(arg);
    if(!pthparam || !(pthparam->presponseCode) || !(pthparam->presponseBody)){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Check Service Request [path=%s][support compat dir=%s][force No SSE=%s]", pthparam->path.c_str(), (pthparam->support_compat_dir ? "true" : "false"), (pthparam->forceNoSSE ? "true" : "false"));

    s3fscurl.SetUseAhbe(false);

    pthparam->result = s3fscurl.CheckBucket(pthparam->path.c_str(), pthparam->support_compat_dir, pthparam->forceNoSSE);

    *(pthparam->presponseCode) = s3fscurl.GetLastResponseCode();

    // [NOTE]
    // A service check request is executed when s3fs starts.
    // Also, regardless of the debug level, if a Curl communication error occurs,
    // a Curl message will be displayed. Therefore, the Curl error message is
    // output to the Body here.
    //
    if(0 > pthparam->result && S3fsCurl::S3FSCURL_RESPONSECODE_FATAL_ERROR == s3fscurl.GetLastResponseCode()){
        std::string curlError;
        if(s3fscurl.GetCurlErrorString(curlError)){
            *(pthparam->presponseBody) = curlError;
        }else{
            *(pthparam->presponseBody) = s3fscurl.GetBodyData();
        }
    }else{
        *(pthparam->presponseBody) = s3fscurl.GetBodyData();
    }

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Worker function for pre multipart upload request
//
void* pre_multipart_upload_req_threadworker(S3fsCurl& s3fscurl, void* arg)
{
    auto* pthparam = static_cast<pre_multipart_upload_req_thparam*>(arg);
    if(!pthparam){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Pre Multipart Upload Request [path=%s][meta count=%zu]", pthparam->path.c_str(), pthparam->meta.size());

    s3fscurl.SetUseAhbe(true);

    pthparam->result = s3fscurl.PreMultipartUploadRequest(pthparam->path.c_str(), pthparam->meta, pthparam->upload_id);

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Worker function for pre multipart upload part request
//
void* multipart_upload_part_req_threadworker(S3fsCurl& s3fscurl, void* arg)
{
    std::unique_ptr<multipart_upload_part_req_thparam> pthparam(static_cast<multipart_upload_part_req_thparam*>(arg));
    if(!pthparam || !pthparam->pthparam_lock || !pthparam->petag || !pthparam->presult){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Multipart Upload Part Worker [path=%s][upload_id=%s][upload_fd=%d][start=%lld][size=%lld][is_copy=%s][part_num=%d]", pthparam->path.c_str(), pthparam->upload_id.c_str(), pthparam->upload_fd, static_cast<long long int>(pthparam->start), static_cast<long long int>(pthparam->size), (pthparam->is_copy ? "true" : "false"), pthparam->part_num);

    //
    // Check last thread result
    //
    {
        const std::lock_guard<std::mutex> lock(*(pthparam->pthparam_lock));
        if(0 != *(pthparam->presult)){
            S3FS_PRN_DBG("Already occurred error(%d), thus this thread worker is exiting.", *(pthparam->presult));
            return reinterpret_cast<void*>(*(pthparam->presult));
        }
    }

    s3fscurl.SetUseAhbe(true);

    //
    // Request
    //
    int result;
    if(0 != (result = s3fscurl.MultipartUploadPartRequest(pthparam->path.c_str(), pthparam->upload_fd, pthparam->start, pthparam->size, pthparam->part_num, pthparam->upload_id, pthparam->petag, pthparam->is_copy))){
        S3FS_PRN_ERR("Failed Multipart Upload Part Worker with error(%d) [path=%s][upload_id=%s][upload_fd=%d][start=%lld][size=%lld][is_copy=%s][part_num=%d]", result, pthparam->path.c_str(), pthparam->upload_id.c_str(), pthparam->upload_fd, static_cast<long long int>(pthparam->start), static_cast<long long int>(pthparam->size), (pthparam->is_copy ? "true" : "false"), pthparam->part_num);
    }

    // Set result for exiting
    {
        const std::lock_guard<std::mutex> lock(*(pthparam->pthparam_lock));
        *(pthparam->presult) = result;
    }

    return reinterpret_cast<void*>(result);
}

//
// Worker function for complete multipart upload request
//
void* complete_multipart_upload_threadworker(S3fsCurl& s3fscurl, void* arg)
{
    auto* pthparam = static_cast<complete_multipart_upload_req_thparam*>(arg);
    if(!pthparam){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Complete Multipart Upload Request [path=%s][upload id=%s][etaglist=%zu]", pthparam->path.c_str(), pthparam->upload_id.c_str(), pthparam->etaglist.size());

    s3fscurl.SetUseAhbe(true);

    pthparam->result = s3fscurl.MultipartUploadComplete(pthparam->path.c_str(), pthparam->upload_id, pthparam->etaglist);

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Worker function for abort multipart upload request
//
void* abort_multipart_upload_req_threadworker(S3fsCurl& s3fscurl, void* arg)
{
    auto* pthparam = static_cast<abort_multipart_upload_req_thparam*>(arg);
    if(!pthparam){
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Abort Multipart Upload Request [path=%s][upload id=%s]", pthparam->path.c_str(), pthparam->upload_id.c_str());

    s3fscurl.SetUseAhbe(true);

    pthparam->result = s3fscurl.AbortMultipartUpload(pthparam->path.c_str(), pthparam->upload_id);

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Thread Worker function for get object request
//
void* get_object_req_threadworker(S3fsCurl& s3fscurl, void* arg)
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

    s3fscurl.SetUseAhbe(false);

    pthparam->result = s3fscurl.GetObjectRequest(pthparam->path.c_str(), pthparam->fd, pthparam->start, pthparam->size, ssetype, ssevalue);

    return reinterpret_cast<void*>(pthparam->result);
}

//
// Thread Worker function for multipart put head request
//
void* multipart_put_head_req_threadworker(S3fsCurl& s3fscurl, void* arg)
{
    std::unique_ptr<multipart_put_head_req_thparam> pthparam(static_cast<multipart_put_head_req_thparam*>(arg));
    if(!pthparam || !pthparam->ppartdata || !pthparam->pthparam_lock || !pthparam->pretrycount || !pthparam->presult){
        return reinterpret_cast<void*>(-EIO);
    }

    s3fscurl.SetUseAhbe(true);

    int result = 0;
    while(true){
        // Request
        result = s3fscurl.MultipartPutHeadRequest(pthparam->from, pthparam->to, pthparam->part_number, pthparam->upload_id, pthparam->meta);

        // Check result
        bool     isResetOffset= true;
        CURLcode curlCode     = s3fscurl.GetCurlCode();
        long     responseCode = S3fsCurl::S3FSCURL_RESPONSECODE_NOTSET;
        if(!s3fscurl.GetResponseCode(responseCode, false)){
            result = -EIO;
            break;
        }

        if(CURLE_OK == curlCode){
            if(responseCode < 400){
                // add into stat cache
                {
                    const std::lock_guard<std::mutex> lock(*(pthparam->pthparam_lock));

                    std::string etag;
                    pthparam->ppartdata->uploaded    = simple_parse_xml(s3fscurl.GetBodyData().c_str(), s3fscurl.GetBodyData().size(), "ETag", etag);
                    pthparam->ppartdata->petag->etag = peeloff(etag);
                }
                result = 0;
                break;

            }else if(responseCode == 400){
                // as possibly in multipart
                S3FS_PRN_WARN("Put Head Request(%s->%s) got 400 response code.", pthparam->from.c_str(), pthparam->to.c_str());

            }else if(responseCode == 404){
                // set path to not found list
                S3FS_PRN_WARN("Put Head Request(%s->%s) got 404 response code.", pthparam->from.c_str(), pthparam->to.c_str());
                break;

            }else if(responseCode == 500){
                // case of all other result, do retry.(11/13/2013)
                // because it was found that s3fs got 500 error from S3, but could success
                // to retry it.
                S3FS_PRN_WARN("Put Head Request(%s->%s) got 500 response code.", pthparam->from.c_str(), pthparam->to.c_str());

            // cppcheck-suppress unmatchedSuppression
            // cppcheck-suppress knownConditionTrueFalse
            }else if(responseCode == S3fsCurl::S3FSCURL_RESPONSECODE_NOTSET){
                // This is a case where the processing result has not yet been updated (should be very rare).
                S3FS_PRN_WARN("Put Head Request(%s->%s) could not get any response code.", pthparam->from.c_str(), pthparam->to.c_str());

            }else{  // including S3fsCurl::S3FSCURL_RESPONSECODE_FATAL_ERROR
                // Retry in other case.
                S3FS_PRN_WARN("Put Head Request(%s->%s) got fatal response code.", pthparam->from.c_str(), pthparam->to.c_str());
            }

        }else if(CURLE_OPERATION_TIMEDOUT == curlCode){
            S3FS_PRN_ERR("Put Head Request(%s->%s) is timed out.", pthparam->from.c_str(), pthparam->to.c_str());
            isResetOffset= false;

        }else if(CURLE_PARTIAL_FILE == curlCode){
            S3FS_PRN_WARN("Put Head Request(%s->%s) is received data does not match the given size.", pthparam->from.c_str(), pthparam->to.c_str());
            isResetOffset= false;

        }else{
            S3FS_PRN_WARN("Put Head Request(%s->%s) got the result code(%d: %s)", pthparam->from.c_str(), pthparam->to.c_str(), curlCode, curl_easy_strerror(curlCode));
        }

        // Check retry max count
        {
            const std::lock_guard<std::mutex> lock(*(pthparam->pthparam_lock));

            ++(*(pthparam->pretrycount));
            if(S3fsCurl::GetRetries() < *(pthparam->pretrycount)){
                S3FS_PRN_ERR("Put Head Request(%s->%s) reached the maximum number of retry count(%d).", pthparam->from.c_str(), pthparam->to.c_str(), *(pthparam->pretrycount));
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

    return reinterpret_cast<void*>(result);
}

//
// Thread Worker function for parallel get object request
//
void* parallel_get_object_req_threadworker(S3fsCurl& s3fscurl, void* arg)
{
    std::unique_ptr<parallel_get_object_req_thparam> pthparam(static_cast<parallel_get_object_req_thparam*>(arg));
    if(!pthparam || !pthparam->pthparam_lock || !pthparam->pretrycount || !pthparam->presult){
        return reinterpret_cast<void*>(-EIO);
    }

    // Check retry max count and print debug message
    {
        const std::lock_guard<std::mutex> lock(*(pthparam->pthparam_lock));

        S3FS_PRN_INFO3("Parallel Get Object Request [path=%s][fd=%d][start=%lld][size=%lld][ssetype=%u][ssevalue=%s]", pthparam->path.c_str(), pthparam->fd, static_cast<long long int>(pthparam->start), static_cast<long long int>(pthparam->size), static_cast<uint8_t>(pthparam->ssetype), pthparam->ssevalue.c_str());

        if(S3fsCurl::GetRetries() < *(pthparam->pretrycount)){
            S3FS_PRN_ERR("Multipart Put Head request(%s) reached the maximum number of retry count(%d).", pthparam->path.c_str(), *(pthparam->pretrycount));
            return reinterpret_cast<void*>(-EIO);
        }
    }

    s3fscurl.SetUseAhbe(true);

    int result = 0;
    while(true){
        // Request
        result = s3fscurl.GetObjectRequest(pthparam->path.c_str(), pthparam->fd, pthparam->start, pthparam->size, pthparam->ssetype, pthparam->ssevalue);

        // Check result
        bool     isResetOffset= true;
        CURLcode curlCode     = s3fscurl.GetCurlCode();
        long     responseCode = S3fsCurl::S3FSCURL_RESPONSECODE_NOTSET;
        if(!s3fscurl.GetResponseCode(responseCode, false)){
            result = -EIO;
            break;
        }

        if(CURLE_OK == curlCode){
            if(responseCode < 400){
                // nothing to do
                result = 0;
                break;

            }else if(responseCode == 400){
                // as possibly in multipart
                S3FS_PRN_WARN("Get Object Request(%s) got 400 response code.", pthparam->path.c_str());

            }else if(responseCode == 404){
                // set path to not found list
                S3FS_PRN_WARN("Get Object Request(%s) got 404 response code.", pthparam->path.c_str());
                break;

            }else if(responseCode == 500){
                // case of all other result, do retry.(11/13/2013)
                // because it was found that s3fs got 500 error from S3, but could success
                // to retry it.
                S3FS_PRN_WARN("Get Object Request(%s) got 500 response code.", pthparam->path.c_str());

            // cppcheck-suppress unmatchedSuppression
            // cppcheck-suppress knownConditionTrueFalse
            }else if(responseCode == S3fsCurl::S3FSCURL_RESPONSECODE_NOTSET){
                // This is a case where the processing result has not yet been updated (should be very rare).
                S3FS_PRN_WARN("Get Object Request(%s) could not get any response code.", pthparam->path.c_str());

            }else{  // including S3fsCurl::S3FSCURL_RESPONSECODE_FATAL_ERROR
                // Retry in other case.
                S3FS_PRN_WARN("Get Object Request(%s) got fatal response code.", pthparam->path.c_str());
            }

        }else if(CURLE_OPERATION_TIMEDOUT == curlCode){
            S3FS_PRN_ERR("Get Object Request(%s) is timed out.", pthparam->path.c_str());
            isResetOffset= false;

        }else if(CURLE_PARTIAL_FILE == curlCode){
            S3FS_PRN_WARN("Get Object Request(%s) is received data does not match the given size.", pthparam->path.c_str());
            isResetOffset= false;

        }else{
            S3FS_PRN_WARN("Get Object Request(%s) got the result code(%d: %s)", pthparam->path.c_str(), curlCode, curl_easy_strerror(curlCode));
        }

        // Check retry max count
        {
            const std::lock_guard<std::mutex> lock(*(pthparam->pthparam_lock));

            ++(*(pthparam->pretrycount));
            if(S3fsCurl::GetRetries() < *(pthparam->pretrycount)){
                S3FS_PRN_ERR("Parallel Get Object Request(%s) reached the maximum number of retry count(%d).", pthparam->path.c_str(), *(pthparam->pretrycount));
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

    return reinterpret_cast<void*>(result);
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
// Calls S3fsCurl::HeadRequest via multi_head_req_threadworker
//
// [NOTE]
// objtype_t is a valid value only for directories.
// For files and symbolic links, specified any value other than the directory type(including UNKNOWN).
//
int multi_head_request(const std::string& strpath, SyncFiller& syncfiller, std::mutex& thparam_lock, int& retrycount, s3obj_list_t& notfound_list, bool use_wtf8, objtype_t objtype, int& result, Semaphore& sem)
{
    // parameter for thread worker
    auto* thargs           = new multi_head_req_thparam;    // free in multi_head_req_threadworker
    thargs->path           = strpath;
    thargs->psyncfiller    = &syncfiller;
    thargs->pthparam_lock  = &thparam_lock;                         // for pretrycount and presult member
    thargs->pretrycount    = &retrycount;
    thargs->pnotfound_list = &notfound_list;
    thargs->use_wtf8       = use_wtf8;
    thargs->objtype        = objtype;
    thargs->presult        = &result;

    // make parameter for thread pool
    thpoolman_param  ppoolparam;
    ppoolparam.args  = thargs;
    ppoolparam.psem  = &sem;
    ppoolparam.pfunc = multi_head_req_threadworker;

    // setup instruction
    if(!ThreadPoolMan::Instruct(ppoolparam)){
        S3FS_PRN_ERR("failed to setup Multi Head Request Thread Worker [path=%s]", strpath.c_str());
        delete thargs;
        return -EIO;
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
        S3FS_PRN_ERR("failed to setup Await Put Head Request Thread Worker [path=%s][meta count=%zu][is copy=%s]", strpath.c_str(), meta.size(), (is_copy ? "true" : "false"));
        return -EIO;
    }
    if(0 != thargs.result){
        S3FS_PRN_ERR("Await Put Head Request by error(%d) [path=%s][meta count=%zu][is copy=%s]", thargs.result, strpath.c_str(), meta.size(), (is_copy ? "true" : "false"));
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
        S3FS_PRN_ERR("failed to setup Await Put Request Thread Worker [path=%s][meta count=%zu][fd=%d][use_ahbe=%s]", strpath.c_str(), meta.size(), fd, (ahbe ? "true" : "false"));
        return -EIO;
    }
    if(0 != thargs.result){
        S3FS_PRN_ERR("Await Put Request by error(%d) [path=%s][meta count=%zu][fd=%d][use_ahbe=%s]", thargs.result, strpath.c_str(), meta.size(), fd, (ahbe ? "true" : "false"));
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
// Calls S3fsCurl::MultipartUploadPartRequest via multipart_upload_part_req_threadworker
//
int multipart_upload_part_request(const std::string& path, int upload_fd, off_t start, off_t size, int part_num, const std::string& upload_id, etagpair* petag, bool is_copy, Semaphore* psem, std::mutex* pthparam_lock, int* req_result)
{
    // parameter for thread worker
    auto* thargs = new multipart_upload_part_req_thparam;   // free in multipart_upload_part_req_threadworker
    thargs->path           = path;
    thargs->upload_id      = upload_id;
    thargs->upload_fd      = upload_fd;
    thargs->start          = start;
    thargs->size           = size;
    thargs->is_copy        = is_copy;
    thargs->part_num       = part_num;
    thargs->pthparam_lock  = pthparam_lock;
    thargs->petag          = petag;
    thargs->presult        = req_result;

    // make parameter for thread pool
    thpoolman_param  ppoolparam;
    ppoolparam.args  = thargs;
    ppoolparam.psem  = psem;
    ppoolparam.pfunc = multipart_upload_part_req_threadworker;

    // send request by thread
    if(!ThreadPoolMan::Instruct(ppoolparam)){
        S3FS_PRN_ERR("failed to setup Multipart Upload Part Thread Worker [path=%s][upload_id=%s][upload_fd=%d][start=%lld][size=%lld][is_copy=%s][part_num=%d]", path.c_str(), upload_id.c_str(), upload_fd, static_cast<long long int>(start), static_cast<long long int>(size), (is_copy ? "true" : "false"), part_num);;
        delete thargs;
        return -EIO;
    }

    return 0;
}

//
// Calls and Await S3fsCurl::MultipartUploadPartRequest via multipart_upload_part_req_threadworker
//
int await_multipart_upload_part_request(const std::string& path, int upload_fd, off_t start, off_t size, int part_num, const std::string& upload_id, etagpair* petag, bool is_copy)
{
    std::mutex thparam_lock;
    int        req_result = 0;

    // parameter for thread worker
    auto* thargs = new multipart_upload_part_req_thparam;   // free in multipart_upload_part_req_threadworker
    thargs->path           = path;
    thargs->upload_id      = upload_id;
    thargs->upload_fd      = upload_fd;
    thargs->start          = start;
    thargs->size           = size;
    thargs->is_copy        = is_copy;
    thargs->part_num       = part_num;
    thargs->pthparam_lock  = &thparam_lock;
    thargs->petag          = petag;
    thargs->presult        = &req_result;

    // make parameter for thread pool
    thpoolman_param  ppoolparam;
    ppoolparam.args  = thargs;
    ppoolparam.psem  = nullptr;         // case await
    ppoolparam.pfunc = multipart_upload_part_req_threadworker;

    // send request by thread
    if(!ThreadPoolMan::AwaitInstruct(ppoolparam)){
        S3FS_PRN_ERR("failed to setup Await Multipart Upload Part Thread Worker [path=%s][upload_id=%s][upload_fd=%d][start=%lld][size=%lld][is_copy=%s][part_num=%d]", path.c_str(), upload_id.c_str(), upload_fd, static_cast<long long int>(start), static_cast<long long int>(size), (is_copy ? "true" : "false"), part_num);;
        delete thargs;
        return -EIO;
    }
    if(0 != req_result){
        S3FS_PRN_ERR("Await Multipart Upload Part Request by error(%d) [path=%s][upload_id=%s][upload_fd=%d][start=%lld][size=%lld][is_copy=%s][part_num=%d]", req_result, path.c_str(), upload_id.c_str(), upload_fd, static_cast<long long int>(start), static_cast<long long int>(size), (is_copy ? "true" : "false"), part_num);
        return req_result;
    }
    return 0;
}

//
// Complete sequence of Multipart Upload Requests processing
//
// Call the following function:
//      pre_multipart_upload_request()
//      multipart_upload_part_request()
//      abort_multipart_upload_request()
//      complete_multipart_upload_request()
//
int multipart_upload_request(const std::string& path, const headers_t& meta, int upload_fd)
{
    S3FS_PRN_INFO3("Multipart Upload Request [path=%s][upload_fd=%d]", path.c_str(), upload_fd);

    // Get file stat
    struct stat st;
    if(-1 == fstat(upload_fd, &st)){
        S3FS_PRN_ERR("Invalid file descriptor(errno=%d)", errno);
        return -errno;
    }

    // Get upload id
    std::string upload_id;
    int         result;
    if(0 != (result = pre_multipart_upload_request(path, meta, upload_id))){
        return result;
    }

    Semaphore  upload_sem(0);
    std::mutex result_lock;         // protects last_result
    int        last_result = 0;
    int        req_count   = 0;     // request count(the part number will be this value +1.)
    etaglist_t list;

    // cycle through open upload_fd, pulling off 10MB chunks at a time
    for(off_t remaining_bytes = st.st_size; 0 < remaining_bytes; ++req_count){
        // add new etagpair to etaglist_t list
        list.emplace_back(nullptr, (req_count + 1));
        etagpair* petag = &list.back();

        off_t     start = st.st_size - remaining_bytes;
        off_t     chunk = std::min(remaining_bytes, S3fsCurl::GetMultipartSize());

        S3FS_PRN_INFO3("Multipart Upload Part [path=%s][start=%lld][size=%lld][part_num=%d]", path.c_str(), static_cast<long long int>(start), static_cast<long long int>(chunk), (req_count + 1));

        // setup instruction and request on another thread
        if(0 != (result = multipart_upload_part_request(path, upload_fd, start, chunk, (req_count + 1), upload_id, petag, false, &upload_sem, &result_lock, &last_result))){
            S3FS_PRN_ERR("failed setup instruction for Multipart Upload Part Request by error(%d) [path=%s][start=%lld][size=%lld][part_num=%d]", result, path.c_str(), static_cast<long long int>(start), static_cast<long long int>(chunk), (req_count + 1));

            // [NOTE]
            // Hold onto result until all request finish.
            break;
        }
        remaining_bytes -= chunk;
    }

    // wait for finish all requests
    while(req_count > 0){
        upload_sem.acquire();
        --req_count;
    }

    // check result
    if(0 != result || 0 != last_result){
        S3FS_PRN_ERR("Error occurred in Multipart Upload Request (errno=%d).", (0 != result ? result : last_result));

        int result2;
        if(0 != (result2 = abort_multipart_upload_request(path, upload_id))){
            S3FS_PRN_ERR("Error aborting Multipart Upload Request (errno=%d).", result2);
        }
        return (0 != result ? result : last_result);
    }

    // complete requests
    if(0 != (result = complete_multipart_upload_request(path, upload_id, list))){
        S3FS_PRN_ERR("Error occurred in Completion for Multipart Upload Request (errno=%d).", result);
        return result;
    }
    return 0;
}

//
// Complete sequence of Mix Multipart Upload Requests processing
//
// Call the following function:
//      pre_multipart_upload_request()
//      multipart_upload_part_request()
//      abort_multipart_upload_request()
//      complete_multipart_upload_request()
//
int mix_multipart_upload_request(const std::string& path, headers_t& meta, int upload_fd, const fdpage_list_t& mixuppages)
{
    S3FS_PRN_INFO3("Mix Multipart Upload Request [path=%s][upload_fd=%d]", path.c_str(), upload_fd);

    // Get file stat
    struct stat st;
    if(-1 == fstat(upload_fd, &st)){
        S3FS_PRN_ERR("Invalid file descriptor(errno=%d)", errno);
        return -errno;
    }

    // Get upload id
    std::string upload_id;
    int         result;
    if(0 != (result = pre_multipart_upload_request(path, meta, upload_id))){
        return result;
    }

    // Prepare headers for Multipart Upload Copy
    std::string srcresource;
    std::string srcurl;
    MakeUrlResource(get_realpath(path.c_str()).c_str(), srcresource, srcurl);
    meta["Content-Type"]      = S3fsCurl::LookupMimeType(path);
    meta["x-amz-copy-source"] = srcresource;

    Semaphore  upload_sem(0);
    std::mutex result_lock;         // protects last_result
    int        last_result = 0;
    int        req_count   = 0;     // request count(the part number will be this value +1.)
    etaglist_t list;

    for(auto iter = mixuppages.cbegin(); iter != mixuppages.cend(); ++iter){
        if(iter->modified){
            //
            // Multipart Upload Content
            //

            // add new etagpair to etaglist_t list
            list.emplace_back(nullptr, (req_count + 1));
            etagpair* petag = &list.back();

            S3FS_PRN_INFO3("Mix Multipart Upload Content Part [path=%s][start=%lld][size=%lld][part_num=%d]", path.c_str(), static_cast<long long int>(iter->offset), static_cast<long long int>(iter->bytes), (req_count + 1));

            // setup instruction and request on another thread
            if(0 != (result = multipart_upload_part_request(path, upload_fd, iter->offset, iter->bytes, (req_count + 1), upload_id, petag, false, &upload_sem, &result_lock, &last_result))){
                S3FS_PRN_ERR("Failed setup instruction for Mix Multipart Upload Content Part Request by error(%d) [path=%s][start=%lld][size=%lld][part_num=%d]", result, path.c_str(), static_cast<long long int>(iter->offset), static_cast<long long int>(iter->bytes), (req_count + 1));
                // [NOTE]
                // Hold onto result until all request finish.
                break;
            }
            ++req_count;

        }else{
            //
            // Multipart Upload Copy
            //
            // [NOTE]
            // Each part must be larger than MIN_MULTIPART_SIZE and smaller than FIVE_GB, then loop.
            // This loop breaks if result is not 0.
            //
            for(off_t processed_bytes = 0, request_bytes = 0; processed_bytes < iter->bytes && 0 == result; processed_bytes += request_bytes){
                // Set temporary part sizes
                request_bytes = std::min(S3fsCurl::GetMultipartCopySize(), (iter->bytes - processed_bytes));

                // Check lastest part size
                off_t remain_bytes = iter->bytes - processed_bytes - request_bytes;
                if((0 < remain_bytes) && (remain_bytes < MIN_MULTIPART_SIZE)){
                    if(FIVE_GB < (request_bytes + remain_bytes)){
                        request_bytes = (request_bytes + remain_bytes) / 2;
                    } else{
                        request_bytes += remain_bytes;
                    }
                }

                // Set headers for Multipart Upload Copy
                std::ostringstream strrange;
                strrange << "bytes=" << (iter->offset + processed_bytes) << "-" << (iter->offset + processed_bytes + request_bytes - 1);
                meta["x-amz-copy-source-range"] = strrange.str();

                // add new etagpair to etaglist_t list
                list.emplace_back(nullptr, (req_count + 1));
                etagpair* petag = &list.back();

                S3FS_PRN_INFO3("Mix Multipart Upload Copy Part [path=%s][start=%lld][size=%lld][part_num=%d]", path.c_str(), static_cast<long long int>(iter->offset + processed_bytes), static_cast<long long int>(request_bytes), (req_count + 1));

                // setup instruction and request on another thread
                if(0 != (result = multipart_upload_part_request(path, upload_fd, (iter->offset + processed_bytes), request_bytes, (req_count + 1), upload_id, petag, true, &upload_sem, &result_lock, &last_result))){
                    S3FS_PRN_ERR("Failed setup instruction for Mix Multipart Upload Copy Part Request by error(%d) [path=%s][start=%lld][size=%lld][part_num=%d]", result, path.c_str(), static_cast<long long int>(iter->offset + processed_bytes), static_cast<long long int>(request_bytes), (req_count + 1));
                    // [NOTE]
                    // This loop breaks because result is not 0.
                }
                ++req_count;
            }
            if(0 != result){
                // [NOTE]
                // Hold onto result until all request finish.
                break;
            }
        }
    }

    // wait for finish all requests
    while(req_count > 0){
        upload_sem.acquire();
        --req_count;
    }

    // check result
    if(0 != result || 0 != last_result){
        S3FS_PRN_ERR("Error occurred in Mix Multipart Upload Request (errno=%d).", (0 != result ? result : last_result));

        int result2;
        if(0 != (result2 = abort_multipart_upload_request(path, upload_id))){
            S3FS_PRN_ERR("Error aborting Mix Multipart Upload Request (errno=%d).", result2);
        }
        return (0 != result ? result : last_result);
    }

    // complete requests
    if(0 != (result = complete_multipart_upload_request(path, upload_id, list))){
        S3FS_PRN_ERR("Error occurred in Completion for Mix Multipart Upload Request (errno=%d).", result);
        return result;
    }
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
// Calls S3fsCurl::MultipartPutHeadRequest via multipart_put_head_req_threadworker
//
int multipart_put_head_request(const std::string& strfrom, const std::string& strto, off_t size, const headers_t& meta)
{
    S3FS_PRN_INFO3("[from=%s][to=%s]", strfrom.c_str(), strto.c_str());

    bool         is_rename = (strfrom != strto);
    int          result;
    std::string  upload_id;
    off_t        chunk;
    off_t        bytes_remaining;
    etaglist_t   list;

    // Prepare additional header information for rename
    std::string contenttype;
    std::string srcresource;
    if(is_rename){
        std::string srcurl;                                                             // this is not used
        MakeUrlResource(get_realpath(strfrom.c_str()).c_str(), srcresource, srcurl);
        contenttype = S3fsCurl::LookupMimeType(strto);
    }

    // get upload_id
    if(0 != (result = pre_multipart_upload_request(strto, meta, upload_id))){
        return result;
    }

    // common variables
    Semaphore    multi_head_sem(0);
    std::mutex   thparam_lock;
    filepart     partdata;
    int          req_count  = 0;
    int          retrycount = 0;
    int          req_result = 0;

    for(bytes_remaining = size; 0 < bytes_remaining; bytes_remaining -= chunk){
        chunk = bytes_remaining > S3fsCurl::GetMultipartCopySize() ? S3fsCurl::GetMultipartCopySize() : bytes_remaining;

        partdata.add_etag_list(list);

        // parameter for thread worker
        auto* thargs = new multipart_put_head_req_thparam;    // free in multipart_put_head_req_threadworker
        thargs->from          = strfrom;
        thargs->to            = strto;
        thargs->upload_id     = upload_id;
        thargs->part_number   = partdata.get_part_number();
        thargs->meta          = meta;
        thargs->pthparam_lock = &thparam_lock;
        thargs->ppartdata     = &partdata;
        thargs->pretrycount   = &retrycount;
        thargs->presult       = &req_result;

        std::ostringstream strrange;
        strrange << "bytes=" << (size - bytes_remaining) << "-" << (size - bytes_remaining + chunk - 1);
        thargs->meta["x-amz-copy-source-range"] = strrange.str();

        if(is_rename){
            thargs->meta["Content-Type"]        = contenttype;
            thargs->meta["x-amz-copy-source"]   = srcresource;
        }

        // make parameter for thread pool
        thpoolman_param  ppoolparam;
        ppoolparam.args  = thargs;
        ppoolparam.psem  = &multi_head_sem;
        ppoolparam.pfunc = multipart_put_head_req_threadworker;

        // setup instruction
        if(!ThreadPoolMan::Instruct(ppoolparam)){
            S3FS_PRN_ERR("failed setup instruction for one header request.");
            delete thargs;
            return -EIO;
        }
        ++req_count;
    }

    // wait for finish all requests
    while(req_count > 0){
        multi_head_sem.acquire();
        --req_count;
    }

    // check result
    if(0 != req_result){
        S3FS_PRN_ERR("error occurred in multi request(errno=%d).", req_result);
        int result2;
        if(0 != (result2 = abort_multipart_upload_request(strto, upload_id))){
            S3FS_PRN_ERR("error aborting multipart upload(errno=%d).", result2);
        }
        return req_result;
    }

    // completion process
    if(0 != (result = complete_multipart_upload_request(strto, upload_id, list))){
        return result;
    }

    return 0;
}

//
// Calls S3fsCurl::ParallelGetObjectRequest via parallel_get_object_req_threadworker
//
int parallel_get_object_request(const std::string& path, int fd, off_t start, off_t size)
{
    S3FS_PRN_INFO3("[path=%s][fd=%d][start=%lld][size=%lld]", path.c_str(), fd, static_cast<long long int>(start), static_cast<long long int>(size));

    sse_type_t  ssetype = sse_type_t::SSE_DISABLE;
    std::string ssevalue;
    if(!get_object_sse_type(path.c_str(), ssetype, ssevalue)){
        S3FS_PRN_WARN("Failed to get SSE type for file(%s).", path.c_str());
    }

    Semaphore    para_getobj_sem(0);
    std::mutex   thparam_lock;
    int          req_count  = 0;
    int          retrycount = 0;
    int          req_result = 0;

    // cycle through open fd, pulling off 10MB chunks at a time
    for(off_t remaining_bytes = size, chunk = 0; 0 < remaining_bytes; remaining_bytes -= chunk){
        // chunk size
        chunk = remaining_bytes > S3fsCurl::GetMultipartSize() ? S3fsCurl::GetMultipartSize() : remaining_bytes;

        // parameter for thread worker
        auto* thargs = new parallel_get_object_req_thparam;  // free in parallel_get_object_req_threadworker
        thargs->path          = path;
        thargs->fd            = fd;
        thargs->start         = (start + size - remaining_bytes);
        thargs->size          = chunk;
        thargs->ssetype       = ssetype;
        thargs->ssevalue      = ssevalue;
        thargs->pthparam_lock = &thparam_lock;
        thargs->pretrycount   = &retrycount;
        thargs->presult       = &req_result;

        // make parameter for thread pool
        thpoolman_param  ppoolparam;
        ppoolparam.args  = thargs;
        ppoolparam.psem  = &para_getobj_sem;
        ppoolparam.pfunc = parallel_get_object_req_threadworker;

        // setup instruction
        if(!ThreadPoolMan::Instruct(ppoolparam)){
            S3FS_PRN_ERR("failed setup instruction for one header request.");
            delete thargs;
            return -EIO;
        }
        ++req_count;
    }

    // wait for finish all requests
    while(req_count > 0){
        para_getobj_sem.acquire();
        --req_count;
    }

    // check result
    if(0 != req_result){
        S3FS_PRN_ERR("error occurred in parallel get object request(errno=%d).", req_result);
        return req_result;
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
    S3FS_PRN_INFO3("Get IAM Role Request directly [url=%s][iam token=%s]", strurl.c_str(), mask_sensitive_string(striamtoken.c_str()));

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
    S3FS_PRN_INFO3("Get IAM Credentials Request directly [url=%s][iam token=%s][ibm secret access key=%s]", strurl.c_str(), mask_sensitive_string(striamtoken.c_str()), mask_sensitive_string(stribmsecret.c_str()));

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
