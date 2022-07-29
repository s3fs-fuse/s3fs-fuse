/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2007 Takeshi Nakatani <ggtakec.com>
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

#include "s3fs.h"
#include "s3fs_logger.h"
#include "mpu_util.h"
#include "curl.h"
#include "s3fs_xml.h"
#include "s3fs_auth.h"
#include "string_util.h"

//-------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------
utility_incomp_type utility_mode = NO_UTILITY_MODE;

//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
static void print_incomp_mpu_list(incomp_mpu_list_t& list)
{
    printf("\n");
    printf("Lists the parts that have been uploaded for a specific multipart upload.\n");
    printf("\n");

    if(!list.empty()){
        printf("---------------------------------------------------------------\n");

        int cnt = 0;
        for(incomp_mpu_list_t::iterator iter = list.begin(); iter != list.end(); ++iter, ++cnt){
            printf(" Path     : %s\n", (*iter).key.c_str());
            printf(" UploadId : %s\n", (*iter).id.c_str());
            printf(" Date     : %s\n", (*iter).date.c_str());
            printf("\n");
        }
        printf("---------------------------------------------------------------\n");

    }else{
        printf("There is no list.\n");
    }
}

static bool abort_incomp_mpu_list(incomp_mpu_list_t& list, time_t abort_time)
{
    if(list.empty()){
        return true;
    }
    time_t now_time = time(NULL);

    // do removing.
    S3fsCurl s3fscurl;
    bool     result = true;
    for(incomp_mpu_list_t::iterator iter = list.begin(); iter != list.end(); ++iter){
        const char* tpath     = (*iter).key.c_str();
        std::string upload_id = (*iter).id;

        if(0 != abort_time){    // abort_time is 0, it means all.
            time_t    date = 0;
            if(!get_unixtime_from_iso8601((*iter).date.c_str(), date)){
                S3FS_PRN_DBG("date format is not ISO 8601 for %s multipart uploading object, skip this.", tpath);
                continue;
            }
            if(now_time <= (date + abort_time)){
                continue;
            }
        }

        if(0 != s3fscurl.AbortMultipartUpload(tpath, upload_id)){
            S3FS_PRN_EXIT("Failed to remove %s multipart uploading object.", tpath);
            result = false;
        }else{
            printf("Succeed to remove %s multipart uploading object.\n", tpath);
        }

        // reset(initialize) curl object
        s3fscurl.DestroyCurlHandle();
    }
    return result;
}

int s3fs_utility_processing(time_t abort_time)
{
    if(NO_UTILITY_MODE == utility_mode){
        return EXIT_FAILURE;
    }
    printf("\n*** s3fs run as utility mode.\n\n");

    S3fsCurl s3fscurl;
    std::string body;
    int result = EXIT_SUCCESS;
    if(0 != s3fscurl.MultipartListRequest(body)){
        S3FS_PRN_EXIT("Could not get list multipart upload.\nThere is no incomplete multipart uploaded object in bucket.\n");
        result = EXIT_FAILURE;
    }else{
        // parse result(incomplete multipart upload information)
        S3FS_PRN_DBG("response body = {\n%s\n}", body.c_str());

        xmlDocPtr doc;
        if(NULL == (doc = xmlReadMemory(body.c_str(), static_cast<int>(body.size()), "", NULL, 0))){
            S3FS_PRN_DBG("xmlReadMemory exited with error.");
            result = EXIT_FAILURE;

        }else{
            // make incomplete uploads list
            incomp_mpu_list_t list;
            if(!get_incomp_mpu_list(doc, list)){
                S3FS_PRN_DBG("get_incomp_mpu_list exited with error.");
                result = EXIT_FAILURE;

            }else{
                if(INCOMP_TYPE_LIST == utility_mode){
                    // print list
                    print_incomp_mpu_list(list);
                }else if(INCOMP_TYPE_ABORT == utility_mode){
                    // remove
                    if(!abort_incomp_mpu_list(list, abort_time)){
                        S3FS_PRN_DBG("an error occurred during removal process.");
                        result = EXIT_FAILURE;
                    }
                }
            }
            S3FS_XMLFREEDOC(doc);
        }
    }

    // ssl
    s3fs_destroy_global_ssl();

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
