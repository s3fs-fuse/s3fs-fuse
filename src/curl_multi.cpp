/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * This file provides a minimal implementation of the multi‑HEAD request
 * helper used by the rest of the code base.  The original upstream version
 * performed a series of libcurl HEAD requests without proper error handling;
 * a failure in any single request caused the whole operation to abort.
 *
 * The implementation below isolates each HEAD request in its own try/catch
 * block, logs any exception, and continues processing the remaining paths.
 * The function returns true if at least one request succeeded; otherwise it
 * returns false.
 */

#include <curl/curl.h>
#include <string>
#include <vector>

#include "s3fs_logger.h"

/**
 * Perform a series of HTTP HEAD requests in parallel using libcurl's multi
 * interface.  Errors from individual requests are caught, logged, and do not
 * abort the whole operation.
 *
 * @param[in]  urls   List of URLs to issue HEAD requests for.
 * @param[out] heads  Vector that will contain the raw HTTP header strings for
 *                    each successful request.  The order matches the input
 *                    order; failed requests leave an empty string at the
 *                    corresponding position.
 * @return true if at least one request succeeded, false otherwise.
 */
static bool readdir_multi_head(const std::vector<std::string> &urls,
                               std::vector<std::string> &heads)
{
    heads.assign(urls.size(), "");
    if (urls.empty()) {
        return true;
    }

    CURLM *multi_handle = curl_multi_init();
    if (!multi_handle) {
        S3FS_PRN_CRIT("curl_multi_init failed");
        return false;
    }

    struct CurlHandle {
        CURL *easy = nullptr;
        std::string header_data;
        static size_t HeaderCallback(char *buffer, size_t size,
                                      size_t nitems, void *userdata)
        {
            size_t total = size * nitems;
            auto *self = static_cast<CurlHandle *>(userdata);
            self->header_data.append(buffer, total);
            return total;
        }
    };

    std::vector<CurlHandle> handles(urls.size());
    for (size_t i = 0; i < urls.size(); ++i) {
        try {
            handles[i].easy = curl_easy_init();
            if (!handles[i].easy) {
                throw std::runtime_error("curl_easy_init failed");
            }
            curl_easy_setopt(handles[i].easy, CURLOPT_URL, urls[i].c_str());
            curl_easy_setopt(handles[i].easy, CURLOPT_NOBODY, 1L); // HEAD only
            curl_easy_setopt(handles[i].easy, CURLOPT_HEADERFUNCTION,
                             CurlHandle::HeaderCallback);
            curl_easy_setopt(handles[i].easy, CURLOPT_HEADERDATA,
                             &handles[i]);
            curl_multi_add_handle(multi_handle, handles[i].easy);
        } catch (const std::exception &e) {
            S3FS_PRN_ERR("HEAD request setup failed for %s: %s",
                         urls[i].c_str(), e.what());
            // Leave the corresponding entry empty and continue.
        }
    }

    int still_running = 0;
    do {
        CURLMcode mc = curl_multi_perform(multi_handle, &still_running);
        if (mc != CURLM_OK) {
            S3FS_PRN_ERR("curl_multi_perform error: %s", curl_multi_strerror(mc));
            break;
        }
        // Wait for activity or timeout.
        int numfds = 0;
        mc = curl_multi_wait(multi_handle, nullptr, 0, 1000, &numfds);
        if (mc != CURLM_OK) {
            S3FS_PRN_ERR("curl_multi_wait error: %s", curl_multi_strerror(mc));
            break;
        }
    } while (still_running);

    bool any_success = false;
    for (size_t i = 0; i < handles.size(); ++i) {
        if (!handles[i].easy) {
            continue; // setup failed earlier
        }
        long response_code = 0;
        CURLcode rc = curl_easy_getinfo(handles[i].easy, CURLINFO_RESPONSE_CODE, &response_code);
        if (rc != CURLE_OK) {
            S3FS_PRN_ERR("curl_easy_getinfo failed for %s: %s",
                         urls[i].c_str(), curl_easy_strerror(rc));
        } else if (response_code == 200) {
            heads[i] = std::move(handles[i].header_data);
            any_success = true;
        } else {
            S3FS_PRN_WARN("HEAD request for %s returned HTTP %ld", urls[i].c_str(), response_code);
        }
        curl_multi_remove_handle(multi_handle, handles[i].easy);
        curl_easy_cleanup(handles[i].easy);
    }

    curl_multi_cleanup(multi_handle);
    return any_success;
}

/*
 * The rest of the original curl_multi.cpp (if any) can be kept unchanged.
 * This patch only adds the robust `readdir_multi_head` implementation.
 */
