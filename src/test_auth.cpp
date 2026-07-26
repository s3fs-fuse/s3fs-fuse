/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2026 Andrew Gaul <andrew@gaul.org>
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

#include <cstdlib>
#include <string>
#include <unistd.h>

#include "s3fs_auth.h"
#include "test_util.h"

static int make_test_fd(const std::string& content)
{
    char name[] = "test_auth.XXXXXX";
    int  fd     = mkstemp(name);
    if(-1 == fd || -1 == unlink(name)){
        std::abort();
    }
    if(static_cast<ssize_t>(content.size()) != pwrite(fd, content.c_str(), content.size(), 0)){
        std::abort();
    }
    return fd;
}

static std::string make_test_content()
{
    // 1,000 bytes so that the hash loops process multiple internal buffers
    std::string content;
    for(int i = 0; i < 100; ++i){
        content += "0123456789";
    }
    return content;
}

void test_sha256_fd()
{
    std::string content = make_test_content();
    int fd = make_test_fd(content);

    // explicit size
    ASSERT_EQUALS(std::string("ab6c5f3237f551d208fc2ca5225a4cca20b3fd638794a804f0ed5549d5041734"), s3fs_sha256_hex_fd(fd, 0, static_cast<off_t>(content.size())));
    // size of -1 means hashing the whole file
    ASSERT_EQUALS(std::string("ab6c5f3237f551d208fc2ca5225a4cca20b3fd638794a804f0ed5549d5041734"), s3fs_sha256_hex_fd(fd, 0, -1));
    // a range within the file
    ASSERT_EQUALS(std::string("ba6ab297dbb2bcbc66d54fb768e01920acb58b5552455834f4563807cbd46efb"), s3fs_sha256_hex_fd(fd, 200, 300));

    close(fd);
}

void test_sha256_fd_empty()
{
    int fd = make_test_fd("");

    ASSERT_EQUALS(std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), s3fs_sha256_hex_fd(fd, 0, -1));

    close(fd);
}

void test_md5_fd()
{
    // s3fs_get_content_md5 hashes the whole file with a size of -1
    int fd = make_test_fd(make_test_content());
    ASSERT_EQUALS(std::string("QnAIs/4ZL2Y9Zl9WzXVxbA=="), s3fs_get_content_md5(fd));
    close(fd);

    fd = make_test_fd("");
    ASSERT_EQUALS(std::string("1B2M2Y8AsgTpgAmY7PhCfg=="), s3fs_get_content_md5(fd));
    close(fd);
}

int main(int argc, const char *argv[])
{
    if(!s3fs_init_global_ssl()){
        std::abort();
    }

    test_sha256_fd();
    test_sha256_fd_empty();
    test_md5_fd();

    s3fs_destroy_global_ssl();
    return 0;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
