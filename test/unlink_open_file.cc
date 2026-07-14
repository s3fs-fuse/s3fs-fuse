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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// [NOTE]
// This program operates on a file which is unlinked while it is still
// open.  FUSE(libfuse) passes a null path to the file handle based
// handlers(read/write/flush/fsync/release and fstat) for such a file,
// especially when mounted with -o hard_remove, and s3fs must serve
// them from the open file descriptor.
//
int main(int argc, const char *argv[])
{
    if(argc != 2){
        fprintf(stderr, "[ERROR] Wrong parameters\n");
        fprintf(stdout, "[Usage] unlink_open_file <file path>\n");
        exit(EXIT_FAILURE);
    }

    const char* filepath = argv[1];
    const char  data[]   = "hello world";
    auto        datalen  = static_cast<ssize_t>(sizeof(data) - 1);
    int         fd;

    // create file
    if(-1 == (fd = open(filepath, O_CREAT | O_EXCL | O_RDWR, 0644))){
        fprintf(stderr, "[ERROR] Could not create file(%s)\n", filepath);
        exit(EXIT_FAILURE);
    }

    // unlink the file while it is open
    if(0 != unlink(filepath)){
        fprintf(stderr, "[ERROR] Could not unlink file(%s)\n", filepath);
        close(fd);
        exit(EXIT_FAILURE);
    }

    // write to the unlinked file
    if(datalen != write(fd, data, datalen)){
        fprintf(stderr, "[ERROR] Could not write to unlinked file(%s)\n", filepath);
        close(fd);
        exit(EXIT_FAILURE);
    }

    // fsync the unlinked file
    if(0 != fsync(fd)){
        fprintf(stderr, "[ERROR] Could not fsync unlinked file(%s)\n", filepath);
        close(fd);
        exit(EXIT_FAILURE);
    }

    // read back and compare
    char buf[sizeof(data)];
    if(datalen != pread(fd, buf, datalen, 0)){
        fprintf(stderr, "[ERROR] Could not read unlinked file(%s)\n", filepath);
        close(fd);
        exit(EXIT_FAILURE);
    }
    if(0 != memcmp(buf, data, datalen)){
        fprintf(stderr, "[ERROR] Read wrong data from unlinked file(%s)\n", filepath);
        close(fd);
        exit(EXIT_FAILURE);
    }

    // fstat the unlinked file
    struct stat st;
    if(0 != fstat(fd, &st)){
        fprintf(stderr, "[ERROR] Could not fstat unlinked file(%s)\n", filepath);
        close(fd);
        exit(EXIT_FAILURE);
    }
    if(datalen != st.st_size){
        fprintf(stderr, "[ERROR] Wrong size(%lld) of unlinked file(%s)\n", static_cast<long long>(st.st_size), filepath);
        close(fd);
        exit(EXIT_FAILURE);
    }

    // close(flush + release)
    if(0 != close(fd)){
        fprintf(stderr, "[ERROR] Could not close unlinked file(%s)\n", filepath);
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
