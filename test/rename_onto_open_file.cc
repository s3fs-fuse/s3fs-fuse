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

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

// [NOTE]
// This program renames one open file over another open file, which is the
// case that leaves two file descriptors on the same path: the renamed file
// takes the destination path, while the replaced file keeps living without
// a name for whoever still has it open.  s3fs must keep both of them, must
// serve a new open of the destination from the renamed file, and must never
// write the replaced file back to the destination path.
//
// Both files are held open, because s3fs only renames its fd entity when
// the source is open.
//

static const char SRC_DATA[] = "source";
static const char DST_DATA[] = "destination-file-contents";

static bool write_file(const char* filepath, const char* data)
{
    int fd;
    if(-1 == (fd = open(filepath, O_CREAT | O_TRUNC | O_WRONLY, 0644))){
        fprintf(stderr, "[ERROR] Could not create file(%s) by errno(%d)\n", filepath, errno);
        return false;
    }
    auto datalen = static_cast<ssize_t>(strlen(data));
    if(datalen != write(fd, data, datalen)){
        fprintf(stderr, "[ERROR] Could not write to file(%s) by errno(%d)\n", filepath, errno);
        close(fd);
        return false;
    }
    if(0 != close(fd)){
        fprintf(stderr, "[ERROR] Could not close file(%s) by errno(%d)\n", filepath, errno);
        return false;
    }
    return true;
}

// Opens the path anew and compares its contents against expected data.
static bool check_file(const char* filepath, const char* data)
{
    int fd;
    if(-1 == (fd = open(filepath, O_RDONLY))){
        fprintf(stderr, "[ERROR] Could not open file(%s) by errno(%d)\n", filepath, errno);
        return false;
    }

    char    buf[128];
    ssize_t readlen;
    if(-1 == (readlen = pread(fd, buf, sizeof(buf), 0))){
        fprintf(stderr, "[ERROR] Could not read file(%s) by errno(%d)\n", filepath, errno);
        close(fd);
        return false;
    }
    close(fd);

    auto datalen = static_cast<ssize_t>(strlen(data));
    if(readlen != datalen || 0 != memcmp(buf, data, datalen)){
        fprintf(stderr, "[ERROR] File(%s) has wrong contents(%.*s), expected(%s)\n", filepath, static_cast<int>(readlen), buf, data);
        return false;
    }
    return true;
}

int main(int argc, const char *argv[])
{
    if(argc != 3){
        fprintf(stderr, "[ERROR] Wrong parameters\n");
        fprintf(stdout, "[Usage] rename_onto_open_file <source path> <destination path>\n");
        exit(EXIT_FAILURE);
    }
    const char* srcpath = argv[1];
    const char* dstpath = argv[2];

    if(!write_file(dstpath, DST_DATA) || !write_file(srcpath, SRC_DATA)){
        exit(EXIT_FAILURE);
    }

    // hold both files open over the rename
    int dstfd;
    if(-1 == (dstfd = open(dstpath, O_RDWR))){
        fprintf(stderr, "[ERROR] Could not open file(%s) by errno(%d)\n", dstpath, errno);
        exit(EXIT_FAILURE);
    }
    int srcfd;
    if(-1 == (srcfd = open(srcpath, O_RDONLY))){
        fprintf(stderr, "[ERROR] Could not open file(%s) by errno(%d)\n", srcpath, errno);
        close(dstfd);
        exit(EXIT_FAILURE);
    }

    // [NOTE]
    // Read the destination through its descriptor before the rename, which
    // both checks its contents and makes s3fs hold all of them locally.  The
    // object behind the file is gone once it has been renamed over, so what
    // has not been read by then can never be read again.
    //
    char    replaced[sizeof(DST_DATA)];
    ssize_t replacedlen;
    auto    dstlen = static_cast<ssize_t>(strlen(DST_DATA));
    if(dstlen != (replacedlen = pread(dstfd, replaced, sizeof(replaced), 0)) || 0 != memcmp(replaced, DST_DATA, dstlen)){
        fprintf(stderr, "[ERROR] File(%s) has wrong contents(%.*s) by errno(%d)\n", dstpath, static_cast<int>(replacedlen < 0 ? 0 : replacedlen), replaced, errno);
        close(srcfd);
        close(dstfd);
        exit(EXIT_FAILURE);
    }

    if(0 != rename(srcpath, dstpath)){
        fprintf(stderr, "[ERROR] Could not rename file(%s) to file(%s) by errno(%d)\n", srcpath, dstpath, errno);
        close(srcfd);
        close(dstfd);
        exit(EXIT_FAILURE);
    }

    // a new open of the destination must find the renamed file
    if(!check_file(dstpath, SRC_DATA)){
        close(srcfd);
        close(dstfd);
        exit(EXIT_FAILURE);
    }

    // [NOTE]
    // The replaced file is still open, so it must still be readable and
    // writable through this descriptor, and it must keep its own contents
    // rather than those of the file which took its name.
    //
    const char clobber[] = "XXXXXX";
    auto       clobberlen = static_cast<ssize_t>(sizeof(clobber) - 1);
    if(clobberlen != pwrite(dstfd, clobber, clobberlen, 0)){
        fprintf(stderr, "[ERROR] Could not write to the replaced file(%s) by errno(%d)\n", dstpath, errno);
        close(srcfd);
        close(dstfd);
        exit(EXIT_FAILURE);
    }

    if(dstlen != (replacedlen = pread(dstfd, replaced, sizeof(replaced), 0)) || 0 != memcmp(replaced + clobberlen, DST_DATA + clobberlen, dstlen - clobberlen)){
        fprintf(stderr, "[ERROR] The replaced file(%s) has wrong contents(%.*s) by errno(%d)\n", dstpath, static_cast<int>(replacedlen < 0 ? 0 : replacedlen), replaced, errno);
        close(srcfd);
        close(dstfd);
        exit(EXIT_FAILURE);
    }

    // close(flush + release) of the replaced file must not write it back
    if(0 != close(dstfd)){
        fprintf(stderr, "[ERROR] Could not close the replaced file(%s) by errno(%d)\n", dstpath, errno);
        close(srcfd);
        exit(EXIT_FAILURE);
    }
    if(0 != close(srcfd)){
        fprintf(stderr, "[ERROR] Could not close the renamed file(%s) by errno(%d)\n", srcpath, errno);
        exit(EXIT_FAILURE);
    }

    if(!check_file(dstpath, SRC_DATA)){
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
