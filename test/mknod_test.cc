/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2021 Andrew Gaul <andrew@gaul.org>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#if !defined(__APPLE__) && !defined(__FreeBSD__)
#include <sys/sysmacros.h>
#endif

//---------------------------------------------------------
// Const
//---------------------------------------------------------
static constexpr char usage_string[]  = "Usage : \"mknod_test <base file path>\"";

static constexpr char str_mode_reg[]  = "REGULAR";
static constexpr char str_mode_chr[]  = "CHARACTER";
static constexpr char str_mode_blk[]  = "BLOCK";
static constexpr char str_mode_fifo[] = "FIFO";
static constexpr char str_mode_sock[] = "SOCK";

static constexpr char str_ext_reg[]   = "reg";
static constexpr char str_ext_chr[]   = "chr";
static constexpr char str_ext_blk[]   = "blk";
static constexpr char str_ext_fifo[]  = "fifo";
static constexpr char str_ext_sock[]  = "sock";

// [NOTE]
// It would be nice if PATH_MAX could be used as is, but since there are
// issues using on Linux and we also must support for macos, this simple
// test program defines a fixed value for simplicity.
//
static constexpr size_t S3FS_TEST_PATH_MAX = 255;
static constexpr size_t MAX_BASE_PATH_LENGTH = S3FS_TEST_PATH_MAX - 5;

//---------------------------------------------------------
// Test function
//---------------------------------------------------------
bool TestMknod(const char* basepath, mode_t mode)
{
    if(!basepath){
        fprintf(stderr, "[ERROR] Called function with wrong basepath argument.\n");
        return false;
    }

    const char* str_mode;
    dev_t       dev;
    char        filepath[S3FS_TEST_PATH_MAX];
    switch(mode){
        case S_IFREG:
            str_mode = str_mode_reg;
            dev      = 0;
            snprintf(filepath, sizeof(filepath), "%s.%s", basepath, str_ext_reg);
            filepath[S3FS_TEST_PATH_MAX - 1] = '\0';    // for safety
            break;
        case S_IFCHR:
            str_mode = str_mode_chr;
            dev      = makedev(0, 0);
            snprintf(filepath, sizeof(filepath), "%s.%s", basepath, str_ext_chr);
            filepath[S3FS_TEST_PATH_MAX - 1] = '\0';    // for safety
            break;
        case S_IFBLK:
            str_mode = str_mode_blk;
            dev      = makedev((unsigned int)(259), 0); // temporary value
            snprintf(filepath, sizeof(filepath), "%s.%s", basepath, str_ext_blk);
            filepath[S3FS_TEST_PATH_MAX - 1] = '\0';    // for safety
            break;
        case S_IFIFO:
            str_mode = str_mode_fifo;
            dev      = 0;
            snprintf(filepath, sizeof(filepath), "%s.%s", basepath, str_ext_fifo);
            filepath[S3FS_TEST_PATH_MAX - 1] = '\0';    // for safety
            break;
        case S_IFSOCK:
            str_mode = str_mode_sock;
            dev      = 0;
            snprintf(filepath, sizeof(filepath), "%s.%s", basepath, str_ext_sock);
            filepath[S3FS_TEST_PATH_MAX - 1] = '\0';    // for safety
            break;
        default:
            fprintf(stderr, "[ERROR] Called function with wrong mode argument.\n");
            return false;
    }

    //
    // Create
    //
    if(0 != mknod(filepath, mode | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, dev)){
        fprintf(stderr, "[ERROR] Could not create %s file(%s) : errno = %d\n", str_mode, filepath, errno);
        return false;
    }

    //
    // Check
    //
    struct stat st;
    if(0 != stat(filepath, &st)){
        fprintf(stderr, "[ERROR] Could not get stat from %s file(%s) : errno = %d\n", str_mode, filepath, errno);
        return false;
    }
    if(mode != (st.st_mode & S_IFMT)){
        fprintf(stderr, "[ERROR] Created %s file(%s) does not have 0%o stat\n", str_mode, filepath, mode);
        return false;
    }

    //
    // Remove
    //
    if(0 != unlink(filepath)){
        fprintf(stderr, "[WARNING] Could not remove %s file(%s) : errno = %d\n", str_mode, filepath, mode);
    }
    return true;
}

//---------------------------------------------------------
// Main
//---------------------------------------------------------
int main(int argc, const char *argv[])
{
    // Parse parameters
    if(2 != argc){
        fprintf(stderr, "[ERROR] No parameter is specified.\n");
        fprintf(stderr, "%s\n", usage_string);
        exit(EXIT_FAILURE);
    }
    if(0 == strcmp("-h", argv[1]) || 0 == strcmp("--help", argv[1])){
        fprintf(stdout, "%s\n", usage_string);
        exit(EXIT_SUCCESS);
    }
    if(MAX_BASE_PATH_LENGTH < strlen(argv[1])){
        fprintf(stderr, "[ERROR] Base file path is too long, it must be less than %zu\n", MAX_BASE_PATH_LENGTH);
        exit(EXIT_FAILURE);
    }

    // Test
    //
    // [NOTE]
    // Privilege is required to execute S_IFBLK.
    //
    if(0 != geteuid()){
        fprintf(stderr, "[WARNING] Skipping mknod(S_IFBLK) due to missing root privileges.\n");
    }
    if(!TestMknod(argv[1], S_IFREG)  ||
       !TestMknod(argv[1], S_IFCHR)  ||
       !TestMknod(argv[1], S_IFIFO)  ||
       !TestMknod(argv[1], S_IFSOCK) ||
       (0 == geteuid() && !TestMknod(argv[1], S_IFBLK)))
    {
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
