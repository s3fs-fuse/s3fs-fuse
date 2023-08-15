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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// [NOTE]
// This is a program used for file size inspection.
// File size checking should be done by the caller of this program.
// This program truncates the file and reads the file in another process
// between truncate and flush(close file).
//
int main(int argc, char *argv[])
{
    if(argc != 3){
        fprintf(stderr, "[ERROR] Wrong paraemters\n");
        fprintf(stdout, "[Usage] truncate_read_file <file path> <truncate size(bytes)>\n");
        exit(EXIT_FAILURE);
    }

    const char* filepath = argv[1];
    off_t       size     = static_cast<off_t>(strtoull(argv[2], nullptr, 10));
    int         fd;

    // open file
    if(-1 == (fd = open(filepath, O_RDWR))){
        fprintf(stderr, "[ERROR] Could not open file(%s)\n", filepath);
        exit(EXIT_FAILURE);
    }

    // truncate
    if(0 != ftruncate(fd, size)){
        fprintf(stderr, "[ERROR] Could not truncate file(%s) to %lld byte.\n", filepath, (long long)size);
        close(fd);
        exit(EXIT_FAILURE);
    }

    // run sub-process for reading file(cat)
    char szCommand[1024];
    snprintf(szCommand, sizeof(szCommand), "cat %s >/dev/null 2>&1", filepath);
    szCommand[sizeof(szCommand) - 1] = '\0';                    // for safety
    if(0 != system(szCommand)){
        fprintf(stderr, "[ERROR] Failed to run sub-process(cat).\n");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // close file(flush)
    close(fd);

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
