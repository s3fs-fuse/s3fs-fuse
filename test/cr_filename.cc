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
int main(int argc, const char *argv[])
{
    if(argc != 2){
        fprintf(stderr, "[ERROR] Wrong paraemters\n");
        fprintf(stdout, "[Usage] cr_filename <base file path>\n");
        exit(EXIT_FAILURE);
    }

    int  fd;
    char filepath[4096];
    snprintf(filepath, sizeof(filepath), "%s\r", argv[1]);
    filepath[sizeof(filepath) - 1] = '\0';              // for safety

    // create empty file
    if(-1 == (fd = open(filepath, O_CREAT|O_RDWR, 0644))){
        fprintf(stderr, "[ERROR] Could not open file(%s)\n", filepath);
        exit(EXIT_FAILURE);
    }
    close(fd);

    // stat
    struct stat buf;
    if(0 != stat(filepath, &buf)){
        fprintf(stderr, "[ERROR] Could not get stat for file(%s)\n", filepath);
        exit(EXIT_FAILURE);
    }

    // remove file
    if(0 != unlink(filepath)){
        fprintf(stderr, "[ERROR] Could not remove file(%s)\n", filepath);
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
