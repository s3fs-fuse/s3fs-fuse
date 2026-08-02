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
#include <unistd.h>

// [NOTE]
// This program calls truncate(2) with a path, unlike the truncate
// command which opens the file and calls ftruncate(2). The filesystem
// receives the request without a file handle, and no file descriptor
// is open for the file.
//
int main(int argc, const char *argv[])
{
    if(argc != 3){
        fprintf(stderr, "[ERROR] Wrong parameters\n");
        fprintf(stdout, "[Usage] path_truncate <file path> <truncate size(bytes)>\n");
        exit(EXIT_FAILURE);
    }

    const char* filepath = argv[1];
    auto        size     = static_cast<off_t>(strtoull(argv[2], nullptr, 10));

    if(0 != truncate(filepath, size)){
        fprintf(stderr, "[ERROR] Could not truncate file(%s) to %lld byte.\n", filepath, static_cast<long long>(size));
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
