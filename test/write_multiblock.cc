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

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <climits>
#include <string>
#include <list>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

//---------------------------------------------------------
// Structures and Typedefs
//---------------------------------------------------------
struct write_block_part
{
    off_t start;
    off_t size;
};

typedef std::list<write_block_part> wbpart_list_t;
typedef std::list<std::string>      strlist_t;

//---------------------------------------------------------
// Const
//---------------------------------------------------------
const char usage_string[] = "Usage : \"write_multiblock -f <file path> -p <start offset:size>\" (allows -f and -p multiple times.)";

//---------------------------------------------------------
// Utility functions
//---------------------------------------------------------
static unsigned char* create_random_data(off_t size)
{
    int fd;
    if(-1 == (fd = open("/dev/urandom", O_RDONLY))){
        std::cerr << "[ERROR] Could not open /dev/urandom" << std::endl;
        return NULL;
    }

    unsigned char* pbuff;
    if(NULL == (pbuff = reinterpret_cast<unsigned char*>(malloc(size)))){
        std::cerr << "[ERROR] Could not allocate memory." << std::endl;
        close(fd);
        return NULL;
    }
    for(ssize_t readpos = 0, readcnt = 0; readpos < size; readpos += readcnt){
        if(-1 == (readcnt = read(fd, &(pbuff[readpos]), static_cast<size_t>(size - readpos)))){
            if(EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno){
                std::cerr << "[ERROR] Failed reading from /dev/urandom with errno: " << errno << std::endl;
                free(pbuff);
                close(fd);
                return NULL;
            }
            readcnt = 0;
        }
    }
    return pbuff;
}

static off_t cvt_string_to_number(const char* pstr)
{
    if(!pstr){
        return -1;
    }

    errno            = 0;
    char*     ptemp  = NULL;
    long long result = strtoll(pstr, &ptemp, 10);

    if(!ptemp || ptemp == pstr || *ptemp != '\0'){
        return -1;
    }
    if((result == LLONG_MIN || result == LLONG_MAX) && errno == ERANGE){
        return -1;
    }

    return static_cast<off_t>(result);
}

static bool parse_string(const char* pstr, char delim, strlist_t& strlist)
{
    if(!pstr){
        return false;
    }
    std::string strAll(pstr);
    while(!strAll.empty()){
        size_t pos = strAll.find_first_of(delim);
        if(std::string::npos != pos){
            strlist.push_back(strAll.substr(0, pos));
            strAll = strAll.substr(pos + 1);
        }else{
            strlist.push_back(strAll);
            strAll.erase();
        }
    }
    return true;
}

static bool parse_write_blocks(const char* pstr, wbpart_list_t& wbparts, off_t& max_size)
{
    if(!pstr){
        return false;
    }

    strlist_t partlist;
    if(!parse_string(pstr, ',', partlist)){
        return false;
    }

    for(strlist_t::const_iterator iter = partlist.begin(); iter != partlist.end(); ++iter){
        strlist_t partpair;
        if(parse_string(iter->c_str(), ':', partpair) && 2 == partpair.size()){
            write_block_part tmp_part;

            tmp_part.start = cvt_string_to_number(partpair.front().c_str());
            partpair.pop_front();
            tmp_part.size  = cvt_string_to_number(partpair.front().c_str());

            if(tmp_part.start < 0 || tmp_part.size <= 0){
                std::cerr << "[ERROR] -p option parameter(" << pstr << ") is something wrong." << std::endl;
                return false;
            }
            if(max_size < tmp_part.size){
                max_size = tmp_part.size;
            }
            wbparts.push_back(tmp_part);
        }else{
            std::cerr << "[ERROR] -p option parameter(" << pstr << ") is something wrong." << std::endl;
            return false;
        }
    }
    return true;
}

static bool parse_arguments(int argc, char** argv, strlist_t& files, wbpart_list_t& wbparts, off_t& max_size)
{
    if(argc < 2 || !argv){
        std::cerr << "[ERROR] The -f option and -p option are required as arguments." << std::endl;
        std::cerr << usage_string << std::endl;
        return false;
    }
    files.clear();
    wbparts.clear();
    max_size = 0;

    int opt;
    while(-1 != (opt = getopt(argc, argv, "f:p:"))){
        switch(opt){
            case 'f':
                files.push_back(std::string(optarg));
                break;
            case 'p':
                if(!parse_write_blocks(optarg, wbparts, max_size)){
                    return false;
                }
                break;
            default:
                std::cerr << usage_string << std::endl;
                return false;
        }
    }

    if(files.empty() || wbparts.empty()){
        std::cerr << "[ERROR] The -f option and -p option are required as arguments." << std::endl;
        std::cerr << usage_string << std::endl;
        return false;
    }
    return true;
}

//---------------------------------------------------------
// Main
//---------------------------------------------------------
int main(int argc, char** argv)
{
    // parse arguments
    strlist_t     files;
    wbpart_list_t wbparts;
    off_t         max_size = 0;
    if(!parse_arguments(argc, argv, files, wbparts, max_size)){
        exit(EXIT_FAILURE);
    }

    // make data and buffer
    unsigned char* pData;
    if(NULL == (pData = create_random_data(max_size))){
        exit(EXIT_FAILURE);
    }

    for(strlist_t::const_iterator fiter = files.begin(); fiter != files.end(); ++fiter){
        // open/create file
        int         fd;
        struct stat st;
        if(0 == stat(fiter->c_str(), &st)){
            if(!S_ISREG(st.st_mode)){
                std::cerr << "[ERROR] File " << fiter->c_str() << " is existed, but it is not regular file." << std::endl;
                free(pData);
                exit(EXIT_FAILURE);
            }
            if(-1 == (fd = open(fiter->c_str(), O_WRONLY))){
                std::cerr << "[ERROR] Could not open " << fiter->c_str() << std::endl;
                free(pData);
                exit(EXIT_FAILURE);
            }
        }else{
            if(-1 == (fd = open(fiter->c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644))){
                std::cerr << "[ERROR] Could not create " << fiter->c_str() << std::endl;
                free(pData);
                exit(EXIT_FAILURE);
            }
        }

        // write blocks
        for(wbpart_list_t::const_iterator piter = wbparts.begin(); piter != wbparts.end(); ++piter){
            // write one block
            for(ssize_t writepos = 0, writecnt = 0; writepos < piter->size; writepos += writecnt){
                if(-1 == (writecnt = pwrite(fd, &(pData[writepos]), static_cast<size_t>(piter->size - writepos), (piter->start + writepos)))){
                    if(EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno){
                        std::cerr << "[ERROR] Failed writing to " << fiter->c_str() << " by errno : " << errno << std::endl;
                        close(fd);
                        free(pData);
                        exit(EXIT_FAILURE);
                    }
                    writecnt = 0;
                }
            }
        }
        // close file
        close(fd);
    }
    free(pData);

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
