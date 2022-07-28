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
#include <cstring>
#include <sstream>
#include <fstream>
#include <strings.h>
#include <vector>

#include "s3fs.h"
#include "addhead.h"
#include "curl_util.h"
#include "s3fs_logger.h"

//-------------------------------------------------------------------
// Symbols
//-------------------------------------------------------------------
#define ADD_HEAD_REGEX              "reg:"

//-------------------------------------------------------------------
// Class AdditionalHeader
//-------------------------------------------------------------------
AdditionalHeader AdditionalHeader::singleton;

//-------------------------------------------------------------------
// Class AdditionalHeader method
//-------------------------------------------------------------------
AdditionalHeader::AdditionalHeader()
{
    if(this == AdditionalHeader::get()){
        is_enable = false;
    }else{
        abort();
    }
}

AdditionalHeader::~AdditionalHeader()
{
    if(this == AdditionalHeader::get()){
        Unload();
    }else{
        abort();
    }
}

bool AdditionalHeader::Load(const char* file)
{
    if(!file){
        S3FS_PRN_WARN("file is NULL.");
        return false;
    }
    Unload();

    std::ifstream AH(file);
    if(!AH.good()){
        S3FS_PRN_WARN("Could not open file(%s).", file);
        return false;
    }

    // read file
    std::string line;
    ADDHEAD *paddhead;
    while(getline(AH, line)){
        if(line.empty()){
            continue;
        }
        if('#' == line[0]){
            continue;
        }
        // load a line
        std::istringstream ss(line);
        std::string        key;           // suffix(key)
        std::string        head;          // additional HTTP header
        std::string        value;         // header value
        if(0 == isblank(line[0])){
            ss >> key;
        }
        if(ss){
            ss >> head;
            if(ss && static_cast<size_t>(ss.tellg()) < line.size()){
                value = line.substr(static_cast<int>(ss.tellg()) + 1);
            }
        }

        // check it
        if(head.empty()){
            if(key.empty()){
                continue;
            }
            S3FS_PRN_ERR("file format error: %s key(suffix) is no HTTP header value.", key.c_str());
            Unload();
            return false;
        }

        paddhead = new ADDHEAD;
        if(0 == strncasecmp(key.c_str(), ADD_HEAD_REGEX, strlen(ADD_HEAD_REGEX))){
            // regex
            if(key.size() <= strlen(ADD_HEAD_REGEX)){
                S3FS_PRN_ERR("file format error: %s key(suffix) does not have key std::string.", key.c_str());
                delete paddhead;
                continue;
            }
            key.erase(0, strlen(ADD_HEAD_REGEX));

          // compile
          regex_t*  preg = new regex_t;
          int       result;
          if(0 != (result = regcomp(preg, key.c_str(), REG_EXTENDED | REG_NOSUB))){ // we do not need matching info
              char    errbuf[256];
              regerror(result, preg, errbuf, sizeof(errbuf));
              S3FS_PRN_ERR("failed to compile regex from %s key by %s.", key.c_str(), errbuf);
              delete preg;
              delete paddhead;
              continue;
          }

          // set
          paddhead->pregex     = preg;
          paddhead->basestring = key;
          paddhead->headkey    = head;
          paddhead->headvalue  = value;

        }else{
            // not regex, directly comparing
            paddhead->pregex     = NULL;
            paddhead->basestring = key;
            paddhead->headkey    = head;
            paddhead->headvalue  = value;
        }

        // add list
        addheadlist.push_back(paddhead);

        // set flag
        if(!is_enable){
            is_enable = true;
        }
    }
    return true;
}

void AdditionalHeader::Unload()
{
    is_enable = false;

    for(addheadlist_t::iterator iter = addheadlist.begin(); iter != addheadlist.end(); ++iter){
        ADDHEAD *paddhead = *iter;
        if(paddhead){
            if(paddhead->pregex){
                regfree(paddhead->pregex);
                delete paddhead->pregex;
            }
            delete paddhead;
        }
    }
    addheadlist.clear();
}

bool AdditionalHeader::AddHeader(headers_t& meta, const char* path) const
{
    if(!is_enable){
        return true;
    }
    if(!path){
        S3FS_PRN_WARN("path is NULL.");
        return false;
    }

    size_t pathlength = strlen(path);

    // loop
    //
    // [NOTE]
    // Because to allow duplicate key, and then scanning the entire table.
    //
    for(addheadlist_t::const_iterator iter = addheadlist.begin(); iter != addheadlist.end(); ++iter){
        const ADDHEAD *paddhead = *iter;
        if(!paddhead){
            continue;
        }

        if(paddhead->pregex){
            // regex
            regmatch_t match;         // not use
            if(0 == regexec(paddhead->pregex, path, 1, &match, 0)){
                // match -> adding header
                meta[paddhead->headkey] = paddhead->headvalue;
            }
        }else{
            // directly comparing
            if(paddhead->basestring.length() < pathlength){
                if(paddhead->basestring.empty() || 0 == strcmp(&path[pathlength - paddhead->basestring.length()], paddhead->basestring.c_str())){
                    // match -> adding header
                    meta[paddhead->headkey] = paddhead->headvalue;
                }
            }
        }
    }
    return true;
}

struct curl_slist* AdditionalHeader::AddHeader(struct curl_slist* list, const char* path) const
{
    headers_t meta;

    if(!AddHeader(meta, path)){
        return list;
    }
    for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
        // Adding header
        list = curl_slist_sort_insert(list, iter->first.c_str(), iter->second.c_str());
    }
    meta.clear();
    S3FS_MALLOCTRIM(0);
    return list;
}

bool AdditionalHeader::Dump() const
{
    if(!S3fsLog::IsS3fsLogDbg()){
        return true;
    }

    std::ostringstream ssdbg;
    int cnt = 1;

    ssdbg << "Additional Header list[" << addheadlist.size() << "] = {" << std::endl;

    for(addheadlist_t::const_iterator iter = addheadlist.begin(); iter != addheadlist.end(); ++iter, ++cnt){
      const ADDHEAD *paddhead = *iter;

      ssdbg << "    [" << cnt << "] = {" << std::endl;

      if(paddhead){
          if(paddhead->pregex){
              ssdbg << "        type\t\t--->\tregex" << std::endl;
          }else{
              ssdbg << "        type\t\t--->\tsuffix matching" << std::endl;
          }
            ssdbg << "        base std::string\t--->\t" << paddhead->basestring << std::endl;
            ssdbg << "        add header\t--->\t"  << paddhead->headkey << ": " << paddhead->headvalue << std::endl;
        }
        ssdbg << "    }" << std::endl;
    }


    ssdbg << "}" << std::endl;

    // print all
    S3FS_PRN_DBG("%s", ssdbg.str().c_str());

    return true;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
