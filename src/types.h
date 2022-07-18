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

#ifndef S3FS_TYPES_H_
#define S3FS_TYPES_H_

#include <cstdlib>
#include <cstring>
#include <string>
#include <map>
#include <list>
#include <vector>

//
// For extended attribute
// (HAVE_XXX symbols are defined in config.h)
//
#ifdef HAVE_SYS_EXTATTR_H
#include <sys/extattr.h>
#elif HAVE_ATTR_XATTR_H
#include <attr/xattr.h>
#elif HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

#if __cplusplus < 201103L
  #define OPERATOR_EXPLICIT
#else
  #define OPERATOR_EXPLICIT     explicit
#endif

//-------------------------------------------------------------------
// xattrs_t
//-------------------------------------------------------------------
//
// Header "x-amz-meta-xattr" is for extended attributes.
// This header is url encoded string which is json formatted.
//   x-amz-meta-xattr:urlencode({"xattr-1":"base64(value-1)","xattr-2":"base64(value-2)","xattr-3":"base64(value-3)"})
//
typedef struct xattr_value
{
    unsigned char* pvalue;
    size_t         length;

    explicit xattr_value(unsigned char* pval = NULL, size_t len = 0) : pvalue(pval), length(len) {}
    ~xattr_value()
    {
        delete[] pvalue;
    }
}XATTRVAL, *PXATTRVAL;

typedef std::map<std::string, PXATTRVAL> xattrs_t;

//-------------------------------------------------------------------
// acl_t
//-------------------------------------------------------------------
class acl_t{
    public:
        enum Value{
            PRIVATE,
            PUBLIC_READ,
            PUBLIC_READ_WRITE,
            AWS_EXEC_READ,
            AUTHENTICATED_READ,
            BUCKET_OWNER_READ,
            BUCKET_OWNER_FULL_CONTROL,
            LOG_DELIVERY_WRITE,
            UNKNOWN
        };

        // cppcheck-suppress noExplicitConstructor
        acl_t(Value value) : value_(value) {}

        operator Value() const { return value_; }

        const char* str() const
        {
            switch(value_){
                case PRIVATE:
                    return "private";
                case PUBLIC_READ:
                    return "public-read";
                case PUBLIC_READ_WRITE:
                    return "public-read-write";
                case AWS_EXEC_READ:
                    return "aws-exec-read";
                case AUTHENTICATED_READ:
                    return "authenticated-read";
                case BUCKET_OWNER_READ:
                    return "bucket-owner-read";
                case BUCKET_OWNER_FULL_CONTROL:
                    return "bucket-owner-full-control";
                case LOG_DELIVERY_WRITE:
                    return "log-delivery-write";
                case UNKNOWN:
                    return NULL;
            }
            abort();
        }

        static acl_t from_str(const char *acl)
        {
            if(0 == strcmp(acl, "private")){
                return PRIVATE;
            }else if(0 == strcmp(acl, "public-read")){
                return PUBLIC_READ;
            }else if(0 == strcmp(acl, "public-read-write")){
                return PUBLIC_READ_WRITE;
            }else if(0 == strcmp(acl, "aws-exec-read")){
                return AWS_EXEC_READ;
            }else if(0 == strcmp(acl, "authenticated-read")){
                return AUTHENTICATED_READ;
            }else if(0 == strcmp(acl, "bucket-owner-read")){
                return BUCKET_OWNER_READ;
            }else if(0 == strcmp(acl, "bucket-owner-full-control")){
                return BUCKET_OWNER_FULL_CONTROL;
            }else if(0 == strcmp(acl, "log-delivery-write")){
                return LOG_DELIVERY_WRITE;
            }else{
                return UNKNOWN;
            }
        }

    private:
        OPERATOR_EXPLICIT operator bool();
        Value value_;
};

//-------------------------------------------------------------------
// sse_type_t
//-------------------------------------------------------------------
class sse_type_t{
    public:
        enum Value{
            SSE_DISABLE = 0,      // not use server side encrypting
            SSE_S3,               // server side encrypting by S3 key
            SSE_C,                // server side encrypting by custom key
            SSE_KMS               // server side encrypting by kms id
        };

        // cppcheck-suppress noExplicitConstructor
        sse_type_t(Value value) : value_(value) {}

        operator Value() const { return value_; }

    private:
        //OPERATOR_EXPLICIT operator bool();
        Value value_;
};

enum signature_type_t {
    V2_ONLY,
    V4_ONLY,
    V2_OR_V4
};

//----------------------------------------------
// etaglist_t / filepart / untreatedpart
//----------------------------------------------
//
// Etag string and part number pair
//
struct etagpair
{
    std::string  etag;        // expected etag value
    int          part_num;    // part number

    etagpair(const char* petag = NULL, int part = -1) : etag(petag ? petag : ""), part_num(part) {}

    ~etagpair()
    {
      clear();
    }

    void clear()
    {
        etag.erase();
        part_num = -1;
    }
};

typedef std::list<etagpair> etaglist_t;

struct petagpool
{
    std::list<etagpair*> petaglist;

    ~petagpool()
    {
        clear();
    }

    void clear()
    {
        for(std::list<etagpair*>::iterator it = petaglist.begin(); petaglist.end() != it; ++it){
            if(*it){
                delete (*it);
            }
        }
        petaglist.clear();
    }

    etagpair* add(const etagpair& etag_entity)
    {
        etagpair* petag = new etagpair(etag_entity);
        petaglist.push_back(petag);
        return petag;
    }
};

//
// Each part information for Multipart upload
//
struct filepart
{
    bool         uploaded;    // does finish uploading
    std::string  etag;        // expected etag value
    int          fd;          // base file(temporary full file) descriptor
    off_t        startpos;    // seek fd point for uploading
    off_t        size;        // uploading size
    bool         is_copy;     // whether is copy multipart
    etagpair*    petag;       // use only parallel upload

    filepart(bool is_uploaded = false, int _fd = -1, off_t part_start = 0, off_t part_size = -1, bool is_copy_part = false, etagpair* petagpair = NULL) : uploaded(false), fd(_fd), startpos(part_start), size(part_size), is_copy(is_copy_part), petag(petagpair) {}

    ~filepart()
    {
      clear();
    }

    void clear()
    {
        uploaded = false;
        etag     = "";
        fd       = -1;
        startpos = 0;
        size     = -1;
        is_copy  = false;
        petag    = NULL;
    }

    void add_etag_list(etaglist_t& list, int partnum = -1)
    {
        if(-1 == partnum){
            partnum = static_cast<int>(list.size()) + 1;
        }
        list.push_back(etagpair(NULL, partnum));
        petag = &list.back();
    }

    void set_etag(etagpair* petagobj)
    {
        petag = petagobj;
    }

    int get_part_number() const
    {
        if(!petag){
            return -1;
        }
        return petag->part_num;
    }
};

typedef std::list<filepart> filepart_list_t;

//
// Each part information for Untreated parts
//
struct untreatedpart
{
    off_t start;            // untreated start position
    off_t size;             // number of untreated bytes
    long  untreated_tag;    // untreated part tag

    untreatedpart(off_t part_start = 0, off_t part_size = 0, long part_untreated_tag = 0) : start(part_start), size(part_size), untreated_tag(part_untreated_tag)
    {
        if(part_start < 0 || part_size <= 0){
            clear();        // wrong parameter, so clear value.
        }
    }

    ~untreatedpart()
    {
        clear();
    }

    void clear()
    {
        start  = 0;
        size   = 0;
        untreated_tag = 0;
    }

    // [NOTE]
    // Check if the areas overlap
    // However, even if the areas do not overlap, this method returns true if areas are adjacent.
    //
    bool check_overlap(off_t chk_start, off_t chk_size)
    {
        if(chk_start < 0 || chk_size <= 0 || start < 0 || size <= 0 || (chk_start + chk_size) < start || (start + size) < chk_start){
            return false;
        }
        return true;
    }

    bool stretch(off_t add_start, off_t add_size, long tag)
    {
        if(!check_overlap(add_start, add_size)){
            return false;
        }
        off_t new_start      = std::min(start, add_start);
        off_t new_next_start = std::max((start + size), (add_start + add_size));

        start         = new_start;
        size          = new_next_start - new_start;
        untreated_tag = tag;

        return true;
    }
};

typedef std::list<untreatedpart> untreated_list_t;

//
// Information on each part of multipart upload
//
struct mp_part
{
    off_t  start;
    off_t  size;
    int    part_num;        // Set only for information to upload

    mp_part(off_t set_start = 0, off_t set_size = 0, int part = 0) : start(set_start), size(set_size), part_num(part) {}
};

typedef std::list<struct mp_part> mp_part_list_t;

inline off_t total_mp_part_list(const mp_part_list_t& mplist)
{
    off_t size = 0;
    for(mp_part_list_t::const_iterator iter = mplist.begin(); iter != mplist.end(); ++iter){
        size += iter->size;
    }
    return size;
}

//-------------------------------------------------------------------
// mimes_t
//-------------------------------------------------------------------
struct case_insensitive_compare_func
{
    bool operator()(const std::string& a, const std::string& b) const {
        return strcasecmp(a.c_str(), b.c_str()) < 0;
    }
};
typedef std::map<std::string, std::string, case_insensitive_compare_func> mimes_t;

//-------------------------------------------------------------------
// Typedefs specialized for use
//-------------------------------------------------------------------
typedef std::list<std::string>             readline_t;
typedef std::map<std::string, std::string> kvmap_t;
typedef std::map<std::string, kvmap_t>     bucketkvmap_t;

#endif // S3FS_TYPES_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
