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
#include <cstdint>
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

//-------------------------------------------------------------------
// xattrs_t
//-------------------------------------------------------------------
//
// Header "x-amz-meta-xattr" is for extended attributes.
// This header is url encoded string which is json formatted.
//   x-amz-meta-xattr:urlencode({"xattr-1":"base64(value-1)","xattr-2":"base64(value-2)","xattr-3":"base64(value-3)"})
//
typedef std::map<std::string, std::string> xattrs_t;

//-------------------------------------------------------------------
// acl_t
//-------------------------------------------------------------------
enum class acl_t : uint8_t {
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

inline const char* str(acl_t value)
{
    switch(value){
    case acl_t::PRIVATE:
        return "private";
    case acl_t::PUBLIC_READ:
        return "public-read";
    case acl_t::PUBLIC_READ_WRITE:
        return "public-read-write";
    case acl_t::AWS_EXEC_READ:
        return "aws-exec-read";
    case acl_t::AUTHENTICATED_READ:
        return "authenticated-read";
    case acl_t::BUCKET_OWNER_READ:
        return "bucket-owner-read";
    case acl_t::BUCKET_OWNER_FULL_CONTROL:
        return "bucket-owner-full-control";
    case acl_t::LOG_DELIVERY_WRITE:
        return "log-delivery-write";
    case acl_t::UNKNOWN:
        return nullptr;
    }
    abort();
}

inline acl_t to_acl(const char *acl)
{
    if(0 == strcmp(acl, "private")){
        return acl_t::PRIVATE;
    }else if(0 == strcmp(acl, "public-read")){
        return acl_t::PUBLIC_READ;
    }else if(0 == strcmp(acl, "public-read-write")){
        return acl_t::PUBLIC_READ_WRITE;
    }else if(0 == strcmp(acl, "aws-exec-read")){
        return acl_t::AWS_EXEC_READ;
    }else if(0 == strcmp(acl, "authenticated-read")){
        return acl_t::AUTHENTICATED_READ;
    }else if(0 == strcmp(acl, "bucket-owner-read")){
        return acl_t::BUCKET_OWNER_READ;
    }else if(0 == strcmp(acl, "bucket-owner-full-control")){
        return acl_t::BUCKET_OWNER_FULL_CONTROL;
    }else if(0 == strcmp(acl, "log-delivery-write")){
        return acl_t::LOG_DELIVERY_WRITE;
    }else{
        return acl_t::UNKNOWN;
    }
}

//-------------------------------------------------------------------
// sse_type_t
//-------------------------------------------------------------------
enum class sse_type_t : uint8_t {
    SSE_DISABLE = 0,      // not use server side encrypting
    SSE_S3,               // server side encrypting by S3 key
    SSE_C,                // server side encrypting by custom key
    SSE_KMS               // server side encrypting by kms id
};

enum class signature_type_t  : uint8_t {
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

    explicit etagpair(const char* petag = nullptr, int part = -1) : etag(petag ? petag : ""), part_num(part) {}

    ~etagpair()
    {
      clear();
    }

    void clear()
    {
        etag.clear();
        part_num = -1;
    }
};

// Requires pointer stability and thus must be a list not a vector
typedef std::list<etagpair> etaglist_t;

struct petagpool
{
    // Requires pointer stability and thus must be a list not a vector
    std::list<etagpair> petaglist;

    ~petagpool()
    {
        clear();
    }

    void clear()
    {
        petaglist.clear();
    }

    etagpair* add(const etagpair& etag_entity)
    {
        petaglist.push_back(etag_entity);
        return &petaglist.back();
    }
};

//
// Each part information for Multipart upload
//
struct filepart
{
    bool         uploaded = false;  // does finish uploading
    std::string  etag;        // expected etag value
    int          fd;          // base file(temporary full file) descriptor
    off_t        startpos;    // seek fd point for uploading
    off_t        size;        // uploading size
    bool         is_copy;     // whether is copy multipart
    etagpair*    petag;       // use only parallel upload

    explicit filepart(bool is_uploaded = false, int _fd = -1, off_t part_start = 0, off_t part_size = -1, bool is_copy_part = false, etagpair* petagpair = nullptr) : fd(_fd), startpos(part_start), size(part_size), is_copy(is_copy_part), petag(petagpair) {}

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
        petag    = nullptr;
    }

    void add_etag_list(etaglist_t& list, int partnum = -1)
    {
        if(-1 == partnum){
            partnum = static_cast<int>(list.size()) + 1;
        }
        list.emplace_back(nullptr, partnum);
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

typedef std::vector<filepart> filepart_list_t;

//
// Each part information for Untreated parts
//
struct untreatedpart
{
    off_t start;            // untreated start position
    off_t size;             // number of untreated bytes
    long  untreated_tag;    // untreated part tag

    explicit untreatedpart(off_t part_start = 0, off_t part_size = 0, long part_untreated_tag = 0) : start(part_start), size(part_size), untreated_tag(part_untreated_tag)
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
    bool check_overlap(off_t chk_start, off_t chk_size) const
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

typedef std::vector<untreatedpart> untreated_list_t;

//
// Information on each part of multipart upload
//
struct mp_part
{
    off_t  start;
    off_t  size;
    int    part_num;        // Set only for information to upload

    explicit mp_part(off_t set_start = 0, off_t set_size = 0, int part = 0) : start(set_start), size(set_size), part_num(part) {}
};

typedef std::vector<struct mp_part> mp_part_list_t;

inline off_t total_mp_part_list(const mp_part_list_t& mplist)
{
    off_t size = 0;
    for(mp_part_list_t::const_iterator iter = mplist.begin(); iter != mplist.end(); ++iter){
        size += iter->size;
    }
    return size;
}

//
// Rename directory struct
//
struct mvnode
{
    mvnode(std::string old_path, std::string new_path, bool is_dir, bool is_normdir)
        : old_path(std::move(old_path))
        , new_path(std::move(new_path))
        , is_dir(is_dir)
        , is_normdir(is_normdir)
    {}
    std::string old_path;
    std::string new_path;
    bool is_dir;
    bool is_normdir;
};

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
typedef std::vector<std::string>           readline_t;
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
