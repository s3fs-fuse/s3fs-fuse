/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2007 Takeshi Nakatani <ggtakec.com>
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
#include <libxml/xpathInternals.h>

#include "common.h"
#include "s3fs.h"
#include "s3fs_logger.h"
#include "s3fs_xml.h"
#include "s3fs_util.h"
#include "s3objlist.h"
#include "autolock.h"
#include "string_util.h"

//-------------------------------------------------------------------
// Variables
//-------------------------------------------------------------------
static constexpr char c_strErrorObjectName[] = "FILE or SUBDIR in DIR";

// [NOTE]
// mutex for static variables in GetXmlNsUrl
//
static pthread_mutex_t* pxml_parser_mutex = nullptr;

//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
static bool GetXmlNsUrl(xmlDocPtr doc, std::string& nsurl)
{
    bool result = false;

    if(!pxml_parser_mutex || !doc){
        return result;
    }

    std::string tmpNs;
    {
        static time_t tmLast = 0;  // cache for 60 sec.
        static std::string strNs;

        AutoLock lock(pxml_parser_mutex);

        if((tmLast + 60) < time(nullptr)){
            // refresh
            tmLast = time(nullptr);
            strNs  = "";
            xmlNodePtr pRootNode = xmlDocGetRootElement(doc);
            if(pRootNode){
                xmlNsPtr* nslist = xmlGetNsList(doc, pRootNode);
                if(nslist){
                    if(nslist[0] && nslist[0]->href){
                        int len = xmlStrlen(nslist[0]->href);
                        if(0 < len){
                            strNs = std::string(reinterpret_cast<const char*>(nslist[0]->href), len);
                        }
                    }
                    S3FS_XMLFREE(nslist);
                }
            }
        }
        tmpNs = strNs;
    }
    if(!tmpNs.empty()){
        nsurl  = tmpNs;
        result = true;
    }
    return result;
}

static unique_ptr_xmlChar get_base_exp(xmlDocPtr doc, const char* exp)
{
    std::string xmlnsurl;
    std::string exp_string;

    if(!doc){
        return {nullptr, xmlFree};
    }
    unique_ptr_xmlXPathContext ctx(xmlXPathNewContext(doc), xmlXPathFreeContext);

    if(!noxmlns && GetXmlNsUrl(doc, xmlnsurl)){
        xmlXPathRegisterNs(ctx.get(), reinterpret_cast<const xmlChar*>("s3"), reinterpret_cast<const xmlChar*>(xmlnsurl.c_str()));
        exp_string = "/s3:ListBucketResult/s3:";
    } else {
        exp_string = "/ListBucketResult/";
    }

    exp_string += exp;

    unique_ptr_xmlXPathObject marker_xp(xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(exp_string.c_str()), ctx.get()), xmlXPathFreeObject);
    if(nullptr == marker_xp){
        return {nullptr, xmlFree};
    }
    if(xmlXPathNodeSetIsEmpty(marker_xp->nodesetval)){
        S3FS_PRN_ERR("marker_xp->nodesetval is empty.");
        return {nullptr, xmlFree};
    }
    xmlNodeSetPtr nodes  = marker_xp->nodesetval;

    unique_ptr_xmlChar result(xmlNodeListGetString(doc, nodes->nodeTab[0]->xmlChildrenNode, 1), xmlFree);
    return result;
}

static unique_ptr_xmlChar get_prefix(xmlDocPtr doc)
{
    return get_base_exp(doc, "Prefix");
}

unique_ptr_xmlChar get_next_continuation_token(xmlDocPtr doc)
{
    return get_base_exp(doc, "NextContinuationToken");
}

unique_ptr_xmlChar get_next_marker(xmlDocPtr doc)
{
    return get_base_exp(doc, "NextMarker");
}

// return: the pointer to object name on allocated memory.
//         the pointer to "c_strErrorObjectName".(not allocated)
//         nullptr(a case of something error occurred)
static char* get_object_name(xmlDocPtr doc, xmlNodePtr node, const char* path)
{
    // Get full path
    unique_ptr_xmlChar fullpath(xmlNodeListGetString(doc, node, 1), xmlFree);
    if(!fullpath){
        S3FS_PRN_ERR("could not get object full path name..");
        return nullptr;
    }
    // basepath(path) is as same as fullpath.
    if(0 == strcmp(reinterpret_cast<char*>(fullpath.get()), path)){
        return const_cast<char*>(c_strErrorObjectName);
    }

    // Make dir path and filename
    std::string strdirpath = mydirname(reinterpret_cast<const char*>(fullpath.get()));
    std::string strmybpath = mybasename(reinterpret_cast<const char*>(fullpath.get()));
    const char* dirpath = strdirpath.c_str();
    const char* mybname = strmybpath.c_str();
    const char* basepath= (path && '/' == path[0]) ? &path[1] : path;

    if('\0' == mybname[0]){
        return nullptr;
    }

    // check subdir & file in subdir
    if(0 < strlen(dirpath)){
        // case of "/"
        if(0 == strcmp(mybname, "/") && 0 == strcmp(dirpath, "/")){
            return const_cast<char*>(c_strErrorObjectName);
        }
        // case of "."
        if(0 == strcmp(mybname, ".") && 0 == strcmp(dirpath, ".")){
            return const_cast<char *>(c_strErrorObjectName);
        }
        // case of ".."
        if(0 == strcmp(mybname, "..") && 0 == strcmp(dirpath, ".")){
            return const_cast<char *>(c_strErrorObjectName);
        }
        // case of "name"
        if(0 == strcmp(dirpath, ".")){
            // OK
            return strdup(mybname);
        }else{
            if(basepath && 0 == strcmp(dirpath, basepath)){
                // OK
                return strdup(mybname);
            }else if(basepath && 0 < strlen(basepath) && '/' == basepath[strlen(basepath) - 1] && 0 == strncmp(dirpath, basepath, strlen(basepath) - 1)){
                std::string withdirname;
                if(strlen(dirpath) > strlen(basepath)){
                    withdirname = &dirpath[strlen(basepath)];
                }
                // cppcheck-suppress unmatchedSuppression
                // cppcheck-suppress knownConditionTrueFalse
                if(!withdirname.empty() && '/' != *withdirname.rbegin()){
                    withdirname += "/";
                }
                withdirname += mybname;
                return strdup(withdirname.c_str());
            }
        }
    }
    // case of something wrong
    return const_cast<char*>(c_strErrorObjectName);
}

static unique_ptr_xmlChar get_exp_value_xml(xmlDocPtr doc, xmlXPathContextPtr ctx, const char* exp_key)
{
    if(!doc || !ctx || !exp_key){
        return {nullptr, xmlFree};
    }

    xmlNodeSetPtr     exp_nodes;

    // search exp_key tag
    unique_ptr_xmlXPathObject exp(xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(exp_key), ctx), xmlXPathFreeObject);
    if(nullptr == exp){
        S3FS_PRN_ERR("Could not find key(%s).", exp_key);
        return {nullptr, xmlFree};
    }
    if(xmlXPathNodeSetIsEmpty(exp->nodesetval)){
        S3FS_PRN_ERR("Key(%s) node is empty.", exp_key);
        return {nullptr, xmlFree};
    }
    // get exp_key value & set in struct
    exp_nodes = exp->nodesetval;
    unique_ptr_xmlChar exp_value(xmlNodeListGetString(doc, exp_nodes->nodeTab[0]->xmlChildrenNode, 1), xmlFree);
    if(nullptr == exp_value){
        S3FS_PRN_ERR("Key(%s) value is empty.", exp_key);
        return {nullptr, xmlFree};
    }

    return exp_value;
}

bool get_incomp_mpu_list(xmlDocPtr doc, incomp_mpu_list_t& list)
{
    if(!doc){
        return false;
    }

    unique_ptr_xmlXPathContext ctx(xmlXPathNewContext(doc), xmlXPathFreeContext);

    std::string xmlnsurl;
    std::string ex_upload = "//";
    std::string ex_key;
    std::string ex_id;
    std::string ex_date;

    if(!noxmlns && GetXmlNsUrl(doc, xmlnsurl)){
        xmlXPathRegisterNs(ctx.get(), reinterpret_cast<const xmlChar*>("s3"), reinterpret_cast<const xmlChar*>(xmlnsurl.c_str()));
        ex_upload += "s3:";
        ex_key    += "s3:";
        ex_id     += "s3:";
        ex_date   += "s3:";
    }
    ex_upload += "Upload";
    ex_key    += "Key";
    ex_id     += "UploadId";
    ex_date   += "Initiated";

    // get "Upload" Tags
    unique_ptr_xmlXPathObject upload_xp(xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(ex_upload.c_str()), ctx.get()), xmlXPathFreeObject);
    if(nullptr == upload_xp){
        S3FS_PRN_ERR("xmlXPathEvalExpression returns null.");
        return false;
    }
    if(xmlXPathNodeSetIsEmpty(upload_xp->nodesetval)){
        S3FS_PRN_INFO("upload_xp->nodesetval is empty.");
        return true;
    }

    // Make list
    int           cnt;
    xmlNodeSetPtr upload_nodes;
    list.clear();
    for(cnt = 0, upload_nodes = upload_xp->nodesetval; cnt < upload_nodes->nodeNr; cnt++){
        ctx->node = upload_nodes->nodeTab[cnt];

        INCOMP_MPU_INFO part;

        // search "Key" tag
        unique_ptr_xmlChar ex_value(get_exp_value_xml(doc, ctx.get(), ex_key.c_str()));
        if(nullptr == ex_value){
            continue;
        }
        if('/' != *(reinterpret_cast<char*>(ex_value.get()))){
            part.key = "/";
        }else{
            part.key = "";
        }
        part.key += reinterpret_cast<char*>(ex_value.get());

        // search "UploadId" tag
        if(nullptr == (ex_value = get_exp_value_xml(doc, ctx.get(), ex_id.c_str()))){
            continue;
        }
        part.id = reinterpret_cast<char*>(ex_value.get());

        // search "Initiated" tag
        if(nullptr == (ex_value = get_exp_value_xml(doc, ctx.get(), ex_date.c_str()))){
            continue;
        }
        part.date = reinterpret_cast<char*>(ex_value.get());

        list.push_back(part);
    }

    return true;
}

bool is_truncated(xmlDocPtr doc)
{
    unique_ptr_xmlChar strTruncate(get_base_exp(doc, "IsTruncated"));
    if(!strTruncate){
        return false;
    }
    return 0 == strcasecmp(reinterpret_cast<const char*>(strTruncate.get()), "true");
}

int append_objects_from_xml_ex(const char* path, xmlDocPtr doc, xmlXPathContextPtr ctx, const char* ex_contents, const char* ex_key, const char* ex_etag, int isCPrefix, S3ObjList& head, bool prefix)
{
    xmlNodeSetPtr content_nodes;

    unique_ptr_xmlXPathObject contents_xp(xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(ex_contents), ctx), xmlXPathFreeObject);
    if(nullptr == contents_xp){
        S3FS_PRN_ERR("xmlXPathEvalExpression returns null.");
        return -1;
    }
    if(xmlXPathNodeSetIsEmpty(contents_xp->nodesetval)){
        S3FS_PRN_DBG("contents_xp->nodesetval is empty.");
        return 0;
    }
    content_nodes = contents_xp->nodesetval;

    bool is_dir;
    std::string stretag;
    int i;
    for(i = 0; i < content_nodes->nodeNr; i++){
        ctx->node = content_nodes->nodeTab[i];

        // object name
        unique_ptr_xmlXPathObject key(xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(ex_key), ctx), xmlXPathFreeObject);
        if(nullptr == key){
            S3FS_PRN_WARN("key is null. but continue.");
            continue;
        }
        if(xmlXPathNodeSetIsEmpty(key->nodesetval)){
            S3FS_PRN_WARN("node is empty. but continue.");
            continue;
        }
        xmlNodeSetPtr key_nodes = key->nodesetval;
        char* name = get_object_name(doc, key_nodes->nodeTab[0]->xmlChildrenNode, path);

        if(!name){
            S3FS_PRN_WARN("name is something wrong. but continue.");

        }else if(reinterpret_cast<const char*>(name) != c_strErrorObjectName){
            is_dir  = isCPrefix ? true : false;
            stretag = "";

            if(!isCPrefix && ex_etag){
                // Get ETag
                unique_ptr_xmlXPathObject ETag(xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(ex_etag), ctx), xmlXPathFreeObject);
                if(nullptr != ETag){
                    if(xmlXPathNodeSetIsEmpty(ETag->nodesetval)){
                        S3FS_PRN_INFO("ETag->nodesetval is empty.");
                    }else{
                        xmlNodeSetPtr etag_nodes = ETag->nodesetval;
                        unique_ptr_xmlChar petag(xmlNodeListGetString(doc, etag_nodes->nodeTab[0]->xmlChildrenNode, 1), xmlFree);
                        if(petag){
                            stretag = reinterpret_cast<const char*>(petag.get());
                        }
                    }
                }
            }

            // [NOTE]
            // The XML data passed to this function is CR code(\r) encoded.
            // The function below decodes that encoded CR code.
            //
            std::string decname = get_decoded_cr_code(name);
            free(name);

            if(prefix){
                head.common_prefixes.push_back(decname);
            }
            if(!head.insert(decname.c_str(), (!stretag.empty() ? stretag.c_str() : nullptr), is_dir)){
                S3FS_PRN_ERR("insert_object returns with error.");
                return -1;
            }
        }else{
            S3FS_PRN_DBG("name is file or subdir in dir. but continue.");
        }
    }

    return 0;
}

int append_objects_from_xml(const char* path, xmlDocPtr doc, S3ObjList& head)
{
    std::string xmlnsurl;
    std::string ex_contents = "//";
    std::string ex_key;
    std::string ex_cprefix  = "//";
    std::string ex_prefix;
    std::string ex_etag;

    if(!doc){
        return -1;
    }

    // If there is not <Prefix>, use path instead of it.
    auto pprefix = get_prefix(doc);
    std::string prefix  = (pprefix ? reinterpret_cast<char*>(pprefix.get()) : path ? path : "");

    unique_ptr_xmlXPathContext ctx(xmlXPathNewContext(doc), xmlXPathFreeContext);

    if(!noxmlns && GetXmlNsUrl(doc, xmlnsurl)){
        xmlXPathRegisterNs(ctx.get(), reinterpret_cast<const xmlChar*>("s3"), reinterpret_cast<const xmlChar*>(xmlnsurl.c_str()));
        ex_contents+= "s3:";
        ex_key     += "s3:";
        ex_cprefix += "s3:";
        ex_prefix  += "s3:";
        ex_etag    += "s3:";
    }
    ex_contents+= "Contents";
    ex_key     += "Key";
    ex_cprefix += "CommonPrefixes";
    ex_prefix  += "Prefix";
    ex_etag    += "ETag";

    if(-1 == append_objects_from_xml_ex(prefix.c_str(), doc, ctx.get(), ex_contents.c_str(), ex_key.c_str(), ex_etag.c_str(), 0, head, /*prefix=*/ false) ||
       -1 == append_objects_from_xml_ex(prefix.c_str(), doc, ctx.get(), ex_cprefix.c_str(), ex_prefix.c_str(), nullptr, 1, head, /*prefix=*/ true) )
    {
        S3FS_PRN_ERR("append_objects_from_xml_ex returns with error.");
        return -1;
    }

    return 0;
}

//-------------------------------------------------------------------
// Utility functions
//-------------------------------------------------------------------
bool simple_parse_xml(const char* data, size_t len, const char* key, std::string& value)
{
    bool result = false;

    if(!data || !key){
        return false;
    }
    value.clear();

    std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)> doc(xmlReadMemory(data, static_cast<int>(len), "", nullptr, 0), xmlFreeDoc);
    if(nullptr == doc){
        return false;
    }

    if(nullptr == doc->children){
        return false;
    }
    for(xmlNodePtr cur_node = doc->children->children; nullptr != cur_node; cur_node = cur_node->next){
        // For DEBUG
        // std::string cur_node_name(reinterpret_cast<const char *>(cur_node->name));
        // printf("cur_node_name: %s\n", cur_node_name.c_str());

        if(XML_ELEMENT_NODE == cur_node->type){
            std::string elementName = reinterpret_cast<const char*>(cur_node->name);
            // For DEBUG
            // printf("elementName: %s\n", elementName.c_str());

            if(cur_node->children){
                if(XML_TEXT_NODE == cur_node->children->type){
                    if(elementName == key) {
                        value = reinterpret_cast<const char *>(cur_node->children->content);
                        result    = true;
                        break;
                    }
                }
            }
        }
    }

    return result;
}

//-------------------------------------------------------------------
// Utility for lock
//-------------------------------------------------------------------
bool init_parser_xml_lock()
{
    if(pxml_parser_mutex){
        return false;
    }
    pxml_parser_mutex = new pthread_mutex_t;

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif

    if(0 != pthread_mutex_init(pxml_parser_mutex, &attr)){
        delete pxml_parser_mutex;
        pxml_parser_mutex = nullptr;
        return false;
    }
    return true;
}

bool destroy_parser_xml_lock()
{
    if(!pxml_parser_mutex){
        return false;
    }
    if(0 != pthread_mutex_destroy(pxml_parser_mutex)){
        return false;
    }
    delete pxml_parser_mutex;
    pxml_parser_mutex = nullptr;

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
