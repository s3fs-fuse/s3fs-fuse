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

//-------------------------------------------------------------------
// Variables
//-------------------------------------------------------------------
static const char c_strErrorObjectName[] = "FILE or SUBDIR in DIR";

// [NOTE]
// mutex for static variables in GetXmlNsUrl
//
static pthread_mutex_t* pxml_parser_mutex = NULL;

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

        if((tmLast + 60) < time(NULL)){
            // refresh
            tmLast = time(NULL);
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

static xmlChar* get_base_exp(xmlDocPtr doc, const char* exp)
{
    xmlXPathObjectPtr  marker_xp;
    std::string xmlnsurl;
    std::string exp_string;

    if(!doc){
        return NULL;
    }
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);

    if(!noxmlns && GetXmlNsUrl(doc, xmlnsurl)){
        xmlXPathRegisterNs(ctx, reinterpret_cast<const xmlChar*>("s3"), reinterpret_cast<const xmlChar*>(xmlnsurl.c_str()));
        exp_string = "/s3:ListBucketResult/s3:";
    } else {
        exp_string = "/ListBucketResult/";
    }

    exp_string += exp;

    if(NULL == (marker_xp = xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(exp_string.c_str()), ctx))){
        xmlXPathFreeContext(ctx);
        return NULL;
    }
    if(xmlXPathNodeSetIsEmpty(marker_xp->nodesetval)){
        S3FS_PRN_ERR("marker_xp->nodesetval is empty.");
        xmlXPathFreeObject(marker_xp);
        xmlXPathFreeContext(ctx);
        return NULL;
    }
    xmlNodeSetPtr nodes  = marker_xp->nodesetval;
    xmlChar*      result = xmlNodeListGetString(doc, nodes->nodeTab[0]->xmlChildrenNode, 1);

    xmlXPathFreeObject(marker_xp);
    xmlXPathFreeContext(ctx);

    return result;
}

static xmlChar* get_prefix(xmlDocPtr doc)
{
    return get_base_exp(doc, "Prefix");
}

xmlChar* get_next_continuation_token(xmlDocPtr doc)
{
    return get_base_exp(doc, "NextContinuationToken");
}

xmlChar* get_next_marker(xmlDocPtr doc)
{
    return get_base_exp(doc, "NextMarker");
}

// return: the pointer to object name on allocated memory.
//         the pointer to "c_strErrorObjectName".(not allocated)
//         NULL(a case of something error occurred)
static char* get_object_name(xmlDocPtr doc, xmlNodePtr node, const char* path)
{
    // Get full path
    xmlChar* fullpath = xmlNodeListGetString(doc, node, 1);
    if(!fullpath){
        S3FS_PRN_ERR("could not get object full path name..");
        return NULL;
    }
    // basepath(path) is as same as fullpath.
    if(0 == strcmp(reinterpret_cast<char*>(fullpath), path)){
        xmlFree(fullpath);
        return const_cast<char*>(c_strErrorObjectName);
    }

    // Make dir path and filename
    std::string   strdirpath = mydirname(std::string(reinterpret_cast<char*>(fullpath)));
    std::string   strmybpath = mybasename(std::string(reinterpret_cast<char*>(fullpath)));
    const char* dirpath = strdirpath.c_str();
    const char* mybname = strmybpath.c_str();
    const char* basepath= (path && '/' == path[0]) ? &path[1] : path;
    xmlFree(fullpath);

    if('\0' == mybname[0]){
        return NULL;
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

static xmlChar* get_exp_value_xml(xmlDocPtr doc, xmlXPathContextPtr ctx, const char* exp_key)
{
    if(!doc || !ctx || !exp_key){
        return NULL;
    }

    xmlXPathObjectPtr exp;
    xmlNodeSetPtr     exp_nodes;
    xmlChar*          exp_value;

    // search exp_key tag
    if(NULL == (exp = xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(exp_key), ctx))){
        S3FS_PRN_ERR("Could not find key(%s).", exp_key);
        return NULL;
    }
    if(xmlXPathNodeSetIsEmpty(exp->nodesetval)){
        S3FS_PRN_ERR("Key(%s) node is empty.", exp_key);
        S3FS_XMLXPATHFREEOBJECT(exp);
        return NULL;
    }
    // get exp_key value & set in struct
    exp_nodes = exp->nodesetval;
    if(NULL == (exp_value = xmlNodeListGetString(doc, exp_nodes->nodeTab[0]->xmlChildrenNode, 1))){
        S3FS_PRN_ERR("Key(%s) value is empty.", exp_key);
        S3FS_XMLXPATHFREEOBJECT(exp);
        return NULL;
    }

    S3FS_XMLXPATHFREEOBJECT(exp);
    return exp_value;
}

bool get_incomp_mpu_list(xmlDocPtr doc, incomp_mpu_list_t& list)
{
    if(!doc){
        return false;
    }

    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);;

    std::string xmlnsurl;
    std::string ex_upload = "//";
    std::string ex_key;
    std::string ex_id;
    std::string ex_date;

    if(!noxmlns && GetXmlNsUrl(doc, xmlnsurl)){
        xmlXPathRegisterNs(ctx, reinterpret_cast<const xmlChar*>("s3"), reinterpret_cast<const xmlChar*>(xmlnsurl.c_str()));
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
    xmlXPathObjectPtr  upload_xp;
    if(NULL == (upload_xp = xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(ex_upload.c_str()), ctx))){
        S3FS_PRN_ERR("xmlXPathEvalExpression returns null.");
        return false;
    }
    if(xmlXPathNodeSetIsEmpty(upload_xp->nodesetval)){
        S3FS_PRN_INFO("upload_xp->nodesetval is empty.");
        S3FS_XMLXPATHFREEOBJECT(upload_xp);
        S3FS_XMLXPATHFREECONTEXT(ctx);
        return true;
    }

    // Make list
    int           cnt;
    xmlNodeSetPtr upload_nodes;
    list.clear();
    for(cnt = 0, upload_nodes = upload_xp->nodesetval; cnt < upload_nodes->nodeNr; cnt++){
        ctx->node = upload_nodes->nodeTab[cnt];

        INCOMP_MPU_INFO part;
        xmlChar*        ex_value;

        // search "Key" tag
        if(NULL == (ex_value = get_exp_value_xml(doc, ctx, ex_key.c_str()))){
            continue;
        }
        if('/' != *(reinterpret_cast<char*>(ex_value))){
            part.key = "/";
        }else{
            part.key = "";
        }
        part.key += reinterpret_cast<char*>(ex_value);
        S3FS_XMLFREE(ex_value);

        // search "UploadId" tag
        if(NULL == (ex_value = get_exp_value_xml(doc, ctx, ex_id.c_str()))){
            continue;
        }
        part.id = reinterpret_cast<char*>(ex_value);
        S3FS_XMLFREE(ex_value);

        // search "Initiated" tag
        if(NULL == (ex_value = get_exp_value_xml(doc, ctx, ex_date.c_str()))){
            continue;
        }
        part.date = reinterpret_cast<char*>(ex_value);
        S3FS_XMLFREE(ex_value);

        list.push_back(part);
    }

    S3FS_XMLXPATHFREEOBJECT(upload_xp);
    S3FS_XMLXPATHFREECONTEXT(ctx);

    return true;
}

bool is_truncated(xmlDocPtr doc)
{
    bool result = false;

    xmlChar* strTruncate = get_base_exp(doc, "IsTruncated");
    if(!strTruncate){
        return false;
    }
    if(0 == strcasecmp(reinterpret_cast<const char*>(strTruncate), "true")){
        result = true;
    }
    xmlFree(strTruncate);
    return result;
}

int append_objects_from_xml_ex(const char* path, xmlDocPtr doc, xmlXPathContextPtr ctx, const char* ex_contents, const char* ex_key, const char* ex_etag, int isCPrefix, S3ObjList& head)
{
    xmlXPathObjectPtr contents_xp;
    xmlNodeSetPtr content_nodes;

    if(NULL == (contents_xp = xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(ex_contents), ctx))){
        S3FS_PRN_ERR("xmlXPathEvalExpression returns null.");
        return -1;
    }
    if(xmlXPathNodeSetIsEmpty(contents_xp->nodesetval)){
        S3FS_PRN_DBG("contents_xp->nodesetval is empty.");
        S3FS_XMLXPATHFREEOBJECT(contents_xp);
        return 0;
    }
    content_nodes = contents_xp->nodesetval;

    bool is_dir;
    std::string stretag;
    int i;
    for(i = 0; i < content_nodes->nodeNr; i++){
        ctx->node = content_nodes->nodeTab[i];

        // object name
        xmlXPathObjectPtr key;
        if(NULL == (key = xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(ex_key), ctx))){
            S3FS_PRN_WARN("key is null. but continue.");
            continue;
        }
        if(xmlXPathNodeSetIsEmpty(key->nodesetval)){
            S3FS_PRN_WARN("node is empty. but continue.");
            xmlXPathFreeObject(key);
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
                xmlXPathObjectPtr ETag;
                if(NULL != (ETag = xmlXPathEvalExpression(reinterpret_cast<const xmlChar*>(ex_etag), ctx))){
                    if(xmlXPathNodeSetIsEmpty(ETag->nodesetval)){
                        S3FS_PRN_INFO("ETag->nodesetval is empty.");
                    }else{
                        xmlNodeSetPtr etag_nodes = ETag->nodesetval;
                        xmlChar* petag = xmlNodeListGetString(doc, etag_nodes->nodeTab[0]->xmlChildrenNode, 1);
                        if(petag){
                            stretag = reinterpret_cast<char*>(petag);
                            xmlFree(petag);
                        }
                    }
                    xmlXPathFreeObject(ETag);
                }
            }
            if(!head.insert(name, (!stretag.empty() ? stretag.c_str() : NULL), is_dir)){
                S3FS_PRN_ERR("insert_object returns with error.");
                xmlXPathFreeObject(key);
                xmlXPathFreeObject(contents_xp);
                free(name);
                S3FS_MALLOCTRIM(0);
                return -1;
            }
            free(name);
        }else{
            S3FS_PRN_DBG("name is file or subdir in dir. but continue.");
        }
        xmlXPathFreeObject(key);
    }
    S3FS_XMLXPATHFREEOBJECT(contents_xp);

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
    xmlChar* pprefix = get_prefix(doc);
    std::string prefix  = (pprefix ? reinterpret_cast<char*>(pprefix) : path ? path : "");
    if(pprefix){
        xmlFree(pprefix);
    }

    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);

    if(!noxmlns && GetXmlNsUrl(doc, xmlnsurl)){
        xmlXPathRegisterNs(ctx, reinterpret_cast<const xmlChar*>("s3"), reinterpret_cast<const xmlChar*>(xmlnsurl.c_str()));
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

    if(-1 == append_objects_from_xml_ex(prefix.c_str(), doc, ctx, ex_contents.c_str(), ex_key.c_str(), ex_etag.c_str(), 0, head) ||
       -1 == append_objects_from_xml_ex(prefix.c_str(), doc, ctx, ex_cprefix.c_str(), ex_prefix.c_str(), NULL, 1, head) )
    {
        S3FS_PRN_ERR("append_objects_from_xml_ex returns with error.");
        S3FS_XMLXPATHFREECONTEXT(ctx);
        return -1;
    }
    S3FS_XMLXPATHFREECONTEXT(ctx);

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

    xmlDocPtr doc;
    if(NULL == (doc = xmlReadMemory(data, static_cast<int>(len), "", NULL, 0))){
        return false;
    }

    if(NULL == doc->children){
        S3FS_XMLFREEDOC(doc);
        return false;
    }
    for(xmlNodePtr cur_node = doc->children->children; NULL != cur_node; cur_node = cur_node->next){
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
    S3FS_XMLFREEDOC(doc);

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
        pxml_parser_mutex = NULL;
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
    pxml_parser_mutex = NULL;

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
