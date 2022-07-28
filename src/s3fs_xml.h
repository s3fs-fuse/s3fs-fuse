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

#ifndef S3FS_S3FS_XML_H_
#define S3FS_S3FS_XML_H_

#include <libxml/xpath.h>

#include <string>

#include "mpu_util.h"

class S3ObjList;

//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
bool is_truncated(xmlDocPtr doc);
int append_objects_from_xml_ex(const char* path, xmlDocPtr doc, xmlXPathContextPtr ctx, const char* ex_contents, const char* ex_key, const char* ex_etag, int isCPrefix, S3ObjList& head);
int append_objects_from_xml(const char* path, xmlDocPtr doc, S3ObjList& head);
xmlChar* get_next_continuation_token(xmlDocPtr doc);
xmlChar* get_next_marker(xmlDocPtr doc);
bool get_incomp_mpu_list(xmlDocPtr doc, incomp_mpu_list_t& list);

bool simple_parse_xml(const char* data, size_t len, const char* key, std::string& value);

bool init_parser_xml_lock();
bool destroy_parser_xml_lock();

#endif // S3FS_S3FS_XML_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
