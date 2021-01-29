/* mod_https.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolf Key Manager.
 *
 * wolfKeyMgr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfKeyMgr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFKM_HTTP_H
#define WOLFKM_HTTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wkm_types.h"

/* HTTP Types */
typedef enum HttpMethods {
    HTTP_METHOD_UNKNOWN,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_GET,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_TRACE,
    HTTP_METHOD_CONNECT,
} HttpMethods;

typedef struct HttpReq {
    HttpMethods method;
    byte*  uri;
    word32 uriLen;
    char*  version;
} HttpReq;


int wolfKeyMgr_HttpParse(HttpReq* req, byte* buf, word32 sz);



#ifdef __cplusplus
}
#endif

#endif /* WOLFKM_HTTP_H */
