/* mod_https.c
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

#include "mod_https.h"
#include <string.h>

/* Examples:
 * GET /.well-known/enterprise-transport-security/keys?fingerprints=[fingerprints]`
 * GET /.well-known/enterprise-transport-security/keys?groups=[groups]&certs=[sigalgs]&context=contextstr
 * GET /index.html HTTP/1.0\r\n\r\n
 */

static const char* kGET = "GET";
static const char* kCrlf = "\r\n";

/* Parse incoming request into `HttpReq` struct */
int wolfKeyMgr_HttpParse(HttpReq* req, char* buf, word32 sz)
{
    int ret = 0;
    char* sec = buf, *endline, *last;
    word32 len = sz;
    word32 itemSz;

    if (req == NULL)  {
        return WOLFKM_BAD_ARGS;
    }

    /* Method */
    if (strncmp(sec, kGET, strlen(kGET)) == 0) {
        req->method = HTTP_METHOD_GET;
        itemSz = strlen(kGET) + 1; /* include space */
        sec += itemSz; len -= itemSz;
        endline = strstr(sec, kCrlf); /* Find end of line */
        if (endline == NULL) {
            return HTTP_ERROR_EXPECTED_CRLF;
        }
        *endline = '\0'; /* null terminate string */

        /* HTTP Header Version */
        /* locate last space */
        last = strrchr(sec, ' ');
        if (last) {
            req->version = last + 1;
            *last = '\0';
        }
        /* Set URI */
        req->uri = sec;
        sec = endline+2;
        len = (word32)((size_t)sec - (size_t)buf);

        /* Parse headers */
        endline = strstr(sec, kCrlf); /* Find end of line */
        while (endline) {
            /* TODO: parse the header elements */
            
            endline = strstr(buf, kCrlf); /* Find end of line */
        }
    }

    return ret;
}
