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

static const char kHttpServerMsg[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n"
    "Content-Length: 141\r\n"
    "\r\n"
    "<html>\r\n"
    "<head>\r\n"
    "<title>Welcome to wolfSSL!</title>\r\n"
    "</head>\r\n"
    "<body>\r\n"
    "<p>wolfSSL has successfully performed handshake!</p>\r\n"
    "</body>\r\n"
    "</html>\r\n";



/* Parse incoming request into `HttpReq` struct */
int wolfKeyMgr_HttpParse(HttpReq* req, byte* buf, unsigned int sz)
{
    int ret = 0;

    /* Method */
    if (memcmp(buf, "GET", 3) == 0) {
        /* URI */

        /* 414 Request-URI Too Long */

        /* Headers */

    }

    (void)kHttpServerMsg;
    return ret;
}
