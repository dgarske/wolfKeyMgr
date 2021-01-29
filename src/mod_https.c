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
 */

typedef struct HttpReqHdr {

} HttpReqHdr;

typedef struct HttpReq {

} HttpReq;


/* URL Encoding / Decoding Support */
static char* url_encode(const unsigned char *s, char *enc)
{
    for (; *s; s++){
        if (*s == '*' || *s == '-' || *s == '.' || *s == '_') {
            char a = (char)(*s >> 4), b = (char)(*s & 0xff);
            *enc++ = '%';
            *enc++ = (a < 10) ? '0' + a : 'A' + a - 10;
            *enc++ = (b < 10) ? '0' + b : 'A' + b - 10;
        }
        else if (*s == ' ')
            *enc++ = '+';
        else
            *enc++ = *s;
    }
    return enc;
}

static int hex_to_char(char a, unsigned char* out)
{
    if (a >= '0' && a <= '9')
        a -= '0';
    else if (a >= 'A' && a <= 'F')
        a -= 'A' - 10;
    else if (a >= 'a' && a <= 'f')
        a -= 'a' - 'A' - 10;
    else
        return 0;
    *out = (unsigned char)a;
    return 1;
}

static unsigned char* url_decode(const char *s, unsigned char *dec)
{
    unsigned char a, b;
    for (; *s; s++){
        if (*s == '%' && 
                hex_to_char((char)s[1], &a) && 
                hex_to_char((char)s[2], &b)) {
            *dec++ = (a << 4 | b);
            s+=2;
        }
        else if (*s == '+') {
            *dec++ = ' ';
        }
        else {
            *dec++ = *s;
        }
    }
    return dec;
}


int wolfKeyMgr_HttpParse(unsigned char* buf, unsigned int sz)
{
    int ret;

    /* Method */
    if (memcmp(buf, "GET", 3) == 0) {
        /* URI */

        /* 414 Request-URI Too Long */

        /* Headers */

    }

}

static const char kHttpGetMsg[] = "GET /index.html HTTP/1.0\r\n\r\n";

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
