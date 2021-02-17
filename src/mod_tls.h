/* mod_tls.h
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

#ifndef WOLFKM_TLS_H
#define WOLFKM_TLS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wkm_types.h"
#include "wkm_utils.h"
#include "mod_socket.h"


/* wolfssl headers */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

typedef struct wkmTlsCtx {
    WOLFSSL_CTX*   sslCtx;
    WOLFSSL*       ssl;
    WKM_SOCKET_T   sockfd;
    int            noTLS;
} wkmTlsCtx;

WOLFKM_API int  wolfKeyMgr_TlsClientInit(wkmTlsCtx* client, 
    const char* ca, const char* key, const char* cert);
WOLFKM_API int  wolfKeyMgr_TlsConnect(wkmTlsCtx* client, const char* host, word16 port);
WOLFKM_API int  wolfKeyMgr_TlsRead(wkmTlsCtx* client, byte* p, int len);
WOLFKM_API int  wolfKeyMgr_TlsWrite(wkmTlsCtx* client, byte* p, int len);
WOLFKM_API void wolfKeyMgr_TlsClose(wkmTlsCtx* client, int sendShutdown);

#ifdef __cplusplus
}
#endif

#endif /* WOLFKM_TLS_H */
