/* server.c
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

#include "mod_tls.h"
#include "mod_http.h"
#include "tls_config.h"

static volatile int mStop = 0;
static WKM_SOCKET_T listenFd = WKM_SOCKET_INVALID;

static void sig_handler(const int sig)
{
    printf("SIGINT handled = %d.\n", sig);
    wolfSocketClose(listenFd);
    listenFd = WKM_SOCKET_INVALID;
    mStop = 1;
}

int main(int argc, char* argv[])
{
    int ret;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl = NULL;
    HttpReq req;
    byte data[TLS_TEST_MAX_DATA];
    int dataSz;
    HttpHeader headers[2];
    const char* body = TEST_HTTP_RESPONSE;
    SOCKADDR_IN_T clientAddr;

    signal(SIGINT, sig_handler);

    printf("TLS Server: Port %d\n", TLS_TEST_PORT);

    wolfSSL_Init();
    
    /* log setup */
    //wolfSSL_Debugging_ON();
    wolfKeyMgr_SetLogFile(NULL, 0, WOLFKM_LOG_DEBUG);

    ctx = wolfTlsServerNew();
    if (ctx == NULL) { ret = WOLFKM_BAD_MEMORY; goto exit; }

    ret = wolfTlsAddCA(ctx, TLS_TEST_CA);
    if (ret != 0) goto exit;

    ret = wolfTlsSetKey(ctx, TLS_TEST_KEY, NULL, TLS_TEST_CERT,
        WOLFSSL_FILETYPE_PEM);
    if (ret != 0) goto exit;

    /* setup listener */
    ret = wolfSockListen(&listenFd, TLS_TEST_PORT);
    if (ret != 0) goto exit;

    do {
        ret = wolfTlsAccept(ctx, listenFd, &ssl, &clientAddr,
            TLS_TEST_TIMEOUT_SEC);
        if (ret == WOLFKM_BAD_TIMEOUT) continue;
        if (ret != 0) goto exit;
        
        printf("TLS Accept %s\n", wolfSocketAddrStr(&clientAddr));

        /* Get HTTP request and print */
        dataSz = (int)sizeof(data);
        ret = wolfTlsRead(ssl, data, &dataSz, TLS_TEST_TIMEOUT_SEC);
        if (ret < 0) goto exit;
        
        ret = wolfHttpServer_ParseRequest(&req, data, dataSz);
        if (ret == 0) {
            wolfHttpRequestPrint(&req);
        }

        /* Build response */
        headers[0].type = HTTP_HDR_CONTENT_TYPE;
        headers[0].string = "text/html";
        headers[1].type = HTTP_HDR_CONNECTION;
        headers[1].string = "keep-alive";
        dataSz = (int)sizeof(data);
        ret = wolfHttpServer_EncodeResponse(200, NULL,
            data, (word32*)&dataSz,
            headers, sizeof(headers)/sizeof(HttpHeader),
            (const byte*)body, strlen(body));
        if (ret == 0) {
            ret = wolfTlsWrite(ssl, data, dataSz);
        }

exit:

        /* Done - send TLS shutdown message */
        if (ssl) {
            (void)wolfTlsClose(ssl, ret == 0 ? 1 : 0);
            ssl = NULL;
        }

        if (ret < 0) {
            printf("TLS Server Error %d: %s\n", ret, wolfTlsGetErrorStr(ret));
        }
    } while (mStop == 0);

    if (listenFd != WKM_SOCKET_INVALID)
        wolfSocketClose(listenFd);
    if (ctx)
        wolfTlsFree(ctx);

    wolfSSL_Cleanup();

    return ret;
}
