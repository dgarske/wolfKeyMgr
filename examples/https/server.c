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

#include "wolfkeymgr/mod_tls.h"
#include "wolfkeymgr/mod_http.h"
#include "wolfkeymgr/mod_etsi.h"
#include "examples/test_config.h"

#include <signal.h>        /* signal */

static volatile int mStop = 0;
static WKM_SOCKET_T listenFd = WKM_SOCKET_INVALID;

static EtsiClientCtx* gEtsiClient;
static int etsi_client_get(WOLFSSL_CTX* ctx);

static void sig_handler(const int sig)
{
    printf("SIGINT handled = %d.\n", sig);
    wolfSocketClose(listenFd);
    listenFd = WKM_SOCKET_INVALID;
    mStop = 1;
}

int https_server_test(int argc, char** argv)
{
    int ret;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl = NULL;
    HttpReq req;
    byte data[HTTPS_TEST_MAX_DATA];
    int dataSz;
    HttpHeader headers[2];
    const char* body = HTTPS_TEST_RESPONSE;
    SOCKADDR_IN_T clientAddr;

    signal(SIGINT, sig_handler);

    /* TODO: Support arguments */
    (void)argc;
    (void)argv;

    printf("HTTPS Server: Port %d\n", HTTPS_TEST_PORT);

    wolfSSL_Init();
    
    /* log setup */
    //wolfSSL_Debugging_ON();
    wolfKeyMgr_SetLogFile(NULL, 0, WOLFKM_LOG_DEBUG);

    ctx = wolfTlsServerNew();
    if (ctx == NULL) { ret = WOLFKM_BAD_MEMORY; goto exit; }

    ret = wolfTlsAddCA(ctx, HTTPS_TEST_CA);
    if (ret != 0) goto exit;

    ret = wolfTlsSetKey(ctx, HTTPS_TEST_KEY, NULL, HTTPS_TEST_CERT,
        WOLFSSL_FILETYPE_PEM);
    if (ret != 0) goto exit;

    /* setup listener */
    ret = wolfSockListen(&listenFd, HTTPS_TEST_PORT);
    if (ret != 0) goto exit;

    do {
        ret = etsi_client_get(ctx);
        if (ret != 0) {
            mStop = 1;
            goto end_sess;
        }

        ret = wolfTlsAccept(ctx, listenFd, &ssl, &clientAddr,
            HTTPS_TEST_TIMEOUT_SEC);
        if (ret == WOLFKM_BAD_TIMEOUT) continue;
        if (ret != 0) goto end_sess;
        
        printf("TLS Accept %s\n", wolfSocketAddrStr(&clientAddr));

        /* Get HTTP request and print */
        dataSz = (int)sizeof(data);
        ret = wolfTlsRead(ssl, data, &dataSz, HTTPS_TEST_TIMEOUT_SEC);
        if (ret < 0) goto end_sess;
        
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

end_sess:

        /* Done - send TLS shutdown message */
        if (ssl) {
            (void)wolfTlsClose(ssl, ret == 0 ? 1 : 0);
            ssl = NULL;
        }

        if (ret < 0) {
            printf("HTTPS Server Error %d: %s\n", ret, wolfTlsGetErrorStr(ret));
        }
    } while (mStop == 0);

exit:
    if (listenFd != WKM_SOCKET_INVALID)
        wolfSocketClose(listenFd);
    if (ctx)
        wolfTlsFree(ctx);

    wolfSSL_Cleanup();

    return ret;
}

/* ETSI Client */
static void etsi_client_cleanup(void)
{
    if (gEtsiClient) {
        wolfEtsiClientFree(gEtsiClient);
        gEtsiClient = NULL;

        wolfEtsiClientCleanup();
    }
}
static int etsi_client_get(WOLFSSL_CTX* ctx)
{
    int ret = -1;
    static EtsiKey key;
    
    /* setup key manager connection */
    if (gEtsiClient == NULL) {
        wolfEtsiClientInit();

        gEtsiClient = wolfEtsiClientNew();
        if (gEtsiClient) {
            wolfEtsiClientAddCA(gEtsiClient, ETSI_TEST_CLIENT_CA);
            wolfEtsiClientSetKey(gEtsiClient,
                ETSI_TEST_CLIENT_KEY, ETSI_TEST_CLIENT_PASS,
                ETSI_TEST_CLIENT_CERT, WOLFSSL_FILETYPE_PEM);

            ret = wolfEtsiClientConnect(gEtsiClient, ETSI_TEST_HOST,
                ETSI_TEST_PORT, ETSI_TEST_TIMEOUT_MS);
            if (ret != 0) {
                printf("Error connecting to ETSI server! %d\n", ret);
                etsi_client_cleanup();
            }
        }
        else {
            ret = WOLFKM_BAD_MEMORY;
        }
    }
    if (gEtsiClient) {
        ret = wolfEtsiClientGet(gEtsiClient, &key, ETSI_TEST_KEY_TYPE, 
            NULL, NULL, ETSI_TEST_TIMEOUT_MS);
        /* positive return means new key returned */
        /* zero means, same key is used */
        /* negative means error */
        if (ret < 0) {
            printf("Error getting ETSI static ephemeral key! %d\n", ret);
            etsi_client_cleanup();
        }
        else if (ret > 0) {
            /* got new key */
            printf("Got ETSI static ephemeral key (%d bytes)\n", key.responseSz);
            wolfEtsiKeyPrint(&key);
            ret = wolfEtsiKeyLoadCTX(&key, ctx);
        }
        else {
            /* key has not changed */
            printf("ETSI Key Cached (valid for %lu sec)\n",
                key.expires - wolfGetCurrentTimeT());
        }
    }
    return ret;
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
{
    return https_server_test(argc, argv);
}
#endif
