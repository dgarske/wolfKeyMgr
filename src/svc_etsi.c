/* svc_etsi.c
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

#include "keymanager.h"
#include "mod_https.h"


#ifdef WOLFKM_ETSI_SERVICE

static svcInfo etsiService = {
    .desc = "ETSI",

    /* Callbacks */
    .requestCb = wolfEtsiSvc_DoRequest,
    .initThreadCb = wolfEtsiSvc_WorkerInit,
    .freeThreadCb = wolfEtsiSvc_WorkerFree,

    /* TLS Certificate and Buffer */
    .certBuffer = NULL,
    .certBufferSz = 0,
    .keyBuffer = NULL,
    .keyBufferSz = 0,
};


typedef struct etsiSvcInfo {
    HttpReq req;
    WC_RNG  rng;
} etsiSvcInfo;

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


static int wolfEtsiSvc_GenerateEccKey(etsiSvcInfo* etsiSvc, 
    byte* out, word32* outSz)
{
    int ret;
    ecc_key eccKey;
    byte eccPubKeyBuf[ECC_BUFSIZE], eccPrivKeyBuf[ECC_BUFSIZE];
    word32 eccPubKeyLen, eccPrivKeyLen;

    /* Generate key */
    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key_ex(&etsiSvc->rng, 32, &eccKey, ECC_CURVE_DEF);
    if(ret != 0) {
        printf("ECC Make Key Failed! %d\n", ret);
    }

    /* Display public key data */
    eccPubKeyLen = ECC_BUFSIZE;
    ret = wc_ecc_export_x963(&eccKey, eccPubKeyBuf, &eccPubKeyLen);
    if (ret != 0) {
        printf("ECC public key x963 export failed! %d\n", ret);
        ret = EXIT_FAILURE;
        goto exit;
    }
    printf("ECC Public Key: Len %d\n", eccPubKeyLen);
    WOLFSSL_BUFFER(eccPubKeyBuf, eccPubKeyLen);

    /* Display private key data */
    eccPrivKeyLen = ECC_BUFSIZE;
    ret = wc_ecc_export_private_only(&eccKey, eccPrivKeyBuf, &eccPrivKeyLen);
    if (ret != 0) {
        printf("ECC private key export failed! %d\n", ret);
        ret = EXIT_FAILURE;
        goto exit;
    }
    printf("ECC Private Key: Len %d\n", eccPrivKeyLen);
    WOLFSSL_BUFFER(eccPrivKeyBuf, eccPrivKeyLen);

exit:
    wc_ecc_free(&eccKey);
    return ret;
}

static int wolfEtsiSvc_GetAsymPackage(svcConn* conn, etsiSvcInfo* etsiSvc)
{
    int ret;

    conn->requestSz = sizeof(conn->request);
    ret = wolfEtsiSvc_GenerateEccKey(etsiSvc, (byte*)conn->request,
        &conn->requestSz);

    /* Version 2 (int 1) */
    
    /* privateKeyAlgorithm shall be set to the key pair algorithm identifier */
    /* DHE - { 1 2 840 10046 2 1 }
    parameter encoding: DomainParameters
    private key encoding: INTEGER
    public key encoding: INTEGER
    */

    /* ECDHE - { 1 3 132 1 12 }
    parameter encoding: ECParameters
    private key encoding: ECPrivateKey
    public key encoding: ECPoint
    */

   return ret;
}


/* the key request handler */
int wolfEtsiSvc_DoRequest(svcConn* conn)
{
    int ret;
    etsiSvcInfo* etsiSvc = (etsiSvcInfo*)conn->svcCtx;

    if (conn == NULL || conn->stream == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI Request pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    XLOG(WOLFKM_LOG_INFO, "Got ETSI Request\n");

    ret = wolfKeyMgr_HttpParse(&etsiSvc->req, (char*)conn->request,
        conn->requestSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI DoSend failed: %d\n", ret);
        return WOLFKM_BAD_REQUEST_TYPE;
    }
    
    /* Send Response */
    ret = wolfEtsiSvc_GetAsymPackage(conn, etsiSvc);
    if (ret == 0) {
        ret = wolfKeyMgr_DoSend(conn, (byte*)kHttpServerMsg,
            strlen(kHttpServerMsg));
        /* send it, response is now in request buffer */
        if (ret < 0) {
            XLOG(WOLFKM_LOG_ERROR, "ETSI DoSend failed: %d\n", ret);
            return WOLFKM_BAD_SEND;
        }
        XLOG(WOLFKM_LOG_INFO, "Sent ETSI Response\n");
    }
    return 0;
}

/* Called for startup of each worker thread */
int wolfEtsiSvc_WorkerInit(svcInfo* svc, void** svcCtx)
{
    int ret = 0;
    etsiSvcInfo* etsiSvc = malloc(sizeof(*etsiSvc));
    if (etsiSvc == NULL) {
        return WOLFKM_BAD_MEMORY;
    }
    memset(etsiSvc, 0, sizeof(*etsiSvc));

    /* Init RNG for each worker */
    wc_InitRng(&etsiSvc->rng);

    *svcCtx = etsiSvc;

    return ret;
}

void wolfEtsiSvc_WorkerFree(svcInfo* svc, void* svcCtx)
{
    etsiSvcInfo* etsiSvc = (etsiSvcInfo*)svcCtx;

    if (svc == NULL || svcCtx == NULL)
        return;

    wc_FreeRng(&etsiSvc->rng);

    free(etsiSvc);
}

#endif /* WOLFKM_ETSI_SERVICE */


svcInfo* wolfEtsiSvc_Init(struct event_base* mainBase, int poolSize)
{
#ifdef WOLFKM_ETSI_SERVICE
    int ret;
    char* listenPort = WOLFKM_ETSISVC_PORT;

    ret = wolfKeyMgr_LoadKeyFile(&etsiService, WOLFKM_ETSISVC_KEY, 
        WOLFSSL_FILETYPE_PEM, WOLFKM_ETSISVC_KEY_PASSWORD);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error loading ETSI TLS key\n");
        return NULL;
    }

    ret = wolfKeyMgr_LoadCertFile(&etsiService, WOLFKM_ETSISVC_CERT, 
        WOLFSSL_FILETYPE_PEM);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error loading ETSI TLS certificate\n");
        return NULL;
    }

    /* setup listening events, bind before .pid file creation */
    ret =  wolfKeyMgr_AddListeners(&etsiService, AF_INET6, listenPort, mainBase);  /* 6 may contain a 4 */
    ret += wolfKeyMgr_AddListeners(&etsiService, AF_INET, listenPort, mainBase);   /* should be first */
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to bind at least one ETSI listener,"
                               "already running?\n");
        wolfEtsiSvc_Cleanup();
        return NULL;
    }
    /* thread setup */
    wolfKeyMgr_ServiceInit(&etsiService, poolSize);
        /* cleanup handled in sigint handler and wolfKeyMgr_ServiceCleanup */

    return &etsiService;
#else
    return NULL;
#endif
}

void wolfEtsiSvc_Cleanup(void)
{
#ifdef WOLFKM_ETSI_SERVICE
    if (etsiService.keyBuffer) {
        free(etsiService.keyBuffer);
        etsiService.keyBuffer = NULL;
    }
    if (etsiService.certBuffer) {
        free(etsiService.certBuffer);
        etsiService.certBuffer = NULL;
    }
#endif
}
