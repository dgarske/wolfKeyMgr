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

    ret = wolfKeyMgr_HttpParse(&etsiSvc->req, (char*)conn->request, conn->requestSz);


    /* Send Response */
    ret = wolfKeyMgr_DoSend(conn, (byte*)kHttpServerMsg, strlen(kHttpServerMsg));
    /* send it, response is now in request buffer */
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI DoSend failed: %d\n", ret);
        return WOLFKM_BAD_SEND;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent ETSI Response\n");
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

    *svcCtx = etsiSvc;

    return ret;
}

void wolfEtsiSvc_WorkerFree(svcInfo* svc, void* svcCtx)
{
    etsiSvcInfo* etsiSvc = (etsiSvcInfo*)svcCtx;

    if (svc == NULL || svcCtx == NULL)
        return;

    free(etsiSvc);
}

#endif /* WOLFKM_ETSI_SERVICE */


int wolfEtsiSvc_Init(struct event_base* mainBase, int poolSize)
{
#ifdef WOLFKM_ETSI_SERVICE
    int ret;
    char* listenPort = WOLFKM_ETSISVC_PORT;

    ret = wolfKeyMgr_LoadKeyFile(&etsiService, WOLFKM_ETSISVC_KEY, WOLFSSL_FILETYPE_PEM, WOLFKM_ETSISVC_KEY_PASSWORD);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error loading ETSI TLS key\n");
        return ret;
    }

    ret = wolfKeyMgr_LoadCertFile(&etsiService, WOLFKM_ETSISVC_CERT, WOLFSSL_FILETYPE_PEM);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error loading ETSI TLS certificate\n");
        return ret;
    }

    /* setup listening events, bind before .pid file creation */
    ret =  wolfKeyMgr_AddListeners(&etsiService, AF_INET6, listenPort, mainBase);  /* 6 may contain a 4 */
    ret += wolfKeyMgr_AddListeners(&etsiService, AF_INET, listenPort, mainBase);   /* should be first */
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to bind at least one ETSI listener,"
                               "already running?\n");
        wolfEtsiSvc_Cleanup();
        return WOLFKM_BAD_LISTENER;
    }
    /* thread setup */
    wolfKeyMgr_InitService(&etsiService, poolSize);

    return 0;
#else
    return WOLFKM_NOT_COMPILED_IN;
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
