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

#ifndef HAVE_ECC
    #error This service requires ECC support
#endif

/* shared context for worker threads */
typedef struct etsiSvcCtx {
    ecc_key         key;  /* last generated key */
    double          last; /* time last generated */
    pthread_mutex_t lock; /* queue lock */
} etsiSvcCtx;
static etsiSvcCtx svcCtx;

/* the top level service */
static svcInfo etsiService = {
    .desc = "ETSI",

    /* Callbacks */
    .requestCb = wolfEtsiSvc_DoRequest,
    .timeoutCb = wolfEtsiSvc_HandleTimeout,
    .initThreadCb = wolfEtsiSvc_WorkerInit,
    .freeThreadCb = wolfEtsiSvc_WorkerFree,

    /* TLS Certificate and Buffer */
    .certBuffer = NULL,
    .certBufferSz = 0,
    .keyBuffer = NULL,
    .keyBufferSz = 0,

    .svcCtx = &svcCtx,
};

/* worker thread objects */
typedef struct etsiSvcThread {
    HttpReq req;
    WC_RNG  rng;
    double  last; /* time key last generated */
    byte*   keyBuf;
    word32  keySz;
} etsiSvcThread;


/* caller must issue pthread mutex lock */
static int GenNewKey(etsiSvcCtx* svcCtx, etsiSvcThread* etsiThread)
{
    int ret = 0;

    if (svcCtx->last == 0) {
        XLOG(WOLFKM_LOG_WARN, "Generating new shared ECC key shared %f, thread %f\n", svcCtx->last, etsiThread->last);

        ret = wc_ecc_init(&svcCtx->key);
        if (ret == 0) {
            /* Generate key */
            /* TODO: Support other key sizes and curves */
            ret = wc_ecc_make_key_ex(&etsiThread->rng, 32, &svcCtx->key, ECC_SECP256R1);
            if (ret == 0) {
                svcCtx->last = wolfKeyMgr_GetCurrentTime();
            }
            else {
                wc_ecc_free(&svcCtx->key);
                XLOG(WOLFKM_LOG_ERROR, "ECC Make Key Failed! %d\n", ret);
                ret = WOLFKM_BAD_KEY;
            }
        }
        else {
            XLOG(WOLFKM_LOG_ERROR, "ECC Init Failed! %d\n", ret);
            ret = WOLFKM_BAD_KEY;
        }
    }
    return ret;
}

/* caller must issue pthread mutex lock */
static int SetupKeyPackage(etsiSvcCtx* svcCtx, etsiSvcThread* etsiThread)
{
    int ret;
    byte tmp[4096];
    word32 tmpSz = sizeof(tmp);

    /* Export as DER IETF RFC 5915 */
    ret = wc_EccKeyToDer(&svcCtx->key, tmp, tmpSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "wc_EccKeyToDer failed %d\n", ret);
        return WOLFKM_BAD_KEY;
    }
    tmpSz = ret;
    ret = 0;

    /* allocate actual size and store in thread */
    if (etsiThread->keyBuf) {
        free(etsiThread->keyBuf);
    }
    etsiThread->keyBuf = malloc(tmpSz);
    if (etsiThread->keyBuf) {
        etsiThread->keySz = tmpSz;
        memcpy(etsiThread->keyBuf, tmp, tmpSz);
    }
    else {
        ret = WOLFKM_BAD_MEMORY;
    }
    etsiThread->last = svcCtx->last;

    return ret;
}

int wolfEtsiSvc_DoResponse(svcConn* conn)
{
    int ret;
    etsiSvcThread* etsiThread;

    if (conn == NULL || conn->stream == NULL || conn->svcThreadCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI response pointers\n");
        return WOLFKM_BAD_ARGS;
    }
    etsiThread = (etsiSvcThread*)conn->svcThreadCtx;

    if (etsiThread->keyBuf == NULL || etsiThread->keySz == 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI Key not found!\n");
        return WOLFKM_BAD_KEY;
    }

    /* send already setup key */
    memcpy(conn->request, etsiThread->keyBuf, etsiThread->keySz);
    conn->requestSz = etsiThread->keySz;
    wolfKeyMgr_PrintBin(conn->request, conn->requestSz);

    /* send response, which is in the reused request buffer */
    ret = wolfKeyMgr_DoSend(conn, (byte*)conn->request, conn->requestSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI DoSend failed: %d\n", ret);
        return WOLFKM_BAD_SEND;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent ETSI Response\n");

    return ret;
}

/* the key request handler */
int wolfEtsiSvc_DoRequest(svcConn* conn)
{
    int ret;
    etsiSvcThread* etsiThread;

    if (conn == NULL || conn->stream == NULL || conn->svcThreadCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI Request pointers\n");
        return WOLFKM_BAD_ARGS;
    }
    etsiThread = (etsiSvcThread*)conn->svcThreadCtx;

    XLOG(WOLFKM_LOG_INFO, "Got ETSI Request\n");

    ret = wolfKeyMgr_HttpParse(&etsiThread->req, (char*)conn->request,
        conn->requestSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI HTTP Parse failed: %d\n", ret);
        return WOLFKM_BAD_REQUEST_TYPE;
    }
    wolfKeyMgr_HttpReqDump(&etsiThread->req);

    /* TODO: Perform URI decode? */
    //ret = wolfKeyMgr_UriDecode(etsiThread->req.uri, etsiThread->req.uri);

    /* Send Response */
    return wolfEtsiSvc_DoResponse(conn);
}

int wolfEtsiSvc_HandleTimeout(svcConn* conn)
{
    svcInfo* svc;
    etsiSvcCtx* svcCtx;
    etsiSvcThread* etsiThread;

    if (conn == NULL || conn->stream == NULL || conn->svc == NULL || 
            conn->svcThreadCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI timeout pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    svc = conn->svc;
    svcCtx = (etsiSvcCtx*)svc->svcCtx;
    etsiThread = (etsiSvcThread*)conn->svcThreadCtx;

    if (etsiThread->req.type != HTTP_METHOD_PUT) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI timeout (not a push request)\n");
        return 1; /* close connection */
    }

    /* generate updated key */
    pthread_mutex_lock(&svcCtx->lock);
    /* TODO: Only update the shared key ONCE on timeout */
    if (etsiThread->last == svcCtx->last) {
        XLOG(WOLFKM_LOG_WARN, "Time sared %f, thread %f\n", svcCtx->last, etsiThread->last);
        svcCtx->last = 0;
        GenNewKey(svcCtx, etsiThread);
    }
    SetupKeyPackage(svcCtx, etsiThread);
    pthread_mutex_unlock(&svcCtx->lock);

    /* send updated key */
    wolfEtsiSvc_DoResponse(conn);

    return 0; /* return non-zero value to close connection */
}

/* Called for startup of each worker thread */
int wolfEtsiSvc_WorkerInit(svcInfo* svc, void** svcThreadCtx)
{
    int ret = 0;
    etsiSvcCtx* svcCtx = (etsiSvcCtx*)svc->svcCtx;
    etsiSvcThread* etsiThread = malloc(sizeof(*etsiThread));
    if (etsiThread == NULL) {
        return WOLFKM_BAD_MEMORY;
    }
    memset(etsiThread, 0, sizeof(*etsiThread));

    /* Init RNG for each worker */
    wc_InitRng(&etsiThread->rng);

    /* make sure we have a key package setup to send */
    pthread_mutex_lock(&svcCtx->lock);
    ret = GenNewKey(svcCtx, etsiThread);
    if (ret == 0) {
        ret = SetupKeyPackage(svcCtx, etsiThread);
    }
    pthread_mutex_unlock(&svcCtx->lock);

    *svcThreadCtx = etsiThread;

    return ret;
}

void wolfEtsiSvc_WorkerFree(svcInfo* svc, void* svcThreadCtx)
{
    etsiSvcCtx* svcCtx = (etsiSvcCtx*)svc->svcCtx;
    etsiSvcThread* etsiThread = (etsiSvcThread*)svcThreadCtx;

    if (svc == NULL || svcThreadCtx == NULL)
        return;

    wc_FreeRng(&etsiThread->rng);
    if (etsiThread->keyBuf) {
        free(etsiThread->keyBuf);
    }
    (void)svcCtx;

    free(etsiThread);
}

#endif /* WOLFKM_ETSI_SERVICE */


svcInfo* wolfEtsiSvc_Init(struct event_base* mainBase, word32 timeoutSec)
{
#ifdef WOLFKM_ETSI_SERVICE
    int ret;
    char* listenPort = WOLFKM_ETSISVC_PORT;
    svcInfo* svc = &etsiService;
    etsiSvcCtx* svcCtx = (etsiSvcCtx*)svc->svcCtx;
    
    ret = wolfKeyMgr_LoadKeyFile(svc, WOLFKM_ETSISVC_KEY, 
        WOLFSSL_FILETYPE_PEM, WOLFKM_ETSISVC_KEY_PASSWORD);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error loading ETSI TLS key\n");
        return NULL;
    }

    ret = wolfKeyMgr_LoadCertFile(svc, WOLFKM_ETSISVC_CERT, 
        WOLFSSL_FILETYPE_PEM);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error loading ETSI TLS certificate\n");
        return NULL;
    }

    /* setup listening events */
    ret = wolfKeyMgr_AddListeners(svc, AF_INET6, listenPort, mainBase);  /* 6 may contain a 4 */
    if (ret < 0)
        ret = wolfKeyMgr_AddListeners(svc, AF_INET, listenPort, mainBase);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to bind at least one ETSI listener,"
                               "already running?\n");
        wolfEtsiSvc_Cleanup(svc);
        return NULL;
    }

    /* use the timeout to trigger sending new set of keys */
    wolfKeyMgr_SetTimeout(svc, timeoutSec);

    (void)svcCtx;

    return svc;
#else
    return NULL;
#endif
}

void wolfEtsiSvc_Cleanup(svcInfo* svc)
{
    if (svc) {
#ifdef WOLFKM_ETSI_SERVICE
        etsiSvcCtx* svcCtx = (etsiSvcCtx*)svc->svcCtx;
        if (svc->keyBuffer) {
            free(svc->keyBuffer);
            svc->keyBuffer = NULL;
        }
        if (svc->certBuffer) {
            free(svc->certBuffer);
            svc->certBuffer = NULL;
        }

        if (svcCtx->last != 0) {
            wc_ecc_free(&svcCtx->key);
        }
    }
#endif
}
