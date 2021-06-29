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

#include "wolfkeymgr/keymanager.h"
#include "wolfkeymgr/mod_http.h"
#include "wolfkeymgr/mod_etsi.h"
#include "wolfkeymgr/mod_vault.h"

#ifdef WOLFKM_ETSI_SERVICE

/* shared context for worker threads */
typedef struct EtsiSvcCtx {
    /* latest shared key data */
    EtsiKey key;
    word32  renewSec;
    word32  index;

    WC_RNG          rng;
    pthread_mutex_t lock;   /* shared lock */
    pthread_t       thread; /* key gen worker */

#ifdef WOLFKM_VAULT
    wolfVaultCtx*   vault; /* key vault */
#endif
} EtsiSvcCtx;
static EtsiSvcCtx gSvcCtx;

/* the top level service */
static SvcInfo etsiService = {
    .desc = "ETSI",

    /* Callbacks */
    .requestCb = wolfEtsiSvc_DoRequest,
    .timeoutCb = wolfEtsiSvc_HandleTimeout,
    .initThreadCb = wolfEtsiSvc_WorkerInit,
    .freeThreadCb = wolfEtsiSvc_WorkerFree,
    .notifyCb = wolfEtsiSvc_DoNotify,
    .closeCb = wolfEtsiSvc_ConnClose,

    /* TLS Certificate and Buffer */
    .certBuffer = NULL,
    .certBufferSz = 0,
    .keyBuffer = NULL,
    .keyBufferSz = 0,
    .caBuffer = NULL,
    .caBufferSz = 0,

    .svcCtx = &gSvcCtx,
};

/* worker thread objects */
typedef struct EtsiSvcThread {
    word32 index;
    EtsiKeyType keyType;
    byte   httpRspBuf[ETSI_MAX_RESPONSE_SZ];
    word32 httpRspSz;
} EtsiSvcThread;

typedef struct EtsiSvcConn {
    HttpReq req;
    char fingerprint[HTTP_MAX_URI];
    char contextStr[HTTP_MAX_URI];
    word32 groupNum;
} EtsiSvcConn;

#ifdef WOLFKM_VAULT
static int AddKeyToVault(EtsiSvcCtx* svcCtx, EtsiKey* key)
{
    if (svcCtx->vault == NULL) {
        XLOG(WOLFKM_LOG_WARN, "AddKey: vault not open\n");
        return 0; /* don't fail, just log warning */
    }

    return wolfVaultAdd(svcCtx->vault, key->type,
        key->name, key->nameSz,
        key->response, key->responseSz);
}
#endif

static int GenNewKey(EtsiSvcCtx* svcCtx, EtsiKeyType keyType)
{
    int ret = WOLFKM_NOT_COMPILED_IN;
    const char* keyTypeStr = wolfEtsiKeyGetTypeStr(keyType);

    if (keyTypeStr == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    XLOG(WOLFKM_LOG_WARN, "Generating new %s key (index %d)\n",
        keyTypeStr, svcCtx->index);

    ret = wolfEtsiKeyGen(&svcCtx->key, keyType, &svcCtx->rng);
    if (ret == 0) {
        svcCtx->key.expires = wolfGetCurrentTimeT() + svcCtx->renewSec;
        svcCtx->index++;

    #ifdef WOLFKM_VAULT
        ret = AddKeyToVault(svcCtx, &svcCtx->key);
    #endif
    }

    return ret;
}

static int SetupKeyPackage(EtsiSvcCtx* svcCtx, EtsiSvcThread* etsiThread)
{
    int ret = 0;
    char expiresStr[100];
    HttpHeader headers[3];
    headers[0].type = HTTP_HDR_CONTENT_TYPE;
    headers[0].string = "application/pkcs8";
    headers[1].type = HTTP_HDR_CONNECTION;
    headers[1].string = "Keep-Alive";
    headers[2].type = HTTP_HDR_EXPIRES;
    headers[2].string = expiresStr;
    memset(expiresStr, 0, sizeof(expiresStr));

    XLOG(WOLFKM_LOG_DEBUG, "Synchronizing key to worker thread\n"); 
    if (etsiThread->index != svcCtx->index) {
        /* Format Expires Time */
        struct tm tm;
        localtime_r(&svcCtx->key.expires, &tm);
        strftime(expiresStr, sizeof(expiresStr), HTTP_DATE_FMT, &tm);

        /* Wrap key in HTTP server response */
        etsiThread->httpRspSz = sizeof(etsiThread->httpRspBuf);
        ret = wolfHttpServer_EncodeResponse(0, NULL, 
            etsiThread->httpRspBuf, &etsiThread->httpRspSz, headers, 
            sizeof(headers)/sizeof(HttpHeader), (byte*)svcCtx->key.response,
            svcCtx->key.responseSz);
        if (ret != 0) {
            pthread_mutex_unlock(&svcCtx->lock);
            XLOG(WOLFKM_LOG_ERROR, "Error encoding HTTP response: %d\n", ret);
            return ret;
        }

        etsiThread->index = svcCtx->index;
        etsiThread->keyType = svcCtx->key.type;
    }

    return ret;
}

static void* KeyPushWorker(void* arg)
{
    int ret;
    SvcInfo* svc = (SvcInfo*)arg;
    EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;

    do {
        /* generate new key */
        pthread_mutex_lock(&svcCtx->lock);
        ret = GenNewKey(svcCtx, svcCtx->key.type);
        pthread_mutex_unlock(&svcCtx->lock);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "ETSI Key Generation Failed %d\n", ret);
            return NULL;
        }

        /* push to any connected clients */
        wolfKeyMgr_NotifyAllClients(svc);

        /* wait seconds */
        sleep(svcCtx->renewSec);
    } while (1);

    return NULL;
}

int wolfEtsiSvc_DoResponse(SvcConn* conn)
{
    int ret;
    EtsiSvcThread* etsiThread;

    if (conn == NULL || conn->stream == NULL || conn->svcThreadCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI response pointers\n");
        return WOLFKM_BAD_ARGS;
    }
    etsiThread = (EtsiSvcThread*)conn->svcThreadCtx;
    if (etsiThread->httpRspSz == 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI HTTP Response / Key not found!\n");
        return WOLFKM_BAD_KEY;
    }

    /* send already setup key */
    memcpy(conn->request, etsiThread->httpRspBuf, etsiThread->httpRspSz);
    conn->requestSz = etsiThread->httpRspSz;

    /* send response, which is in the reused request buffer */
    ret = wolfKeyMgr_DoSend(conn, (byte*)conn->request, conn->requestSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI DoSend failed: %d\n", ret);
        return WOLFKM_BAD_SEND;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent ETSI Response (%d bytes)\n", conn->requestSz);

    return ret;
}

/* the key request handler */
int wolfEtsiSvc_DoRequest(SvcConn* conn)
{
    int ret;
    SvcInfo* svc;
    EtsiSvcCtx* svcCtx;
    EtsiSvcConn* etsiConn;
    EtsiSvcThread* etsiThread;

    if (conn == NULL || conn->svc == NULL || conn->stream == NULL || 
            conn->svcThreadCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI Request pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    XLOG(WOLFKM_LOG_INFO, "Got ETSI Request (%d bytes)\n", conn->requestSz);

    if (conn->svcConnCtx == NULL) {
        /* Creating connection context */
        XLOG(WOLFKM_LOG_INFO, "Creating connection context\n");
        conn->svcConnCtx = malloc(sizeof(EtsiSvcConn));
        if (conn->svcConnCtx == NULL) {
            return WOLFKM_BAD_MEMORY;
        }
        memset(conn->svcConnCtx, 0, sizeof(EtsiSvcConn));
    }
    svc = conn->svc;
    svcCtx = (EtsiSvcCtx*)svc->svcCtx;
    etsiConn = (EtsiSvcConn*)conn->svcConnCtx;
    etsiThread = (EtsiSvcThread*)conn->svcThreadCtx;

    ret = wolfHttpServer_ParseRequest(&etsiConn->req, conn->request,
        conn->requestSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI HTTP Server Parse failed: %d\n", ret);
        return WOLFKM_BAD_REQUEST_TYPE;
    }
    wolfHttpRequestPrint(&etsiConn->req);

    /* Get fingerprint */
    ret = wolfHttpUriGetItem(etsiConn->req.uri, "fingerprints=",
        etsiConn->fingerprint, sizeof(etsiConn->fingerprint));
    if (ret > 0)
        XLOG(WOLFKM_LOG_DEBUG, "Fingerprint: %s\n", etsiConn->fingerprint);

    /* Get groups - borrow contextStr variable */
    ret = wolfHttpUriGetItem(etsiConn->req.uri, "groups=",
        etsiConn->contextStr, sizeof(etsiConn->contextStr));
    if (ret > 0) {
        const char* groupName;
        etsiConn->groupNum = (word32)strtol(etsiConn->contextStr, NULL, 16);
        groupName = wolfEtsiKeyGetTypeStr((EtsiKeyType)etsiConn->groupNum);
        XLOG(WOLFKM_LOG_DEBUG, "Group: %s (%d)\n", groupName, etsiConn->groupNum);
        if (groupName == NULL) {
            etsiConn->groupNum = 0;
        }
        /* clear borrowed contextStr */
        memset(etsiConn->contextStr, 0, sizeof(etsiConn->contextStr));
    }

    /* Get context string */
    ret = wolfHttpUriGetItem(etsiConn->req.uri, "contextstr=",
        etsiConn->contextStr, sizeof(etsiConn->contextStr));
    if (ret > 0)
        XLOG(WOLFKM_LOG_DEBUG, "Context: %s\n", etsiConn->contextStr);


    /* If generated key doesn't match, force it now */
    if (etsiConn->groupNum > 0 && 
            etsiThread->keyType != (EtsiKeyType)etsiConn->groupNum) {
        pthread_mutex_lock(&svcCtx->lock);
        ret = GenNewKey(svcCtx, (EtsiKeyType)etsiConn->groupNum);
        if (ret == 0) {
            ret = SetupKeyPackage(svcCtx, etsiThread);
        }
        pthread_mutex_unlock(&svcCtx->lock);
    }

    /* Send Response */
    return wolfEtsiSvc_DoResponse(conn);
}

void wolfEtsiSvc_ConnClose(SvcConn* conn)
{
    if (conn && conn->svcConnCtx) {
        free(conn->svcConnCtx);
        conn->svcConnCtx = NULL;
    }
}

int wolfEtsiSvc_DoNotify(SvcConn* conn)
{
    int ret;
    SvcInfo* svc;
    EtsiSvcCtx* svcCtx;
    EtsiSvcThread* etsiThread;
    EtsiSvcConn* etsiConn;

    if (conn == NULL || conn->svc == NULL || conn->svcThreadCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI notify pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    svc = conn->svc;
    svcCtx = (EtsiSvcCtx*)svc->svcCtx;
    etsiThread = (EtsiSvcThread*)conn->svcThreadCtx;
    etsiConn = (EtsiSvcConn*)conn->svcConnCtx;

    /* update key */
    pthread_mutex_lock(&svcCtx->lock);
    ret = SetupKeyPackage(svcCtx, etsiThread);
    pthread_mutex_unlock(&svcCtx->lock);

    /* push key to active push threads */
    if (ret == 0 && etsiConn != NULL && 
            etsiConn->req.type == HTTP_METHOD_PUT) {
        /* send updated key - already populated in httpRspBuf */
        ret = wolfEtsiSvc_DoResponse(conn);
    }

    return ret;
}

int wolfEtsiSvc_HandleTimeout(SvcConn* conn)
{
    EtsiSvcConn* etsiConn;

    if (conn == NULL || conn->svcConnCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI timeout pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    etsiConn = (EtsiSvcConn*)conn->svcConnCtx;

    /* if we received an HTTP request then keep open */
    if (etsiConn->req.type != HTTP_METHOD_UNKNOWN) {
        return 0; /* keep open (return non-zero value to close connection) */
    }
    return 1; /* close connection */
}

/* Called for startup of each worker thread */
int wolfEtsiSvc_WorkerInit(SvcInfo* svc, void** svcThreadCtx)
{
    int ret = 0;
    EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;
    EtsiSvcThread* etsiThread = malloc(sizeof(*etsiThread));
    if (etsiThread == NULL) {
        return WOLFKM_BAD_MEMORY;
    }
    memset(etsiThread, 0, sizeof(*etsiThread));

    /* make sure we have a key package setup to send */
    pthread_mutex_lock(&svcCtx->lock);
    ret = SetupKeyPackage(svcCtx, etsiThread);
    pthread_mutex_unlock(&svcCtx->lock);

    *svcThreadCtx = etsiThread;

    return ret;
}

void wolfEtsiSvc_WorkerFree(SvcInfo* svc, void* svcThreadCtx)
{
    if (svcThreadCtx == NULL)
        return;

    (void)svc;

    free((EtsiSvcThread*)svcThreadCtx);
}

#endif /* WOLFKM_ETSI_SERVICE */


SvcInfo* wolfEtsiSvc_Init(struct event_base* mainBase, int renewSec,
    EtsiKeyType keyTypeDef)
{
#ifdef WOLFKM_ETSI_SERVICE
    int ret;
    char* listenPort = WOLFKM_ETSISVC_PORT;
    SvcInfo* svc = &etsiService;
    EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;

    ret = wc_InitRng(&svcCtx->rng);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error initializing RNG %d\n", ret);
        return NULL;
    }

    pthread_mutex_init(&svcCtx->lock, NULL);

    svcCtx->renewSec = renewSec;
    svcCtx->key.type = keyTypeDef;

    /* start key generation thread */
    if (pthread_create(&svcCtx->thread, NULL, KeyPushWorker, svc) != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error creating keygen worker\n");
        wolfEtsiSvc_Cleanup(svc);
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

    return svc;
#else
    (void)mainBase;
    (void)renewSec;

    return NULL;
#endif
}

void wolfEtsiSvc_Cleanup(SvcInfo* svc)
{
    if (svc) {
#ifdef WOLFKM_ETSI_SERVICE
        EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;

        if (svc->keyBuffer) {
            free(svc->keyBuffer);
            svc->keyBuffer = NULL;
        }
        if (svc->certBuffer) {
            free(svc->certBuffer);
            svc->certBuffer = NULL;
        }

        wc_FreeRng(&svcCtx->rng);
        pthread_mutex_destroy(&svcCtx->lock);
    }
#endif
}
