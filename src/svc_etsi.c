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

#ifndef ETSI_SVC_MAX_ACTIVE_KEYS
#define ETSI_SVC_MAX_ACTIVE_KEYS 4
#endif

/* shared context for worker threads */
typedef struct EtsiSvcCtx {
    /* latest shared key data */
    EtsiKey         keys[ETSI_SVC_MAX_ACTIVE_KEYS];
    EtsiKeyType     keyTypeDef; /* default key type */
    word32          renewSec;

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

/* connection object */
typedef struct EtsiSvcConn {
    HttpReq req;
    char    fingerprint[HTTP_MAX_URI];
    char    contextStr[HTTP_MAX_URI];
    word32  groupNum; /* same as enum EtsiKeyType */
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

static int GenNewKey(EtsiSvcCtx* svcCtx, EtsiKeyType keyType, EtsiKey* key)
{
    int ret = WOLFKM_NOT_COMPILED_IN;
    const char* keyTypeStr = wolfEtsiKeyGetTypeStr(keyType);

    if (svcCtx == NULL || key == NULL || keyTypeStr == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    XLOG(WOLFKM_LOG_WARN, "Generating new %s key\n", keyTypeStr);

    ret = wolfEtsiKeyGen(key, keyType, &svcCtx->rng);
    if (ret == 0) {
        key->expires = wolfGetCurrentTimeT() + svcCtx->renewSec;
    #ifdef WOLFKM_VAULT
        ret = AddKeyToVault(svcCtx, key);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "Failed adding %s key to vault! %d\n",
                keyTypeStr, ret);
        }
    #endif
    }
    else {
        XLOG(WOLFKM_LOG_ERROR, "Failed generating %s key! %s (%d)\n",
            keyTypeStr, wolfKeyMgr_GetError(ret), ret);
    }

    return ret;
}

static int SetupKeyPackage(SvcConn* conn, EtsiSvcCtx* svcCtx)
{
    int ret = 0, i;
    EtsiSvcConn* etsiConn;
    HttpHeader headers[3];
    struct tm tm;
    char expiresStr[100];
    EtsiKey* key = NULL;

    if (conn == NULL || conn->svcConnCtx == NULL || svcCtx == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    etsiConn = (EtsiSvcConn*)conn->svcConnCtx;
    
    headers[0].type = HTTP_HDR_CONTENT_TYPE;
    headers[0].string = "application/pkcs8";
    headers[1].type = HTTP_HDR_CONNECTION;
    headers[1].string = "Keep-Alive";
    headers[2].type = HTTP_HDR_EXPIRES;
    headers[2].string = expiresStr;
    memset(expiresStr, 0, sizeof(expiresStr));

    /* find key based on group */
    pthread_mutex_lock(&svcCtx->lock);
    for (i=0; i<ETSI_SVC_MAX_ACTIVE_KEYS; i++) {
        if ((word32)svcCtx->keys[i].type == etsiConn->groupNum) {
            key = &svcCtx->keys[i];
            break;
        }
    }
    /* if one doesn't exist for this group then trigger generation */
    if (key == NULL) {
        /* assign free slot */
        for (i=0; i<ETSI_SVC_MAX_ACTIVE_KEYS; i++) {
            if ((word32)svcCtx->keys[i].type == 0) {
                key = &svcCtx->keys[i];
                break;
            }
        }
        /* if no free slots then find oldest key */
        if (key == NULL) {
            time_t oldestTime = 0;
            for (i=0; i<ETSI_SVC_MAX_ACTIVE_KEYS; i++) {
                if (oldestTime == 0 || oldestTime > svcCtx->keys[i].expires)
                    oldestTime = svcCtx->keys[i].expires;
            }
            for (i=0; i<ETSI_SVC_MAX_ACTIVE_KEYS; i++) {
                if (oldestTime == svcCtx->keys[i].expires) {
                    key = &svcCtx->keys[i];
                    break;
                }
            }
        }
        ret = GenNewKey(svcCtx, etsiConn->groupNum, key);
    }

    if (ret == 0) {
        /* Format Expires Time */
        localtime_r(&key->expires, &tm);
        strftime(expiresStr, sizeof(expiresStr), HTTP_DATE_FMT, &tm);

        /* Wrap key in HTTP server response */
        conn->responseSz = sizeof(conn->response);
        ret = wolfHttpServer_EncodeResponse(0, NULL, 
            conn->response, &conn->responseSz, headers, 
            sizeof(headers)/sizeof(HttpHeader), (byte*)key->response,
            key->responseSz);
    }
    pthread_mutex_unlock(&svcCtx->lock);

    return ret;
}

#ifdef WOLFKM_VAULT
static int SetupKeyFindResponse(SvcConn* conn, wolfVaultItem* item)
{
    int ret = 0;
    HttpHeader headers[2];
    headers[0].type = HTTP_HDR_CONTENT_TYPE;
    headers[0].string = "application/pkcs8";
    headers[1].type = HTTP_HDR_CONNECTION;
    headers[1].string = "Keep-Alive";

    /* Wrap key in HTTP server response */
    conn->responseSz = sizeof(conn->response);
    ret = wolfHttpServer_EncodeResponse(0, NULL, 
        conn->response, &conn->responseSz, headers, 
        sizeof(headers)/sizeof(HttpHeader), (byte*)item->data,
        item->dataSz);

    return ret;
}
#endif

static void* KeyPushWorker(void* arg)
{
    int i;
    SvcInfo* svc = (SvcInfo*)arg;
    EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;
    EtsiKey* key;
    time_t now, nextExpires;
    int renewSec, keyGenCount;

    /* generate default key */
    pthread_mutex_lock(&svcCtx->lock);
    key = &svcCtx->keys[0];
    (void)GenNewKey(svcCtx, svcCtx->keyTypeDef, key);
    pthread_mutex_unlock(&svcCtx->lock);

    do {
        keyGenCount = 0;
        nextExpires = 0;

        /* renew any expired keys */
        pthread_mutex_lock(&svcCtx->lock);
        now = wolfGetCurrentTimeT();
        for (i=0; i<ETSI_SVC_MAX_ACTIVE_KEYS; i++) {
            if (svcCtx->keys[i].type != ETSI_KEY_TYPE_UNKNOWN && svcCtx->keys[i].expires > 0) {
                if (now >= svcCtx->keys[i].expires) {
                    (void)GenNewKey(svcCtx, svcCtx->keys[i].type, &svcCtx->keys[i]);
                    keyGenCount++;
                }
                if (nextExpires == 0 || nextExpires > svcCtx->keys[i].expires)
                    nextExpires = svcCtx->keys[i].expires;
            }
        }
        renewSec = (nextExpires > now) ? nextExpires - now : svcCtx->renewSec;
        pthread_mutex_unlock(&svcCtx->lock);

        if (keyGenCount > 0) {
            /* push to any connected clients */
            wolfKeyMgr_NotifyAllClients(svc);
        }

        /* wait seconds */
        XLOG(WOLFKM_LOG_INFO, "Next key renewal %d seconds\n", renewSec);
        sleep(renewSec);
    } while (1);

    return NULL;
}

static int wolfEtsiSvc_DoResponse(SvcConn* conn)
{
    int ret;

    if (conn == NULL || conn->stream == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI response pointers\n");
        return WOLFKM_BAD_ARGS;
    }
    if (conn->responseSz == 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI HTTP Response / Key not found!\n");
        return WOLFKM_BAD_KEY;
    }

    /* send response, which is in the reused request buffer */
    ret = wolfKeyMgr_DoSend(conn, (byte*)conn->response, conn->responseSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI DoSend failed: %d\n", ret);
        return WOLFKM_BAD_SEND;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent ETSI Response (%d bytes)\n", conn->responseSz);

    return ret;
}

/* the key request handler */
int wolfEtsiSvc_DoRequest(SvcConn* conn)
{
    int ret = 0;
    SvcInfo* svc;
    EtsiSvcCtx* svcCtx;
    EtsiSvcConn* etsiConn;;

    if (conn == NULL || conn->svc == NULL || conn->stream == NULL) {
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

    ret = wolfHttpServer_ParseRequest(&etsiConn->req, conn->request,
        conn->requestSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI HTTP Server Parse failed: %d\n", ret);
        return WOLFKM_BAD_REQUEST_TYPE;
    }
    wolfHttpRequestPrint(&etsiConn->req);

    /* Get fingerprint */
    if (wolfHttpUriGetItem(etsiConn->req.uri, "fingerprints=",
        etsiConn->fingerprint, sizeof(etsiConn->fingerprint)) > 0) {
        XLOG(WOLFKM_LOG_DEBUG, "Fingerprint: %s\n", etsiConn->fingerprint);
    }

    /* Get groups - borrow contextStr variable */
    if (wolfHttpUriGetItem(etsiConn->req.uri, "groups=",
        etsiConn->contextStr, sizeof(etsiConn->contextStr)) > 0) {
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
    if (wolfHttpUriGetItem(etsiConn->req.uri, "contextstr=",
        etsiConn->contextStr, sizeof(etsiConn->contextStr)) > 0) {
        XLOG(WOLFKM_LOG_DEBUG, "Context: %s\n", etsiConn->contextStr);
    }

#ifdef WOLFKM_VAULT
    /* If "find" request (fingerprint) populated */
    if (etsiConn->groupNum > 0 && strlen(etsiConn->fingerprint) > 0) {
        wolfVaultItem item;
        memset(&item, 0, sizeof(item));
        item.nameSz = (word32)sizeof(item.name);
        ret = wolfHexStringToByte(etsiConn->fingerprint,
            strlen(etsiConn->fingerprint), item.name, item.nameSz);
        if (ret > 0) {
            item.nameSz = ret;
            ret = 0;
        }
        if (ret == 0) {
            ret = wolfVaultGet(svcCtx->vault, &item, etsiConn->groupNum,
                item.name, item.nameSz);
            if (ret == 0) {
                ret = SetupKeyFindResponse(conn, &item);
            }
            wolfVaultFreeItem(&item);            
        }
    }
    else
#endif
    if (etsiConn->groupNum > 0) {
        ret = SetupKeyPackage(conn, svcCtx);
    }

    if (ret != 0) {
        /* TODO: Setup error response */
    }

    /* Send Response */
    if (ret == 0) {
        ret = wolfEtsiSvc_DoResponse(conn);
    }

    return ret;
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
    EtsiSvcConn* etsiConn;

    if (conn == NULL || conn->svc == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI notify pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    svc = conn->svc;
    svcCtx = (EtsiSvcCtx*)svc->svcCtx;
    etsiConn = (EtsiSvcConn*)conn->svcConnCtx;

    /* update key */
    ret = SetupKeyPackage(conn, svcCtx);

    /* push key to active push threads */
    if (ret == 0 && etsiConn != NULL && 
            etsiConn->req.type == HTTP_METHOD_PUT) {    
        /* send updated key */
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

SvcInfo* wolfEtsiSvc_Init(int renewSec, EtsiKeyType keyTypeDef)
{
    int ret;
    SvcInfo* svc = &etsiService;
    EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;

    ret = wc_InitRng(&svcCtx->rng);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error initializing RNG %d\n", ret);
        return NULL;
    }

    pthread_mutex_init(&svcCtx->lock, NULL);

    svcCtx->renewSec = renewSec;
    svcCtx->keyTypeDef = keyTypeDef;

    return svc;
}

int wolfEtsiSvc_Start(SvcInfo* svc, struct event_base* mainBase, const char* listenPort)
{
    int ret;
    EtsiSvcCtx* svcCtx;

    if (svc == NULL)
        return WOLFKM_BAD_ARGS;

    svcCtx = (EtsiSvcCtx*)svc->svcCtx;

    /* start key generation thread */
    if (pthread_create(&svcCtx->thread, NULL, KeyPushWorker, svc) != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error creating keygen worker\n");
        return WOLFKM_BAD_MEMORY;
    }

    /* setup listening events */
    ret = wolfKeyMgr_AddListeners(svc, AF_INET6, listenPort, mainBase);  /* 6 may contain a 4 */
    if (ret < 0)
        ret = wolfKeyMgr_AddListeners(svc, AF_INET, listenPort, mainBase);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to bind at least one ETSI listener,"
                               "already running?\n");
    }

    return ret;
}

void wolfEtsiSvc_Cleanup(SvcInfo* svc)
{
    if (svc) {
        EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;

        if (svc->keyBuffer) {
            free(svc->keyBuffer);
            svc->keyBuffer = NULL;
        }
        if (svc->certBuffer) {
            free(svc->certBuffer);
            svc->certBuffer = NULL;
        }
    #ifdef WOLFKM_VAULT
        if (svcCtx->vault) {
            wolfVaultClose(svcCtx->vault);
        }
    #endif

        wc_FreeRng(&svcCtx->rng);
        pthread_mutex_destroy(&svcCtx->lock);
    }
}

static int wolfEtsiSvcVaultAuthCb(wolfVaultCtx* ctx, byte* key, word32 keySz,
    void* cbCtx)
{
    int ret;
    EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)cbCtx;

#if 1
    /* For testing use fixed key */
    static byte k1[] = {
        0x1e, 0xa6, 0x61, 0xc5, 0x8d, 0x94, 0x3a, 0x0e,
        0x48, 0x01, 0xe4, 0x2f, 0x4b, 0x09, 0x47, 0x14,
        0x9e, 0x7f, 0x9f, 0x8e, 0x3e, 0x68, 0xd0, 0xc7,
        0x50, 0x52, 0x10, 0xbd, 0x31, 0x1a, 0x0e, 0x7c,
        0xd6, 0xe1, 0x3f, 0xfd, 0xf2, 0x41, 0x8d, 0x8d,
        0x19, 0x11, 0xc0, 0x04, 0xcd, 0xa5, 0x8d, 0xa3,
        0xd6, 0x19, 0xb7, 0xe2, 0xb9, 0x14, 0x1e, 0x58,
        0x31, 0x8e, 0xea, 0x39, 0x2c, 0xf4, 0x1b, 0x08
    };
    if (keySz > sizeof(k1))
        keySz = sizeof(k1);
    memcpy(key, k1, keySz);
    ret = 0;
#else
    /* TODO: Setting up authentication key */
    /* TODO: !NO_RSA
    WC_RNG rng;
    RsaKey key;

    /* do we have an encrypted key available? */

    /* Generate key for encryption */
    ret = wc_InitRng(&rng, NULL);
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&rng, key, keySz);
        wc_FreeRng(&rnd);
    }

    /* use long term private RSA key to encrypt key */
    ret = wc_InitRsaKey(&key, NULL);
    if (ret == 0) {
        byte in[256], *out = NULL;
        word32 inLen = (word32)sizeof(in);
        word32 idx = 0;
        ret = wc_RsaPrivateKeyDecode(svcCtx->keyBuffer, &idx, &key, svcCtx->keyBufferSz);

        if (ret == 0) {
            ret = wc_RsaPrivateDecryptInline(in, inLen, &out, &key);
        }

        wc_FreeRsaKey(&key);
    }
#endif

    (void)key;
    (void)keySz;
    (void)svcCtx;
    return ret;
}

int wolfEtsiSvc_SetVaultFile(SvcInfo* svc, const char* vaultFile)
{
    int ret = 0;
    EtsiSvcCtx* svcCtx;
    
    if (svc == NULL || vaultFile == NULL)
        return WOLFKM_BAD_ARGS;

#ifdef WOLFKM_VAULT
    svcCtx = (EtsiSvcCtx*)svc->svcCtx;
    ret = wolfVaultOpen(&svcCtx->vault, vaultFile);
    if (ret == 0) {
        wolfVaultPrintInfo(svcCtx->vault);

        ret = wolfVaultAuth(svcCtx->vault, wolfEtsiSvcVaultAuthCb, svcCtx);
    }
#endif
    return ret;
}
