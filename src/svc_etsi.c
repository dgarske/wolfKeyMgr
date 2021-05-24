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

#ifdef WOLFKM_ETSI_SERVICE

/* shared context for worker threads */
typedef struct EtsiSvcCtx {
    /* latest shared key data */
    EtsiKeyType     keyType;
    time_t          expires;
    word32          renewSec;
    word32          index;

    /* wolf key struct union */
    union {
    #ifdef HAVE_ECC
        ecc_key ecc;
    #endif
    #if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
        DhKey dh;
    #endif
    #ifdef HAVE_CURVE25519
        curve25519_key x25519;
    #endif
    #ifdef HAVE_CURVE448
        curve448_key x448;
    #endif
    } key;

    /* exported private key as PKCS8 (DER) */
    byte            keyBuf[ETSI_MAX_RESPONSE_SZ];
    word32          keyBufSz;

    /* Key Gen worker thread */
    WC_RNG          rng;
    pthread_mutex_t lock; /* queue lock */
    pthread_t       thread; /* key gen worker */
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
typedef struct etsiSvcThread {
    word32 index;
    byte   httpRspBuf[ETSI_MAX_RESPONSE_SZ];
    word32 httpRspSz;
} etsiSvcThread;

typedef struct etsiSvcConn {
    HttpReq req;
} etsiSvcConn;

#ifdef HAVE_ECC
static int GenNewKeyEcc(EtsiSvcCtx* svcCtx, EtsiKeyType keyType)
{
    int ret;
    int curveId = ECC_CURVE_DEF, keySize = 32;

    /* Determine ECC Key Size and Curve */
    switch (keyType) {
        case ETSI_KEY_TYPE_SECP160K1:
            curveId = ECC_SECP160K1; keySize = 20; break;
        case ETSI_KEY_TYPE_SECP160R1:
            curveId = ECC_SECP160R1; keySize = 20; break;
        case ETSI_KEY_TYPE_SECP160R2:
            curveId = ECC_SECP160R2; keySize = 20; break;
        case ETSI_KEY_TYPE_SECP192K1:
            curveId = ECC_SECP192K1; keySize = 24; break;
        case ETSI_KEY_TYPE_SECP192R1:
            curveId = ECC_SECP192R1; keySize = 24; break;
        case ETSI_KEY_TYPE_SECP224K1:
            curveId = ECC_SECP224K1; keySize = 28; break;
        case ETSI_KEY_TYPE_SECP224R1:
            curveId = ECC_SECP224R1; keySize = 28; break;
        case ETSI_KEY_TYPE_SECP256K1:
            curveId = ECC_SECP256K1; keySize = 32; break;
        case ETSI_KEY_TYPE_SECP256R1:
            curveId = ECC_SECP256R1; keySize = 32; break;
        case ETSI_KEY_TYPE_SECP384R1:
            curveId = ECC_SECP384R1; keySize = 48; break;
        case ETSI_KEY_TYPE_SECP521R1:
            curveId = ECC_SECP521R1; keySize = 66; break;
        case ETSI_KEY_TYPE_BRAINPOOLP256R1:
            curveId = ECC_BRAINPOOLP256R1; keySize = 32; break;
        case ETSI_KEY_TYPE_BRAINPOOLP384R1:
            curveId = ECC_BRAINPOOLP384R1; keySize = 48; break;
        case ETSI_KEY_TYPE_BRAINPOOLP512R1:
            curveId = ECC_BRAINPOOLP512R1; keySize = 64; break;
        default:
            break;
    }

    ret = wc_ecc_init(&svcCtx->key.ecc);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "ECC Init Failed! %d\n", ret);
        return WOLFKM_BAD_KEY;
    }
        
    ret = wc_ecc_make_key_ex(&svcCtx->rng, keySize, &svcCtx->key.ecc,
        curveId);
    if (ret == 0) {
        /* Export as DER IETF RFC 5915 */
        svcCtx->keyBufSz = sizeof(svcCtx->keyBuf);
        ret = wc_EccKeyToDer(&svcCtx->key.ecc, svcCtx->keyBuf, svcCtx->keyBufSz);
        if (ret >= 0) {
            svcCtx->keyBufSz = ret;
            ret = 0;
        }
    }

    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "ECC Key Generation Failed! %d\n", ret);
        wc_ecc_free(&svcCtx->key.ecc);
    }

    return ret;
}
#endif

#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)

/* Determine max build-time DH key sizes */
#if defined(HAVE_FFDHE_8192)
    #define MAX_DH_PRIV_SZ 52
    #define MAX_DH_PUB_SZ  1024
#elif defined(HAVE_FFDHE_6144)
    #define MAX_DH_PRIV_SZ 46
    #define MAX_DH_PUB_SZ  768
#elif defined(HAVE_FFDHE_4096)
    #define MAX_DH_PRIV_SZ 39
    #define MAX_DH_PUB_SZ  512
#elif defined(HAVE_FFDHE_3072)
    #define MAX_DH_PRIV_SZ 34
    #define MAX_DH_PUB_SZ  384
#elif defined(HAVE_FFDHE_2048)
    #define MAX_DH_PRIV_SZ 29
    #define MAX_DH_PUB_SZ  256
#else
    #error No DH FFDHE parameters enabled!
#endif

static int GenNewKeyDh(EtsiSvcCtx* svcCtx, EtsiKeyType keyType)
{
    int ret;
    const DhParams* params = NULL;
    word32 privKeySz = 0, pubKeySz = 0;
    byte privKey[MAX_DH_PRIV_SZ];
    byte pubKey[MAX_DH_PUB_SZ];

    switch (keyType) {
    #ifdef HAVE_FFDHE_2048
        case ETSI_KEY_TYPE_FFDHE_2048:
            params = wc_Dh_ffdhe2048_Get(); privKeySz = 29; break;
    #endif
    #ifdef HAVE_FFDHE_3072
        case ETSI_KEY_TYPE_FFDHE_3072:
            params = wc_Dh_ffdhe3072_Get(); privKeySz = 34; break;
    #endif
    #ifdef HAVE_FFDHE_4096
        case ETSI_KEY_TYPE_FFDHE_4096:
            params = wc_Dh_ffdhe4096_Get(); privKeySz = 39; break;
    #endif
    #ifdef HAVE_FFDHE_6144
        case ETSI_KEY_TYPE_FFDHE_6144:
            params = wc_Dh_ffdhe6144_Get(); privKeySz = 46; break;
    #endif
    #ifdef HAVE_FFDHE_8192
        case ETSI_KEY_TYPE_FFDHE_8192:
            params = wc_Dh_ffdhe8192_Get(); privKeySz = 52; break;
    #endif
        default:
            break;
    }

    if (params == NULL) {
        return WOLFKM_NOT_COMPILED_IN;
    }

    ret = wc_InitDhKey(&svcCtx->key.dh);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "DH Init Failed! %d\n", ret);
        return WOLFKM_BAD_KEY;
    }

    /* Set key params */
    ret = wc_DhSetKey(&svcCtx->key.dh,
        params->p, params->p_len,
        params->g, params->g_len);
    if (ret == 0) {
        /* Generate a new key pair */
        pubKeySz = params->p_len;
        ret = wc_DhGenerateKeyPair(&svcCtx->key.dh, &svcCtx->rng,
            privKey, &privKeySz,
            pubKey, &pubKeySz);
    }
    if (ret == 0) {
        if (params->p_len != pubKeySz) {
            /* Zero pad the front of the public key to match prime "p" size */
            memmove(pubKey + params->p_len - pubKeySz, pubKey, pubKeySz);
            memset(pubKey, 0, params->p_len - pubKeySz);
        }

        /* load public and private key info into DkKey */
        ret = wc_DhImportKeyPair(&svcCtx->key.dh,
            privKey, privKeySz,
            pubKey, pubKeySz);
    }

    if (ret == 0) {
        /* export DH key as DER */
        /* Note: Proper support for wc_DhPrivKeyToDer was added v4.8.0 or later (see PR 3832) */
        svcCtx->keyBufSz = sizeof(svcCtx->keyBuf);
        ret = wc_DhPrivKeyToDer(&svcCtx->key.dh, svcCtx->keyBuf, &svcCtx->keyBufSz);
        if (ret >= 0)
            ret = 0; /* size is returned in keyBufSz */
    }

    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "DH Key Generation Failed! %d\n", ret);
        wc_FreeDhKey(&svcCtx->key.dh);
    }

    return ret;
}
#endif /* !NO_DH */

/* caller should lock svcCtx->lock */
static void FreeSvcKey(EtsiSvcCtx* svcCtx)
{
    if (svcCtx == NULL || svcCtx->keyType == ETSI_KEY_TYPE_UNKNOWN) {
        return;
    }

#ifdef HAVE_ECC
    if (svcCtx->keyType >= ETSI_KEY_TYPE_SECP160K1 && 
        svcCtx->keyType <= ETSI_KEY_TYPE_BRAINPOOLP512R1) {
        wc_ecc_free(&svcCtx->key.ecc);
    }
#endif
#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
    if (svcCtx->keyType >= ETSI_KEY_TYPE_FFDHE_2048 && 
        svcCtx->keyType <= ETSI_KEY_TYPE_FFDHE_8192) {
        wc_FreeDhKey(&svcCtx->key.dh);
    }
#endif
#ifdef HAVE_CURVE25519
    if (svcCtx->keyType == ETSI_KEY_TYPE_X25519) {
        wc_curve25519_free(&svcCtx->key.x25519);
    }
#endif
#ifdef HAVE_CURVE448
    if (svcCtx->keyType == ETSI_KEY_TYPE_X448) {
        wc_curve448_free(&svcCtx->key.x448);
    }
#endif
    svcCtx->keyType = ETSI_KEY_TYPE_UNKNOWN;
}

static int GenNewKey(EtsiSvcCtx* svcCtx)
{
    int ret = NOT_COMPILED_IN;
    EtsiKeyType keyType;

    pthread_mutex_lock(&svcCtx->lock);
    keyType = svcCtx->keyType;

    /* Free old key type */
    FreeSvcKey(svcCtx);

#ifdef HAVE_ECC
    /* Default to SECP256R1 */
    if (keyType == ETSI_KEY_TYPE_UNKNOWN)
        keyType = ETSI_KEY_TYPE_SECP256R1;
    if (keyType >= ETSI_KEY_TYPE_SECP160K1 && 
        keyType <= ETSI_KEY_TYPE_BRAINPOOLP512R1) {
        XLOG(WOLFKM_LOG_WARN, "Generating new %s key (index %d)\n",
            wolfEtsiKeyGetTypeStr(keyType), svcCtx->index);
        ret = GenNewKeyEcc(svcCtx, keyType);
    }
#endif
#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
    if (keyType == ETSI_KEY_TYPE_UNKNOWN)
        keyType = ETSI_KEY_TYPE_FFDHE_2048;
    if (keyType >= ETSI_KEY_TYPE_FFDHE_2048 && 
        keyType <= ETSI_KEY_TYPE_FFDHE_8192) {
        XLOG(WOLFKM_LOG_WARN, "Generating new %s key (index %d)\n",
            wolfEtsiKeyGetTypeStr(keyType), svcCtx->index);
        ret = GenNewKeyDh(svcCtx, keyType);
    }
#endif
#ifdef HAVE_CURVE25519
    if (keyType == ETSI_KEY_TYPE_UNKNOWN)
        keyType = ETSI_KEY_TYPE_X25519;
    if (keyType == ETSI_KEY_TYPE_X25519) {
        XLOG(WOLFKM_LOG_WARN, "Generating new X25519 key (index %d)\n",
            svcCtx->index);
    }
#endif
#ifdef HAVE_CURVE448
    if (keyType == ETSI_KEY_TYPE_UNKNOWN)
        keyType = ETSI_KEY_TYPE_X448;
    if (keyType == ETSI_KEY_TYPE_X448) {
        //curveId = ECC_X448;
        //keySize = 56;
        XLOG(WOLFKM_LOG_WARN, "Generating new X448 key (index %d)\n",
            svcCtx->index);
    }
#endif

    if (ret == 0) {
        svcCtx->expires = wolfGetCurrentTimeT() + svcCtx->renewSec;
        svcCtx->keyType = keyType;
        svcCtx->index++;
    }

    pthread_mutex_unlock(&svcCtx->lock);
    return ret;
}

static int SetupKeyPackage(EtsiSvcCtx* svcCtx, etsiSvcThread* etsiThread)
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

    pthread_mutex_lock(&svcCtx->lock);
    XLOG(WOLFKM_LOG_DEBUG, "Synchronizing key to worker thread\n"); 
    if (etsiThread->index != svcCtx->index) {
        /* Format Expires Time */
        struct tm tm;
        localtime_r(&svcCtx->expires, &tm);
        strftime(expiresStr, sizeof(expiresStr), HTTP_DATE_FMT, &tm);

        /* Wrap key in HTTP server response */
        etsiThread->httpRspSz = sizeof(etsiThread->httpRspBuf);
        ret = wolfHttpServer_EncodeResponse(0, NULL, 
            etsiThread->httpRspBuf, &etsiThread->httpRspSz, headers, 
            sizeof(headers)/sizeof(HttpHeader), svcCtx->keyBuf, svcCtx->keyBufSz);
        if (ret != 0) {
            pthread_mutex_unlock(&svcCtx->lock);
            XLOG(WOLFKM_LOG_ERROR, "Error encoding HTTP response: %d\n", ret);
            return ret;
        }

        etsiThread->index = svcCtx->index;
    }
    pthread_mutex_unlock(&svcCtx->lock);

    return ret;
}

static void* KeyPushWorker(void* arg)
{
    int ret;
    SvcInfo* svc = (SvcInfo*)arg;
    EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;

    do {
        /* generate new key */
        ret = GenNewKey(svcCtx);
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
    etsiSvcThread* etsiThread;

    if (conn == NULL || conn->stream == NULL || conn->svcThreadCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI response pointers\n");
        return WOLFKM_BAD_ARGS;
    }
    etsiThread = (etsiSvcThread*)conn->svcThreadCtx;
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
    etsiSvcConn* etsiConn;
    char *fingerprint, *groups;

    if (conn == NULL || conn->stream == NULL || conn->svcThreadCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI Request pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    XLOG(WOLFKM_LOG_INFO, "Got ETSI Request (%d bytes)\n", conn->requestSz);

    if (conn->svcConnCtx == NULL) {
        /* Creating connection context */
        XLOG(WOLFKM_LOG_INFO, "Creating connection context\n");
        conn->svcConnCtx = malloc(sizeof(etsiSvcConn));
        if (conn->svcConnCtx == NULL) {
            return WOLFKM_BAD_MEMORY;
        }
    }
    etsiConn = (etsiSvcConn*)conn->svcConnCtx;

    ret = wolfHttpServer_ParseRequest(&etsiConn->req, conn->request,
        conn->requestSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI HTTP Server Parse failed: %d\n", ret);
        return WOLFKM_BAD_REQUEST_TYPE;
    }
    wolfHttpRequestPrint(&etsiConn->req);

    /* Get fingerprint and groups */
    fingerprint = wolfHttpUriGetItem(etsiConn->req.uri, "fingerprint=");
    groups = wolfHttpUriGetItem(etsiConn->req.uri, "groups=");
    printf("Fingerprint %s\n", fingerprint);
    printf("Groups %s\n", groups);

    /* TODO: Get key based on parameters */


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
    etsiSvcThread* etsiThread;
    etsiSvcConn* etsiConn;

    if (conn == NULL || conn->svc == NULL || conn->svcThreadCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI notify pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    svc = conn->svc;
    svcCtx = (EtsiSvcCtx*)svc->svcCtx;
    etsiThread = (etsiSvcThread*)conn->svcThreadCtx;
    etsiConn = (etsiSvcConn*)conn->svcConnCtx;

    /* update key */
    ret = SetupKeyPackage(svcCtx, etsiThread);

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
    etsiSvcConn* etsiConn;

    if (conn == NULL || conn->svcConnCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI timeout pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    etsiConn = (etsiSvcConn*)conn->svcConnCtx;

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
    etsiSvcThread* etsiThread = malloc(sizeof(*etsiThread));
    if (etsiThread == NULL) {
        return WOLFKM_BAD_MEMORY;
    }
    memset(etsiThread, 0, sizeof(*etsiThread));

    /* make sure we have a key package setup to send */
    ret = SetupKeyPackage(svcCtx, etsiThread);

    *svcThreadCtx = etsiThread;

    return ret;
}

void wolfEtsiSvc_WorkerFree(SvcInfo* svc, void* svcThreadCtx)
{
    if (svcThreadCtx == NULL)
        return;

    (void)svc;

    free((etsiSvcThread*)svcThreadCtx);
}

#endif /* WOLFKM_ETSI_SERVICE */


SvcInfo* wolfEtsiSvc_Init(struct event_base* mainBase, int renewSec)
{
#ifdef WOLFKM_ETSI_SERVICE
    int ret;
    char* listenPort = WOLFKM_ETSISVC_PORT;
    SvcInfo* svc = &etsiService;
    EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;

    ret = wc_InitRng(&svcCtx->rng);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Can't make keygen worker\n");
        return NULL;
    }

    pthread_mutex_init(&svcCtx->lock, NULL);

    svcCtx->renewSec = renewSec;

    /* start key generation thread */
    if (pthread_create(&svcCtx->thread, NULL, KeyPushWorker, svc) != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Can't make keygen worker\n");
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

        FreeSvcKey(svcCtx);
        wc_FreeRng(&svcCtx->rng);
        pthread_mutex_destroy(&svcCtx->lock);
    }
#endif
}
