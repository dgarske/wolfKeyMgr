/* etsi_client.c
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

#ifdef WOLFKM_ETSI_SERVICE

#include "mod_etsi.h"
#include "mod_tls.h"

struct EtsiClientCtx {
    WOLFSSL_CTX*   sslCtx;
    WOLFSSL*       ssl;
    EtsiClientType type;
};

static const char* kEtsiGet1 = "GET /.well-known/enterprise-transport-security/keys?fingerprints=%s HTTP/1.1\r\nAccept: application/pkcs8\r\n";
//static const char* kEtsiGet2 = "GET /.well-known/enterprise-transport-security/keys?groups=%s&certs=%s HTTP/1.1\r\nAccept: application/pkcs8\r\n";
static const char* kEtsiPush = "PUT /enterprise-transport-security/keys HTTP/1.1\r\nAccept: application/pkcs8\r\n";


EtsiClientCtx* wolfKeyMgr_EtsiClientNew(void)
{
    EtsiClientCtx* client = (EtsiClientCtx*)malloc(sizeof(EtsiClientCtx));
    if (client) {
        memset(client, 0, sizeof(EtsiClientCtx));
        client->sslCtx = wolfKeyMgr_TlsClientNew();
        if (client->sslCtx == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "Error creating TLS client!\n");
            free(client);
            return NULL;
        }
    }
    return client;
}

int wolfKeyMgr_EtsiClientSetKey(EtsiClientCtx* client, const char* keyFile, 
    const char* keyPassword, const char* certFile, int fileType)
{
    int ret;
    if (client == NULL) {
        return WOLFKM_BAD_ARGS;
    }
    ret = wolfKeyMgr_TlsSetKey(client->sslCtx, keyFile, keyPassword, certFile, fileType);
    return ret;
}

int wolfKeyMgr_EtsiClientAddCA(EtsiClientCtx* client, const char* caFile)
{
    int ret;
    if (client == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    ret = wolfKeyMgr_TlsAddCA(client->sslCtx, caFile);
    return ret;
}

int wolfKeyMgr_EtsiClientConnect(EtsiClientCtx* client, const char* host,
    word16 port, int timeoutSec)
{
    int ret;

    if (client == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    ret = wolfKeyMgr_TlsConnect(client->sslCtx, &client->ssl, host, port, timeoutSec);
    if (ret == 0) {
        XLOG(WOLFKM_LOG_INFO, "Connected to ETSI service\n");
    }
    else {
        XLOG(WOLFKM_LOG_ERROR, "Failure connecting to ETSI service %d\n", ret);   
    }

    return ret;
}

static int EtsiClientMakeRequest(EtsiClientType type, const char* fingerprint,
    char* request, word32* requestSz)
{
    /* Build HTTP ETSI request */
    if (type == ETSI_CLIENT_PUSH) {
        *requestSz = strlen(kEtsiPush);
        strncpy(request, kEtsiPush, *requestSz+1);
    }
    else {
        *requestSz = snprintf(request, *requestSz, kEtsiGet1, fingerprint);
    }
    return 0;
}

int wolfKeyMgr_EtsiClientGet(EtsiClientCtx* client, 
    EtsiClientType type, const char* fingerprint, int timeoutSec,
    byte* response, word32* responseSz)
{
    int    ret;
    char   request[ETSI_MAX_REQUEST_SZ];
    word32 requestSz = ETSI_MAX_REQUEST_SZ;
    int    pos;

    if (client == NULL || response == NULL || responseSz == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    /* only send request if we need to */
    if (type != ETSI_CLIENT_PUSH || client->type != type) {
        ret = EtsiClientMakeRequest(type, fingerprint, request, &requestSz);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_INFO, "EtsiClientMakeRequest failed: %d\n", ret);
            return ret;
        }

        /* send key request */
        pos = 0;
        while (pos < requestSz) {
            ret = wolfKeyMgr_TlsWrite(client->ssl, (byte*)request + pos,
                requestSz - pos);
            if (ret < 0) {
                XLOG(WOLFKM_LOG_INFO, "DoClientSend failed: %d\n", ret);
                return ret;
            }
            pos += ret;
        }
        XLOG(WOLFKM_LOG_INFO, "Sent %s request\n", 
            type == ETSI_CLIENT_PUSH ? "push" : "single get");
        client->type = type;
    }

    do {
        /* get key response */
        ret = wolfKeyMgr_TlsRead(client->ssl, response, *responseSz, timeoutSec);
        if (ret < 0) {
            XLOG(WOLFKM_LOG_ERROR, "DoClientRead failed: %d\n", ret);
            break;
        }
        /* zero respnse means try again */
    } while (ret == 0);
    
    if (ret > 0) {
        /* asymmetric key package response */
        *responseSz = ret;
        XLOG(WOLFKM_LOG_INFO, "Got ETSI response sz = %d\n", *responseSz);
        ret = 0;
    }

    /* TODO: Parse HTTP headers and just return PKCS8 key */

    return ret;
}

int wolfKeyMgr_EtsiLoadKey(ecc_key* key, byte* buffer, word32 length)
{
    int ret;
    word32 idx = 0;

    if (key == NULL || buffer == NULL || length == 0) {
        return WOLFKM_BAD_ARGS;
    }

    /* Parsing key package */
    ret = wc_EccPrivateKeyDecode(buffer, &idx, key, length);

    return ret;
}

int wolfKeyMgr_EtsiClientClose(EtsiClientCtx* client)
{
    int ret = 0;
    if (client) {
        /* send shutdown */
        ret = wolfKeyMgr_TlsClose(client->ssl, 1);
        client->ssl = NULL;
    }
    return ret;
}

void wolfKeyMgr_EtsiClientFree(EtsiClientCtx* client)
{
    if (client) {
        wolfKeyMgr_TlsFree(client->sslCtx);
        client->sslCtx = NULL;
        free(client);
    }

    wolfSSL_Cleanup();
}

#endif /* WOLFKM_ETSI_SERVICE */
