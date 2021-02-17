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
    wkmTlsCtx      tls;
    EtsiClientType type;
    const char*    fingerprint;
    WKM_SOCKET_T   sockfd;
    int            noTLS;
};

static const char* kEtsiGet1 = "GET /.well-known/enterprise-transport-security/keys?fingerprints=%s HTTP/1.1\r\nAccept: application/pkcs8\r\n";
//static const char* kEtsiGet2 = "GET /.well-known/enterprise-transport-security/keys?groups=%s&certs=%s HTTP/1.1\r\nAccept: application/pkcs8\r\n";
static const char* kEtsiPush = "PUT /enterprise-transport-security/keys HTTP/1.1\r\nAccept: application/pkcs8\r\n";

#define WOLFKM_ETSISVC_CERT    "./certs/test-cert.pem"

EtsiClientCtx* wolfKeyMgr_EtsiClientNew(void)
{
    int ret;
    EtsiClientCtx* client = (EtsiClientCtx*)malloc(sizeof(EtsiClientCtx));
    if (client) {
        memset(client, 0, sizeof(EtsiClientCtx));
        ret = wolfKeyMgr_TlsClientInit(&client->tls, WOLFKM_ETSISVC_CERT, NULL, NULL);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "Error setting up TLS client %d\n", ret);
            free(client);
            return NULL;
        }
    }
    return client;
}

int wolfKeyMgr_EtsiClientConnect(EtsiClientCtx* client, const char* host, word16 port)
{
    int ret;

    if (client == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    ret = wolfKeyMgr_TlsConnect(&client->tls, host, port);
    if (ret == 0) {
        XLOG(WOLFKM_LOG_INFO, "Connected to ETSI service\n");
    }
    else {
        XLOG(WOLFKM_LOG_ERROR, "Failure connecting to ETSI service %d\n", ret);   
    }

    return ret;
}

int wolfKeyMgr_EtsiClientGet(EtsiClientCtx* client, 
    EtsiClientType type, const char* fingerprint, int timeoutSec,
    byte* response, word32* responseSz)
{
    int   ret;
    int   requestSz = 0;
    byte* request;
    int   pos;

    if (client == NULL || response == NULL || responseSz == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    if (client->type != type) {
        /* Build HTTP ETSI request */
        if (type == ETSI_CLIENT_PUSH) {
            requestSz = (int)strlen(kEtsiPush);
            request = (byte*)kEtsiPush;
        }
        else {
            /* kEtsiGet1 / kEtsiGet2 */
            requestSz = (int)strlen(kEtsiGet1);
            request = (byte*)kEtsiPush;
        }

        /* send key request */
        pos = 0;
        while (pos < requestSz) {
            ret = wolfKeyMgr_TlsWrite(&client->tls, request + pos, requestSz - pos);
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

    /* get key response */
    ret = wolfKeyMgr_TlsRead(&client->tls, response, *responseSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "DoClientRead failed: %d\n", ret);
        return ret;
    }
    else if (ret == 0) {
        XLOG(WOLFKM_LOG_ERROR, "peer closed: %d\n", ret);
        return -1;
    }
        
    /* asymmetric key package response */
    *responseSz = ret;
    XLOG(WOLFKM_LOG_INFO, "Got ETSI response sz = %d\n", *responseSz);

    /* if not a push then close connection */
    if (type != ETSI_CLIENT_PUSH) {
        /* TODO: Add session resumption with tickets */
        client->type = ETSI_CLIENT_UNKNOWN;
        wolfKeyMgr_TlsClose(&client->tls, 1);
    }

    (void)fingerprint;

    return 0;
}

int wolfKeyMgr_EtsiLoadKey(ecc_key* key, byte* buffer, word32 length)
{
    int ret;
    word32 idx = 0;
    byte pubX[32*2+1], pubY[32*2+1];
    word32 pubXLen = sizeof(pubX), pubYLen = sizeof(pubY);

    if (key == NULL || buffer == NULL || length == 0) {
        return WOLFKM_BAD_ARGS;
    }

    /* Parsing key package */
    ret = wc_EccPrivateKeyDecode(buffer, &idx, key, length);
    if (ret == 0) {
        ret = wc_ecc_export_ex(key, pubX, &pubXLen, pubY, &pubYLen, 
            NULL, NULL, WC_TYPE_HEX_STR);
    }
    if (ret == 0) {
        XLOG(WOLFKM_LOG_INFO, "Pub X: %s\n", pubX);
        XLOG(WOLFKM_LOG_INFO, "Pub Y: %s\n", pubY);
    }
    else {
        XLOG(WOLFKM_LOG_INFO, "ECC Key Parse Failed %d\n", ret);
    }

    return ret;
}

void wolfKeyMgr_EtsiClientFree(EtsiClientCtx* client)
{
    if (client) {
        wolfKeyMgr_TlsClose(&client->tls, 0);
        free(client);
    }

    wolfSSL_Cleanup();
}

#endif /* WOLFKM_ETSI_SERVICE */
