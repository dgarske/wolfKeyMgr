/* mod_tls.c
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


/* wolfSSL I/O Receive CallBack */
static int wkmTlsReadCb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int ret;
    struct wkmTlsCtx* client = (struct wkmTlsCtx*)ctx;

    (void)ssl;

    if (client == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "wkmTls RecvCb NULL ctx\n");
        return -1;
    }

    ret = wolfKeyMgr_SocketRead(client->sockfd, (byte*)buf, sz);
    if (ret < 0) {
        int err = wolfKeyMgr_SocketLastError(ret);
        XLOG(WOLFKM_LOG_ERROR, "wkmTls RecvCb error %d (errno %d)\n", ret, err);

        if (err == SOCKET_EWOULDBLOCK || err == SOCKET_EAGAIN) {
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
        else if (err == SOCKET_ECONNRESET) {
            return WOLFSSL_CBIO_ERR_CONN_RST;
        }
        else if (err == SOCKET_EINTR) {
            return WOLFSSL_CBIO_ERR_ISR;
        }
        else if (err == SOCKET_EPIPE) {
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        else {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    return ret;
}

/* return bytes read or < 0 on error */
int wolfKeyMgr_TlsRead(wkmTlsCtx* client, byte* p, int len)
{
    int ret;

    if (client->noTLS) {
        ret = wolfKeyMgr_SocketRead(client->sockfd, p, len);
    }
    else {
        ret = wolfSSL_read(client->ssl, p, len);
        if (ret < 0) {
            int err = wolfSSL_get_error(client->ssl, 0);
            XLOG(WOLFKM_LOG_ERROR, "DoClientRead error %d: %s\n",
                                 err, wolfSSL_ERR_reason_error_string(err));
            if (err < 0)
                ret = err;
        }
    }

    return ret;
}

/* wolfSSL I/O Send CallBack */
static int wkmTlsWriteCb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int ret;
    struct wkmTlsCtx* client = (struct wkmTlsCtx*)ctx;

    (void)ssl;

    if (client == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "wkmTls SendCb NULL ctx\n");
        return -1;
    }

    ret = wolfKeyMgr_SocketWrite(client->sockfd, (byte*)buf, sz);
    if (ret < 0) {
        int err = wolfKeyMgr_SocketLastError(ret);
        XLOG(WOLFKM_LOG_ERROR, "wkmTls SendCb error %d (errno %d)\n", ret, err);

        if (err == SOCKET_EWOULDBLOCK || err == SOCKET_EAGAIN) {
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }
        else if (err == SOCKET_ECONNRESET) {
            return WOLFSSL_CBIO_ERR_CONN_RST;
        }
        else if (err == SOCKET_EINTR) {
            return WOLFSSL_CBIO_ERR_ISR;
        }
        else if (err == SOCKET_EPIPE) {
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        else {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    if (ret > sz) {
        printf("trap error %d %d\n", ret, sz);
    }
    return ret;
}

/* return sent bytes or < 0 on error */
int wolfKeyMgr_TlsWrite(wkmTlsCtx* client, byte* p, int len)
{
    int ret = -1;

    if (client->noTLS) {
        ret = wolfKeyMgr_SocketWrite(client->sockfd, p, len);
    }
    else {
        ret = wolfSSL_write(client->ssl, p, len);
        if (ret < 0) {
            int err = wolfSSL_get_error(client->ssl, 0);
            XLOG(WOLFKM_LOG_ERROR, "DoClientSend error %d: %s\n",
                                 err, wolfSSL_ERR_reason_error_string(err));
            if (err < 0)
                ret = err;
        }
    }

    return ret;
}

/* setup TLS context */
int wolfKeyMgr_TlsClientInit(wkmTlsCtx* client, 
    const char* ca, const char* key, const char* cert)
{
    int ret;

    client->sslCtx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (client->sslCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Can't alloc TLS 1.3 context");
        return WOLFKM_BAD_MEMORY;
    }

    ret = wolfSSL_CTX_load_verify_locations(client->sslCtx, ca, NULL);
    if (ret != WOLFSSL_SUCCESS) {
        XLOG(WOLFKM_LOG_ERROR, "Can't load TLS CA etsi into context. Error: %s (%d)\n", 
            wolfSSL_ERR_reason_error_string(ret), ret);
        wolfSSL_CTX_free(client->sslCtx); client->sslCtx = NULL;
        return ret;
    }

    wolfSSL_SetIORecv(client->sslCtx, wkmTlsReadCb);
    wolfSSL_SetIOSend(client->sslCtx, wkmTlsWriteCb);

    /* TODO: Add mutual authentication */
    (void)key;
    (void)cert;

    client->sockfd = WKM_SOCKET_INVALID;
#ifdef DISABLE_SSL
    client->noTLS = 1;    /* build time only disable for now */
#endif
    return 0;
}

int wolfKeyMgr_TlsConnect(wkmTlsCtx* client, const char* host, word16 port)
{
    int ret;
    if (client == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    ret = wolfKeyMgr_SockConnect(&client->sockfd, host, port);
    if (ret == 0) {
        if (client->noTLS)
            return 0;

        client->ssl = wolfSSL_new(client->sslCtx);
        if (client->ssl == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "wolfSSL_new memory failure");
            return WOLFKM_BAD_MEMORY;
        }

        wolfSSL_SetIOReadCtx( client->ssl, client);
        wolfSSL_SetIOWriteCtx(client->ssl, client);
    }
    return ret;
}

void wolfKeyMgr_TlsClose(wkmTlsCtx* client, int sendShutdown)
{
    if (client) {
        if (client->ssl && sendShutdown) {
            wolfSSL_shutdown(client->ssl);
        }
        if (client->sockfd != WKM_SOCKET_INVALID) {
            wolfKeyMgr_SocketClose(client->sockfd);
            client->sockfd = WKM_SOCKET_INVALID;
        }
        if (client->ssl) {
            wolfSSL_free(client->ssl);
            client->ssl = NULL;
        }
        if (client->sslCtx) {
            wolfSSL_CTX_free(client->sslCtx);
            client->sslCtx = NULL;
        }
    }
}
