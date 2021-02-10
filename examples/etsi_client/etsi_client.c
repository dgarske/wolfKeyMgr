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

#include "etsi_client.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/ssl.h>
#include <wolfssl/test.h>

#include "src/keymanager.h"
#include "src/svc_etsi.h"

static pthread_t*  tids;          /* our threads */
static int         poolSize = 0;  /* number of threads */
static word16      port;          /* peer port */
static const char* host =  WOLFKM_DEFAULT_HOST;  /* peer host */

static WOLFSSL_CTX* sslCtx;       /* ssl context factory */
static int usingTLS = 1;          /* ssl is on by default */

static const char* kEtsiGet1 = "GET /.well-known/enterprise-transport-security/keys?fingerprints=%s HTTP/1.1\r\nAccept: application/pkcs8\r\n";
//static const char* kEtsiGet2 = "GET /.well-known/enterprise-transport-security/keys?groups=%s&certs=%s HTTP/1.1\r\nAccept: application/pkcs8\r\n";
static const char* kEtsiPush = "PUT /enterprise-transport-security/keys HTTP/1.1\r\nAccept: application/pkcs8\r\n";


/* return sent bytes or < 0 on error */
static int DoClientSend(int sockfd, WOLFSSL* ssl, const byte* p, int len)
{
    int ret = -1;

    if (usingTLS == 0) {
        ret = send(sockfd, p, len, 0);
    } else {
        ret = wolfSSL_write(ssl, p, len);
        if (ret < 0) {
            int err = wolfSSL_get_error(ssl, 0);
            XLOG(WOLFKM_LOG_ERROR, "DoClientSend err = %s\n",
                                 wolfSSL_ERR_reason_error_string(err));
            if (err < 0) ret = err;
        }
    }

    return ret;
}


/* return bytes read or < 0 on error */
static int DoClientRead(int sockfd, WOLFSSL* ssl, byte* p, int len)
{
    int ret;

    if (usingTLS == 0) {
        ret = recv(sockfd, p, len, 0);
    } else {
        ret = wolfSSL_read(ssl, p, len);
        if (ret < 0) {
            int err = wolfSSL_get_error(ssl, 0);
            XLOG(WOLFKM_LOG_ERROR, "DoClientRead err = %s\n",
                                 wolfSSL_ERR_reason_error_string(err));
            if (err < 0) ret = err;
        }
    }

    return ret;
}


/* create new ssl object */
static WOLFSSL* NewSSL(int sockfd)
{
    WOLFSSL* ssl;

    if (usingTLS == 0) return NULL;

    ssl = wolfSSL_new(sslCtx);
    if (ssl == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "wolfSSL_new memory failure");
        exit(EXIT_FAILURE);
    }
    wolfSSL_set_fd(ssl, sockfd);

    return ssl;
}


/* for error response in errorMode, 0 on success */
static int DoErrorMode(void)
{
    /* TODO: Add error case */

    return 0;
}

/* ETSI Asymmetric Key Request */
static int DoKeyRequest(SOCKET_T sockfd, WOLFSSL* ssl, int usePush, char* saveResp)
{
    int     ret;
    int     requestSz = 0;
    byte    tmp[4096]; /* buffer large enough for private keys */
    byte*   request = tmp;  /* use to build header in front */
    int     sent = 0;

    /* Build HTTP ETSI request */
    if (usePush) {
        requestSz = (int)strlen(kEtsiPush);
        memcpy(request, kEtsiPush, requestSz);
    }
    else {
        /* kEtsiGet1 / kEtsiGet2 */
        requestSz = (int)strlen(kEtsiGet1);
        memcpy(request, kEtsiGet1, requestSz);
    }

    while (sent < requestSz) {
        ret = DoClientSend(sockfd, ssl, tmp + sent, requestSz - sent);
        if (ret < 0) {
            XLOG(WOLFKM_LOG_INFO, "DoClientSend failed: %d\n", ret);
            return ret;
        }
        sent += ret;
        if (sent == requestSz)
            break;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent %s request\n", usePush ? "push" : "single");

    /* for push run until error */
    do {
        ret = DoClientRead(sockfd, ssl, tmp, sizeof(tmp));
        if (ret < 0) {
            XLOG(WOLFKM_LOG_ERROR, "DoClientRead failed: %d\n", ret);
            return ret;
        }
        else if (ret == 0) {
            XLOG(WOLFKM_LOG_ERROR, "peer closed: %d\n", ret);
            return -1;
        }
        
        /* Process asymmetric key package response */
        XLOG(WOLFKM_LOG_INFO, "Got ETSI response sz = %d\n", ret);

        /* TODO: Show parsing key package */

        if (saveResp) {
            FILE* raw = fopen(saveResp, "wb");
            if (raw == NULL) {
                XLOG(WOLFKM_LOG_INFO, "Error saving response to %s\n", saveResp);
                return -1;
            }
            requestSz = (int)fwrite(tmp, 1, ret, raw);
            fclose(raw);
            if (ret != requestSz) {
                XLOG(WOLFKM_LOG_ERROR, "fwrite failed\n");
                return -1;
            }
        }
    } while (usePush && ret > 0);

    return 0;
}


/* Do requests per thread, persistent connection */
static void* DoRequests(void* arg)
{
    int i;
    int ret = -1;
    int requests = *(int*)arg;
    WOLFSSL* ssl = NULL;

    SOCKET_T sockfd;
    tcp_connect(&sockfd, host, port, 0, 0, NULL);
    ssl = NewSSL(sockfd);

    for (i = 0; i < requests; i++) {
        ret = DoKeyRequest(sockfd, ssl, 0, NULL);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "DoKeyRequest failed: %d\n", ret);
            exit(EXIT_FAILURE);
        }
    }

    CloseSocket(sockfd);
    wolfSSL_free(ssl);

    return NULL;
}


/* setup SSL */
static int InitClientTLS(void)
{
    int ret;
    sslCtx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (sslCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Can't alloc TLS 1.3 context");
        return WOLFKM_BAD_MEMORY;
    }

    ret = wolfSSL_CTX_load_verify_locations(sslCtx, WOLFKM_ETSISVC_CERT, NULL);
    if (ret != WOLFSSL_SUCCESS) {
        XLOG(WOLFKM_LOG_ERROR, "Can't load TLS CA etsi into context. Error: %s (%d)\n", 
            wolfSSL_ERR_reason_error_string(ret), ret);
        wolfSSL_CTX_free(sslCtx); sslCtx = NULL;
        return ret;
    }
    return 0;
}


/* usage help */
static void Usage(void)
{
    printf("%s %s\n", "client", PACKAGE_VERSION);
    printf("-?          Help, print this usage\n");
    printf("-e          Error mode, force error response\n");
    printf("-h <str>    Host to connect to, default %s\n", WOLFKM_DEFAULT_HOST);
    printf("-p <num>    Port to connect to, default %s\n", WOLFKM_ETSISVC_PORT);
    printf("-t <num>    Thread pool size (stress test), default  %d\n", 0);
    printf("-l <num>    Log Level, default %d\n", WOLFKM_DEFAULT_LOG_LEVEL);
    printf("-r <num>    Requests per thread, default %d\n",
                                                          WOLFKM_DEFAULT_REQUESTS);
    printf("-f <file>   <file> to store ETSI response\n");
    printf("-u          Use Push (HTTP PUT)");
}


int main(int argc, char** argv)
{
    int         ch, i;
    int         ret;
    char*       saveResp  = NULL;        /* save response */
    int         requests = WOLFKM_DEFAULT_REQUESTS;
    int         errorMode = 0;
    int         usePush = 0;
    SOCKET_T    sockfd;
    WOLFSSL*    ssl = NULL;
    enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;

    port       = atoi(WOLFKM_ETSISVC_PORT);

#ifdef DISABLE_SSL
    usingTLS = 0;    /* can only disable at build time */
#endif

    /* argument processing */
    while ((ch = getopt(argc, argv, "?eh:p:t:l:r:f:u")) != -1) {
        switch (ch) {
            case '?' :
                Usage();
                exit(EX_USAGE);
            case 'h' :
                host = optarg;
                break;
            case 'f' :
                saveResp = optarg;
                break;
            case 'p' :
                port = atoi(optarg);
                break;
            case 't' :
                poolSize = atoi(optarg);
                break;
            case 'r' :
                requests = atoi(optarg);
                break;
            case 'e' :
                errorMode = 1;
                break;
            case 'l' :
                logLevel = atoi(optarg);
                if (logLevel < WOLFKM_LOG_DEBUG || logLevel > WOLFKM_LOG_ERROR) {
                    perror("loglevel [1:4] only");
                    exit(EX_USAGE);
                }
                break;
            case 'u':
                usePush = 1;
                break;

            default:
                Usage();
                exit(EX_USAGE);
        }
    }

    /* log setup */
    wolfKeyMgr_SetLogFile(NULL, 0, logLevel);
    XLOG(WOLFKM_LOG_INFO, "Starting client\n");

    if (errorMode)
        return DoErrorMode();

    if (usingTLS) {
        ret = InitClientTLS();
        if (ret != 0) {
            exit(EXIT_FAILURE);
        }
    }

    tcp_connect(&sockfd, host, port, 0, 0, NULL);
    ssl = NewSSL(sockfd);
    XLOG(WOLFKM_LOG_INFO, "Connected to etsi service\n");

    /* Do a etsi test and save the pem */
    ret = DoKeyRequest(sockfd, ssl, usePush, saveResp);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "DoKeyRequest failed: %d\n", ret);
        exit(EXIT_FAILURE);
    }
    XLOG(WOLFKM_LOG_INFO, "First ETSI test worked!\n");

    CloseSocket(sockfd);
    wolfSSL_free(ssl);

    /* are we stress testing with a thread pool ? */
    if (poolSize) {
        /* thread id holder */
        tids = calloc(poolSize, sizeof(pthread_t));
        if (tids == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "calloc tids failed");
            exit(EXIT_FAILURE);
        }

        /* create workers */
        for (i = 0; i < poolSize; i++) {
            if (pthread_create(&tids[i], NULL, DoRequests, &requests) != 0){
                XLOG(WOLFKM_LOG_ERROR, "pthread_create failed");
                exit(EXIT_FAILURE);
            }
        }

        /* wait until they're all done */
        for (i = 0; i < poolSize; i++) {
            ret = pthread_join(tids[i], NULL);
            XLOG(WOLFKM_LOG_INFO, "pthread_join ret = %d\n", ret);
        }

        free(tids);
    }

    wolfSSL_CTX_free(sslCtx);

    return 0;
}
