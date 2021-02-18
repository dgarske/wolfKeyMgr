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
#include "mod_etsi.h"

#define WOLFKM_ETST_CLIENT_DEF_TIMEOUT_SEC 10

static pthread_t*  tids;          /* our threads */
static int         poolSize = 0;  /* number of threads */
static word16      port;          /* peer port */
static const char* host =  WOLFKM_DEFAULT_HOST;  /* peer host */
static int         timeoutSec = WOLFKM_ETST_CLIENT_DEF_TIMEOUT_SEC;

#ifndef EX_USAGE
#define EX_USAGE 2
#endif

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif

/* Certificate for ETSI server or signer CA */
#define WOLFKM_ETSISVC_CERT    "./certs/test-cert.pem"

/* for error response in errorMode, 0 on success */
static int DoErrorMode(void)
{
    /* TODO: Add error case */

    return 0;
}

/* ETSI Asymmetric Key Request */
static int DoKeyRequest(EtsiClientCtx* client, int useGet, char* saveResp)
{
    int     ret;
    EtsiClientType type;
    byte    response[ETSI_MAX_RESPONSE_SZ];
    word32  responseSz;
    ecc_key key;

    if (useGet) {
        type = ETSI_CLIENT_GET;
    }
    else {
        type = ETSI_CLIENT_PUSH;
    }

    /* for push run until error */
    do {
        responseSz = sizeof(response);
        ret = wolfKeyMgr_EtsiClientGet(client, type, NULL, 60, response, &responseSz);
        if (ret == 0) {
            ret = wc_ecc_init(&key);
            if (ret == 0) {
                ret = wolfKeyMgr_EtsiLoadKey(&key, response, responseSz);
                wc_ecc_free(&key);
            }
            if (ret != 0) {
                XLOG(WOLFKM_LOG_INFO, "ECC Key Parse Failed %d\n", ret);
            }
            if (saveResp) {
                ret = wolfKeyMgr_SaveFile(saveResp, response, responseSz);
            }
        }
    } while (!useGet && ret == 0);

    return ret;
}

typedef struct WorkThreadInfo {
    int requests;
    int useGet;
    char* saveResp;
} WorkThreadInfo;

/* Do requests per thread, persistent connection */
static void* DoRequests(void* arg)
{
    int i;
    int ret = -1;
    WorkThreadInfo* info = (WorkThreadInfo*)arg;
    EtsiClientCtx* client = wolfKeyMgr_EtsiClientNew();
    if (client == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Error loading ETSI server CA %d!\n", ret);
    }

    ret = wolfKeyMgr_EtsiClientConnect(client, host, port, timeoutSec);
    if (ret == 0) {
        for (i = 0; i < info->requests; i++) {
            ret = DoKeyRequest(client, info->useGet, info->saveResp);
            if (ret != 0) {
                XLOG(WOLFKM_LOG_ERROR, "DoKeyRequest failed: %d\n", ret);
                break;
            }
        }
    }

    wolfKeyMgr_EtsiClientFree(client);

    return NULL;
}



/* usage help */
static void Usage(void)
{
    printf("%s %s\n", "client", PACKAGE_VERSION);
    printf("-?          Help, print this usage\n");
    printf("-e          Error mode, force error response\n");
    printf("-h <str>    Host to connect to, default %s\n", WOLFKM_DEFAULT_HOST);
    printf("-p <num>    Port to connect to, default %s\n", WOLFKM_DEFAULT_ETSISVC_PORT);
    printf("-t <num>    Thread pool size (stress test), default  %d\n", 0);
    printf("-l <num>    Log Level, default %d\n", WOLFKM_DEFAULT_LOG_LEVEL);
    printf("-r <num>    Requests per thread, default %d\n",
                                                          WOLFKM_DEFAULT_REQUESTS);
    printf("-f <file>   <file> to store ETSI response\n");
    printf("-g          Use HTTP GET (default is Push with HTTP PUT)\n");
    printf("-s <sec>    Timeout seconds (default %d)\n", WOLFKM_ETST_CLIENT_DEF_TIMEOUT_SEC);

}


int main(int argc, char** argv)
{
    int         ch, i;
    int         ret;
    char*       saveResp  = NULL;        /* save response */
    int         requests = WOLFKM_DEFAULT_REQUESTS;
    int         errorMode = 0;
    int         useGet = 0;
    enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;
    WorkThreadInfo info;

    port       = atoi(WOLFKM_DEFAULT_ETSISVC_PORT);

#ifdef DISABLE_SSL
    usingTLS = 0;    /* can only disable at build time */
#endif

    /* argument processing */
    while ((ch = getopt(argc, argv, "?eh:p:t:l:r:f:gs:")) != -1) {
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
            case 'g':
                useGet = 1;
                break;
            case 's' :
                timeoutSec = atoi(optarg);
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

    if (poolSize == 0) {
        EtsiClientCtx* client = wolfKeyMgr_EtsiClientNew();
        if (client == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "Error creating ETSI client!\n");
            exit(EXIT_FAILURE);
        }
        ret = wolfKeyMgr_EtsiClientAddCA(client, WOLFKM_ETSISVC_CERT);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "Error loading ETSI server CA %d!\n", ret);
        }
        ret = wolfKeyMgr_EtsiClientConnect(client, host, port, timeoutSec);
        if (ret != 0) {
            wolfKeyMgr_EtsiClientFree(client);
            XLOG(WOLFKM_LOG_ERROR, "Failure connecting to ETSI service\n");
            exit(EXIT_FAILURE);
        }

        /* Do an ETSI request */
        ret = DoKeyRequest(client, useGet, saveResp);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "DoKeyRequest failed: %d\n", ret);
            exit(EXIT_FAILURE);
        }
        XLOG(WOLFKM_LOG_INFO, "First ETSI test worked!\n");

        wolfKeyMgr_EtsiClientFree(client);
    }
    else {
        /* stress testing with a thread pool */

        /* thread id holder */
        tids = calloc(poolSize, sizeof(pthread_t));
        if (tids == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "calloc tids failed");
            exit(EXIT_FAILURE);
        }

        /* setup worker thread info */
        info.requests = requests;
        info.useGet = useGet;
        info.saveResp = saveResp;

        /* create workers */
        for (i = 0; i < poolSize; i++) {
            if (pthread_create(&tids[i], NULL, DoRequests, &info) != 0){
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

    return 0;
}
