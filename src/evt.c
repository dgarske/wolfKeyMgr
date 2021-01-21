/* evt.c
*
* Copyright (C) 2013 wolfSSL Inc.
*
* This file is part of cert service
*
* All rights reserved.
*
*/


#include <stdio.h>        /* system headers */
#include <stdlib.h>
#include <ctype.h>        /* isupper */
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "config.h"     /* our headers */
#include "evt.h"
#include "evt_log.h"
#include "evt_err.h"
#include "helpers.h"

#include <wolfssl/options.h>       /* wolfssl headers */
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/ssl.h>  /* wolfSSL_KeyPemToDer */

/* file locals */

static struct timeval readto;     /* our event timeout */
static int initCount = 0;         /* number of worker threads done setting up */
static pthread_mutex_t initLock;  /* for initCount */
static pthread_cond_t  initCond;  /* for initCount */

static eventThread* threads;         /* worker thread pool */
static int          threadPoolSize;  /* our reference here */

static connItem*       freeConnItems = NULL;    /* free connection item list */
static pthread_mutex_t itemLock;                /* for freeItems */

static __thread stats threadStats;    /* per thread stats, doesn't use lock */
static stats globalStats;             /* global (all threads) total stats */

static __thread int     maxSigns  = EVT_DEFAULT_MAX_SIGNS;  /* max b4 re-init */
static __thread int     signCount = 0;/* per thread signing count */
static __thread RNG     rng;          /* per thread rng */
static __thread ecc_key eccKey;       /* per thread ecc key */
static byte keyBuffer[ECC_BUFSIZE*4]; /* from file, private includes public */
static word32 keyBufferSz;            /* size */
static char subjectStr[ASN_NAME_MAX*2]; /* from file, for matching request */
static int  subjectStrLen;              /* length of above str for matching */

static WOLFSSL_CTX* sslCtx;             /* ssl context factory */
static int usingSSL = 1;                /* ssl is on by default */

/* a cert request connection */
enum {
    FOURK_BUFFER_SZ = 4096 - sizeof(int*)*3 - sizeof(int) - sizeof(double)
                        /* allow certConn to be <= 4k */
};

typedef struct certConn certConn;

/* cert connection */
struct certConn {
    struct bufferevent* stream;     /* buffered stream */
    WOLFSSL*            ssl;        /* ssl object */
    certConn*           next;       /* for free list */
    double              start;      /* response processing time start */
    unsigned int        requestSz;  /* bytes in request buffer */
    unsigned char       request[FOURK_BUFFER_SZ];   /* full input request */
};

static __thread certConn* freeCertConns = NULL;  /* per thread conn list */


/* verify request message */
typedef struct verifyReq {
    byte*  key;       /* key        pointer into request  */
    byte*  msg;       /* message    pointer into request */
    byte*  sig;       /* signature pointer into request */
    word16 keyLen;    /* length of key       in bytes */
    word16 msgLen;    /* length of message   in bytes */
    word16 sigLen;    /* length of signature in bytes */
} verifyReq;


#ifndef min
    int min(int a, int b)
    {
        return a < b ? a : b;
    }
#endif


/* turn on TCP NODELAY for socket */
static inline void TcpNoDelay(int fd)
{
    int flags = 1;

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*)&flags, sizeof(flags))
                   < 0)
        XLOG(EVT_LOG_INFO, "setsockopt TCP_NODELAY failed\n");
}


/* Our own sigignore */
int SigIgnore(int sig)
{
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;

    if (sigemptyset(&sa.sa_mask) == -1 || sigaction(sig, &sa, 0) == -1)
        return -1;

    return 0;
}


/* Our signal handler callback */
void SignalCb(evutil_socket_t fd, short event, void* arg)
{
    signalArg* sigArg = (signalArg*)arg;
    int        sigId = event_get_signal(sigArg->ev);
    int        i;
    char       c = 'c';   /* cancel */

    if (sigId == SIGINT)
        XLOG(EVT_LOG_INFO, "SIGINT handled.\n");
    else if (sigId == SIGTERM)
        XLOG(EVT_LOG_INFO, "SIGTERM handled.\n");
    else {
        XLOG(EVT_LOG_INFO, "Got unknown signal %d\n", sigId);
    }

    /* end main loop */
    XLOG(EVT_LOG_INFO, "Ending main thread loop\n");
    event_base_loopexit(sigArg->base, NULL);

    /* cancel each thread */
    XLOG(EVT_LOG_INFO, "Sending cancel to threads\n");
    for (i = 0; i < threadPoolSize; i++)
        if (write(threads[i].notifySend, &c, 1) != 1) {
            XLOG(EVT_LOG_ERROR, "Write to cancel thread notify failed\n");
            return;
        }

    /* join each thread */
    XLOG(EVT_LOG_INFO, "Joining threads\n");
    for (i = 0; i < threadPoolSize; i++) {
        int ret = pthread_join(threads[i].tid, NULL);

        XLOG(EVT_LOG_DEBUG, "Join ret = %d\n", ret);
    }

    /* free custom resources */
    wolfSSL_CTX_free(sslCtx);
}


/* return time in seconds with precision */
static double current_time(void)
{
    struct timeval tv;

    gettimeofday(&tv, 0);

    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}


/* Initialize all stats to zero, pre allocs may increment some counters */
static void InitStats(stats* myStats)
{
    /* don't use memset, lock already init */
    myStats->totalConnections   = 0;
    myStats->completedRequests  = 0;
    myStats->timeouts           = 0;
    myStats->currentConnections = 0;
    myStats->maxConcurrent      = 0;
    myStats->began              = 0;
    myStats->responseTime       = 0.0f;
}


/* Add to current per thread connection stats, handle max too */
static inline void IncrementCurrentConnections(void)
{
    threadStats.currentConnections++;
    if (threadStats.currentConnections > threadStats.maxConcurrent)
        threadStats.maxConcurrent = threadStats.currentConnections;
}


/* Add to total per thread connection stats */
static inline void IncrementTotalConnections(void)
{
    threadStats.totalConnections++;
    IncrementCurrentConnections();
}


/* Add to total per thread completed stats */
static inline void IncrementCompleted(certConn* conn)
{
    threadStats.completedRequests++;
    threadStats.responseTime += current_time() - conn->start;
}


/* Add to total per thread timeout stats */
static inline void IncrementTimeouts(void)
{
    threadStats.timeouts++;
}


/* Decrement current per thread connection stats */
static inline void DecrementCurrentConnections(void)
{
    threadStats.currentConnections--;
}


/* Show our statistics, log them */
void ShowStats(void)
{
    stats  local;
    double avgResponse = 0.0f;

    pthread_mutex_lock(&globalStats.lock);

        local = globalStats;

    pthread_mutex_unlock(&globalStats.lock);

    /* adjust max conncurrent since now per thread */
    if (local.maxConcurrent < threadPoolSize)
        local.maxConcurrent = local.maxConcurrent ? 1 : 0;
    else 
        local.maxConcurrent -= threadPoolSize - 1;

    if (local.responseTime > 0.0f && local.completedRequests > 0) {
        avgResponse = local.responseTime / local.completedRequests;
        avgResponse *= 1000;  /* convert to ms */
    }

    /* always show stats */
    XLOG(EVT_LOG_ERROR, "Current stats:\n"
             "total   connections  = %19llu\n"
             "completed            = %19llu\n"
             "timeouts             = %19u\n"
             "current connections  = %19u\n"
             "max     concurrent   = %19u\n"
             "uptime  in seconds   = %19lu\n"
             "average response(ms) = %19.3f\n",
             (unsigned long long)local.totalConnections,
             (unsigned long long)local.completedRequests,
             local.timeouts,
             local.currentConnections,
             local.maxConcurrent,
             time(NULL) - local.began,
             avgResponse);
}


/* our listener error call back to use our logging */
static void OurListenerError(struct evconnlistener* listener, void* ptr)
{
    int  err = EVUTIL_SOCKET_ERROR();

    (void)ptr;

    XLOG(EVT_LOG_ERROR, "Got an error %d (%s) on the listener. \n",
                                      err, evutil_socket_error_to_string(err));

    if (err == EMFILE || err == ENFILE || err == ENOMEM) {
        XLOG(EVT_LOG_WARN, "Backing off listener, no open files\n");
        usleep(EVT_BACKOFF_TIME);
    }
}


/* store listener error callback to use our logging */
void SetListenerErrorCb(struct evconnlistener* el)
{
    evconnlistener_set_error_cb(el, OurListenerError);
}


/* Initialize the connection queue */
static void ConnQueueInit(connQueue* cq)
{
    cq->head = NULL;
    cq->tail = NULL;
    pthread_mutex_init(&cq->lock, NULL);
}


/* put connection item back onto the free connection item list */
static void ConnItemFree(connItem* item)
{
    pthread_mutex_lock(&itemLock);

        item->next = freeConnItems;
        freeConnItems = item;

    pthread_mutex_unlock(&itemLock);
}


/* Get a new connection item */
static connItem* ConnItemNew(void)
{
    connItem* item;

    pthread_mutex_lock(&itemLock);

        if ( (item = freeConnItems) )
            freeConnItems = item->next;

    pthread_mutex_unlock(&itemLock);

    if (item == NULL) {
        /* free list empty, add more items to the free list pool */
        XLOG(EVT_LOG_INFO, "Setting up new conn item pool\n");
        item = (connItem*)malloc(sizeof(connItem) * EVT_CONN_ITEMS);
        if (item) {
            int i;

            /* the first one is the new item */
            for (i = 1; i < EVT_CONN_ITEMS; i++)
                item[i].next = &item[i+1];

            pthread_mutex_lock(&itemLock);

                item[EVT_CONN_ITEMS-1].next = freeConnItems;
                freeConnItems = &item[1];

            pthread_mutex_unlock(&itemLock);
        }
        else
            XLOG(EVT_LOG_ERROR, "ConnItemNew pool malloc error\n");
    }

    if (item) {
        item->next = NULL;
        item->fd   = -1;
    }

    return item;
}


/* push an item onto the connection queue */
static void ConnQueuePush(connQueue* cq, connItem* item)
{
    item->next = NULL;

    pthread_mutex_lock(&cq->lock);

        if (cq->tail == NULL)  /* empty ? */
            cq->head = item;
        else
            cq->tail->next = item;
        cq->tail = item;      /*  add to the end either way */

    pthread_mutex_unlock(&cq->lock);
}


/* pop an item off the connection queue */
static connItem* ConnQueuePop(connQueue* cq)
{
    connItem* item;

    pthread_mutex_lock(&cq->lock);

        if ( (item = cq->head) ) {
            cq->head = item->next;
            if (cq->head == NULL)   /* are we now empty */
                cq->tail = NULL;
        }

    pthread_mutex_unlock(&cq->lock);

    return item;
}


/* put cert connection item back onto the free item list, handle stats */
static void CertConnFree(certConn* conn)
{
    if (conn == NULL)
        return;

    XLOG(EVT_LOG_DEBUG, "Freeing Cert Connection\n");
    DecrementCurrentConnections();

    /* release per connection resources */
    if (conn->stream) {
        bufferevent_free(conn->stream);
        conn->stream = NULL;
    }

    if (conn->ssl) {
        wolfSSL_free(conn->ssl);
        conn->ssl = NULL;
    }

    /* push to fee list */
    conn->next    = freeCertConns;
    freeCertConns = conn;
}


/* get a new cert connection, handle stats */
static certConn* CertConnNew(void)
{
    certConn* conn;

    if ( (conn = freeCertConns) )
        freeCertConns = conn->next;

    if (conn == NULL) {
        /* free list empty, add more items to the free list pool */
        XLOG(EVT_LOG_INFO, "Setting up new cert conn pool\n");
        conn = (certConn*)malloc(sizeof(certConn) * EVT_CONN_ITEMS);
        if (conn) {
            int i;

            /* the first one is the new item */
            for (i = 1; i < EVT_CONN_ITEMS; i++)
                conn[i].next = &conn[i+1];

            conn[EVT_CONN_ITEMS-1].next = freeCertConns;
            freeCertConns = &conn[1];
        }
        else
            XLOG(EVT_LOG_ERROR, "CertConnNew pool malloc error\n");
    }

    if (conn) {
        /* per connection inits */
        conn->next      = NULL;
        conn->stream    = NULL;
        conn->ssl       = NULL;
        conn->start     = 0.0f;
        conn->requestSz = 0;
        IncrementTotalConnections();
    }

    return conn;
}


/* worker event has been canceled, clean up */
static void WorkerExit(void* arg)
{
    eventThread* me = (eventThread*)arg;

    event_del(me->notify);
    event_base_loopexit(me->threadBase, NULL);

#if defined(HAVE_HASHDRBG)
    wc_FreeRng(&rng);
#endif

    XLOG(EVT_LOG_INFO, "Worker thread exiting, tid = %ld\n",
                        (long)pthread_self());
    /* put per thread stats into global stats*/
    pthread_mutex_lock(&globalStats.lock);

        globalStats.totalConnections   += threadStats.totalConnections;
        globalStats.completedRequests  += threadStats.completedRequests;
        globalStats.timeouts           += threadStats.timeouts;
        globalStats.currentConnections += threadStats.currentConnections;
        globalStats.maxConcurrent      += threadStats.maxConcurrent;
        globalStats.responseTime       += threadStats.responseTime;

    pthread_mutex_unlock(&globalStats.lock);

    pthread_exit(NULL);
}


/* our close on write callback
Not needed now with persistent connection
static void CloseOnFinishedWriteCb(struct bufferevent* bev, void* ctx)
{
    certConn* conn = (certConn*)ctx;

    XLOG(EVT_LOG_DEBUG, "CloseOnFinishedWriteCb\n");
    if (conn == NULL)
        return;

    if (evbuffer_get_length(bufferevent_get_output(bev)) == 0)
        CertConnFree(conn);
}
*/


/* our event callback */
static void EventCb(struct bufferevent* bev, short what, void* ctx)
{
    XLOG(EVT_LOG_INFO, "EventCb what = %d\n", what);

    if (what & BEV_EVENT_TIMEOUT) {
        XLOG(EVT_LOG_INFO, "Got timeout on connection, closing\n");
        CertConnFree(ctx);
        IncrementTimeouts();
        return;
    }

    if (what & BEV_EVENT_EOF) {
        XLOG(EVT_LOG_INFO, "Peer ended connection, closing\n");
        CertConnFree(ctx);
        return;
    }

    if (what & BEV_EVENT_ERROR) {
        XLOG(EVT_LOG_INFO, "Generic connection error, closing\n");
        CertConnFree(ctx);
        return;
    }
}


/* parse in verify response, 0 on success */
static int ParseVerifyRequest(byte* request, int requestSz, verifyReq* vr)
{
    byte* requestMax = request + requestSz;

    /* make sure we can read in key legnth */
    if (request + WORD16_LEN > requestMax) {
        XLOG(EVT_LOG_ERROR, "Bad VerifyRequest size for keyLen\n"); 
        return EVT_BAD_VERIFY_SIZE;
    }
    ato16(request, &vr->keyLen);
    request += WORD16_LEN;

    /* make sure we can read in key */
    if (request + vr->keyLen > requestMax) {
        XLOG(EVT_LOG_ERROR, "Bad VerifyRequest size for key\n"); 
        return EVT_BAD_VERIFY_SIZE; 
    }
    vr->key  = request;
    request += vr->keyLen;

    /* make sure we can read in msg legnth */
    if (request + WORD16_LEN > requestMax) {
        XLOG(EVT_LOG_ERROR, "Bad VerifyRequest size for msgLen\n"); 
        return EVT_BAD_VERIFY_SIZE; 
    }
    ato16(request, &vr->msgLen);
    request += WORD16_LEN;

    /* make sure we can read in msg */
    if (request + vr->msgLen > requestMax) {
        XLOG(EVT_LOG_ERROR, "Bad VerifyRequest size for msg\n"); 
        return EVT_BAD_VERIFY_SIZE; 
    }
    vr->msg  = request;
    request += vr->msgLen;

    /* make sure we can read in sig legnth */
    if (request + WORD16_LEN > requestMax) {
        XLOG(EVT_LOG_ERROR, "Bad VerifyRequest size for sigLen\n"); 
        return EVT_BAD_VERIFY_SIZE;
    }
    ato16(request, &vr->sigLen);
    request += WORD16_LEN;

    /* make sure we can read in msg */
    if (request + vr->sigLen > requestMax) {
        XLOG(EVT_LOG_ERROR, "Bad VerifyRequest size for sig\n"); 
        return EVT_BAD_VERIFY_SIZE;
    }
    vr->sig  = request;
    request += vr->sigLen;

    (void)request;  /* silence scan-build, leave request += for changes */

    return 0;
}


/* create our verify response (place into request buffer), 0 on success */
static int GenerateVerify(certConn* conn)
{
    int    ret;
    Sha256 sha256;
    int    stat   = 0;
    word32 outlen = 1;
    byte   hash[SHA256_DIGEST_SIZE];
    verifyReq vr;
    ecc_key verifyKey;

    /* we put response into request buffer since we already have it */
    byte* request   = conn->request;
    byte* hdrSz     = request + CERT_HEADER_SZ_OFFSET;
    int   requestSz = conn->requestSz - CERT_HEADER_SZ;

    /* make header */
    request[CERT_HEADER_VERSION_OFFSET] = CERT_VERSION;
    request[CERT_HEADER_TYPE_OFFSET]    = VERIFY_RESPONSE;
    request += CERT_HEADER_SZ;

    /* get input */
    ret = ParseVerifyRequest(request, requestSz, &vr);
    if (ret < 0) {
        XLOG(EVT_LOG_ERROR, "Bad ParseVerifyRequest: %d\n", ret); 
        return ret;
    }

    /* import key */
    wc_ecc_init(&verifyKey);
    ret = wc_ecc_import_x963(vr.key, vr.keyLen, &verifyKey);
    if (ret < 0) {
        XLOG(EVT_LOG_ERROR, "Bad ParseVerifyRequest import key: %d\n", ret); 
        return ret;
    }

    /* make hash */
    wc_InitSha256(&sha256);
    wc_Sha256Update(&sha256, vr.msg, vr.msgLen);
    wc_Sha256Final(&sha256, hash);

    /* do verify */
    ret = wc_ecc_verify_hash(vr.sig, vr.sigLen, hash, sizeof(hash), &stat,
                             &verifyKey);
    wc_ecc_free(&verifyKey);
    if (ret < 0) {
        XLOG(EVT_LOG_ERROR, "Bad ParseVerifyRequest verify hash: %d\n", ret); 
        return ret;
    }

    /* store answer */
    *request = stat ? 0x1 : 0x0;

    /* out size */
    c16toa((unsigned short)outlen, hdrSz);  /* size in header */
    conn->requestSz = outlen + CERT_HEADER_SZ;

    return 0;
}


/* increment signing counter, re-init rng if over max signs, 0 on success */
static int IncrementSignCounter(void)
{
    int ret = 0;

    signCount++;
    if (signCount > maxSigns) {
        XLOG(EVT_LOG_INFO, "Sign cout over threshold, rng re-init: %d\n",
                                                                    signCount);
#if defined(HAVE_HASHDRBG)
        wc_FreeRng(&rng);
#endif
        ret = wc_InitRng(&rng);
        if (ret < 0) {
            XLOG(EVT_LOG_ERROR, "RNG re-init failed: %d\n", ret);
            return ret;
        }
        signCount = 0;  /* re-init success, counter back to zero */
    }

    return ret;
}


/* create our signing response (place into request buffer), 0 on success */
static int GenerateSign(certConn* conn)
{
    int    ret;
    word32 outlen = sizeof(conn->request);
    Sha256 sha256;
    byte   hash[SHA256_DIGEST_SIZE];

    /* we put response into request buffer since we already have it */
    byte* request   = conn->request;
    byte* hdrSz     = request + CERT_HEADER_SZ_OFFSET;
    int   requestSz = conn->requestSz - CERT_HEADER_SZ;

    /* make header */
    request[CERT_HEADER_VERSION_OFFSET] = CERT_VERSION;
    request[CERT_HEADER_TYPE_OFFSET]    = SIGN_RESPONSE;
    request += CERT_HEADER_SZ;

    /* make hash */
    wc_InitSha256(&sha256);
    wc_Sha256Update(&sha256, request, requestSz);
    wc_Sha256Final(&sha256, hash);

    /* actual sign */
    ret = IncrementSignCounter();
    if (ret < 0) {
        XLOG(EVT_LOG_ERROR, "Increment Sign Counter failed: %d\n", ret);
        return ret;
    }
    ret = wc_ecc_sign_hash(hash, sizeof(hash), request, &outlen, &rng, &eccKey);
    if (ret < 0) {
        XLOG(EVT_LOG_ERROR, "Sign failed: %d\n", ret);
        return ret;
    }
    c16toa((unsigned short)outlen, hdrSz);  /* size in header */
    conn->requestSz = outlen + CERT_HEADER_SZ;

    return 0;
}


/* create our cert response (place into request buffer), 0 on success */
static int GenerateCert(certConn* conn)
{
    int ret;

    /* we put response into request buffer since we already have it */
    byte* request   = conn->request;
    byte* hdrSz     = request + CERT_HEADER_SZ_OFFSET;
    int   requestSz = conn->requestSz - CERT_HEADER_SZ;

    /* make header */
    request[CERT_HEADER_VERSION_OFFSET] = CERT_VERSION;
    request[CERT_HEADER_TYPE_OFFSET]    = CERT_RESPONSE;
    request += CERT_HEADER_SZ;

    /* actual sign */
    ret = IncrementSignCounter();
    if (ret < 0) {
        XLOG(EVT_LOG_ERROR, "Increment Sign Counter failed: %d\n", ret);
        return ret;
    }
    ret = wc_SignCert(requestSz, CTC_SHA256wECDSA, request,
                      sizeof(conn->request), NULL, &eccKey, &rng);
    if (ret < 0) {
        XLOG(EVT_LOG_ERROR, "SignCert failed: %d\n", ret);
        return ret;
    } else {
        /* let's do sanity check on request issuer vs our subject */
        int  issuerStrLen;
        char issuerStr[sizeof(subjectStr)];
        WOLFSSL_X509_NAME* issuer;
        WOLFSSL_X509* x509 = wolfSSL_X509_d2i(NULL, request, ret);
        if (x509 == NULL) {
            XLOG(EVT_LOG_ERROR, "X509 d2i failed\n");
            return EVT_BAD_X509_D2I;
        }

        issuer = wolfSSL_X509_get_issuer_name(x509);
        if (issuer == NULL) {
            XLOG(EVT_LOG_ERROR, "X509 get issuer failed\n");
            wolfSSL_X509_free(x509);
            return EVT_BAD_X509_GET_NAME;
        }

        issuerStr[0] = '\0';
        issuerStr[sizeof(issuerStr)-1] = '\0';
        if (wolfSSL_X509_NAME_oneline(issuer, issuerStr, sizeof(issuerStr)-1) ==
                                                                  NULL) {
            XLOG(EVT_LOG_ERROR, "X509 get name oneline failed\n");
            wolfSSL_X509_free(x509);
            return EVT_BAD_X509_ONELINE;
        }

        issuerStrLen = strlen(issuerStr);
        if (issuerStrLen <= 0 || subjectStrLen <= 0) {
            XLOG(EVT_LOG_ERROR, "X509 str lens bad\n");
            wolfSSL_X509_free(x509);
            return EVT_BAD_X509_MATCH;
        }
        if (memcmp(issuerStr, subjectStr, min(issuerStrLen, subjectStrLen))
                                                                        != 0) {
            XLOG(EVT_LOG_ERROR, "X509 memcmp match failed on request\n");
            wolfSSL_X509_free(x509);
            return EVT_BAD_X509_MATCH;
        }

        XLOG(EVT_LOG_INFO, "X509 issuer subject match\n");
        wolfSSL_X509_free(x509);
        /* issuer doesn't need to be freed, points into x509 */
    }


    c16toa((unsigned short)ret, hdrSz);  /* size in header */
    conn->requestSz = ret + CERT_HEADER_SZ;

    return 0;
}


/* create our error response (place into request buffer), 0 on success */
static int GenerateError(certConn* conn, int err)
{
    int   totalSz = WORD16_LEN * 2;  /* error code + string length */
    int   strLen;
    char  tmp[WOLFSSL_MAX_ERROR_SZ];
    char* errStr = tmp;
    short int serr = (short int)err;

    /* we put response into request buffer since we already have it */
    byte* request   = conn->request;
    byte* hdrSz     = request + CERT_HEADER_SZ_OFFSET;

    /* make header */
    request[CERT_HEADER_VERSION_OFFSET] = CERT_VERSION;
    request[CERT_HEADER_TYPE_OFFSET]    = ERROR_RESPONSE;
    request += CERT_HEADER_SZ;

    c16toa((unsigned short)serr, request);  /* error code */
    request += WORD16_LEN;

    tmp[0]                     = '\0';
    tmp[WOLFSSL_MAX_ERROR_SZ-1] = '\0';

    if (err < EVT_ERROR_BEGIN)   /* EVT_ERROR uses lower errors than CyaSSL */
        errStr = (char*)GetEvtError(err); 
    else
        wolfSSL_ERR_error_string(err, errStr);

    strLen = strlen(errStr);                    /* str length */
    c16toa((unsigned short)strLen, request); 
    request += WORD16_LEN;

    memcpy(request, errStr, strLen);            /* error string */
    totalSz += strLen;

    c16toa((unsigned short)totalSz, hdrSz);     /* size in header */
    conn->requestSz = totalSz + CERT_HEADER_SZ;

    return 0;
}


static const char* GetRequestStr(int type)
{
    switch (type) {
        case CERT_REQUEST:
            return "CERT Type";

        case SIGN_REQUEST:
            return "SIGN Type";

        case VERIFY_REQUEST:
            return "VERIFY Type";

        default:
            return "Unknown type";
    }
}


/* verify input request, 0 on success, 1 on need more input, <0 error */
static int VerifyHeader(certConn* conn, int* type)
{
    unsigned short size = 0;

    if (conn == NULL || type == NULL) {
        XLOG(EVT_LOG_ERROR, "Bad VerifyHeader pointers\n"); 
        return EVT_BAD_ARGS;
    }

    /* need full header to verify, ok, just continue */
    if (conn->requestSz < CERT_HEADER_SZ) {
        XLOG(EVT_LOG_INFO, "Not enough input to process request header\n"); 
        return 1;
    }

    /* version */
    if (conn->request[CERT_HEADER_VERSION_OFFSET] != CERT_VERSION) {
        XLOG(EVT_LOG_ERROR, "Bad version on request header\n"); 
        return EVT_BAD_VERSION;
    }

    /* type */
    *type = conn->request[CERT_HEADER_TYPE_OFFSET];
    XLOG(EVT_LOG_INFO, "Request type = %s\n", GetRequestStr(*type));
    if (*type != CERT_REQUEST && *type != SIGN_REQUEST &&
                                 *type != VERIFY_REQUEST) {
        XLOG(EVT_LOG_ERROR, "Not a valid REQUEST header\n"); 
        return EVT_BAD_REQUEST_TYPE;
    }

    /* size */
    ato16(&conn->request[CERT_HEADER_SZ_OFFSET], &size);
    XLOG(EVT_LOG_DEBUG, "Request header size = %d, read = %d\n", size,
                         conn->requestSz); 
    if (size > (conn->requestSz - CERT_HEADER_SZ)) {
        XLOG(EVT_LOG_INFO, "Not enough input to process full request\n"); 
        return 1;
    } else if (size < (conn->requestSz - CERT_HEADER_SZ)) {
        XLOG(EVT_LOG_ERROR, "Request data bigger than request header size\n");
        return EVT_BAD_HEADER_SZ;
    }

    return 0;
}


/* Response message handler by type, 0 on success */
static int DoResponse(certConn* conn, int type)
{
    conn->start = current_time();  /* response start time */

    switch (type) {
        case CERT_REQUEST:
            return GenerateCert(conn);

        case SIGN_REQUEST:
            return GenerateSign(conn);

        case VERIFY_REQUEST:
            return GenerateVerify(conn);

        default:
            XLOG(EVT_LOG_ERROR, "Bad DoResponse Type: %d\n", type);
            return EVT_BAD_REQUEST_TYPE;
    }
}


/* return sent bytes or < 0 on error */
static int DoSend(certConn* conn)
{
    int ret = -1;

    if (usingSSL == 0) {
        ret = evbuffer_add( bufferevent_get_output(conn->stream),
                            conn->request, conn->requestSz);
    } else if (conn->ssl) {
        ret = wolfSSL_write(conn->ssl,
                            conn->request, conn->requestSz);
        if (ret < 0) {
            int err = wolfSSL_get_error(conn->ssl, 0);
            XLOG(EVT_LOG_ERROR, "wolfSSL_write err = %s",
                                 wolfSSL_ERR_reason_error_string(err));
        }
    } else {
       XLOG(EVT_LOG_ERROR, "DoSend() usingSSL but no SSL object");
       ret = -1;
    }

    return ret;
}


/* our request handler */
static void DoRequest(certConn* conn)
{
    int ret;
    int type = -1;

    if (conn == NULL || conn->stream == NULL) {
        XLOG(EVT_LOG_ERROR, "Bad DoRequest pointers\n");
        return;
    }

    XLOG(EVT_LOG_INFO, "Got Request\n");

    /* verify input, let error fall down to send error */
    ret = VerifyHeader(conn, &type);
    if (ret < 0) {
        XLOG(EVT_LOG_ERROR, "Verify request failed: %d\n", ret);
    }
    else if (ret == 1) {
        XLOG(EVT_LOG_INFO, "Verify request needs more input\n");
        return;
    }

    /* Make response, if ok */
    if (ret == 0) {
        ret = DoResponse(conn, type);
        if (ret < 0)
            XLOG(EVT_LOG_ERROR, "DoResponse failed: %d\n", ret);
    }

    /* if not ok let's send error response */
    if (ret < 0) {
        ret = GenerateError(conn, ret);
        if (ret < 0) {
            XLOG(EVT_LOG_ERROR, "GenerateError failed: %d, closing\n", ret);
            CertConnFree(conn);
            return;
        }
        XLOG(EVT_LOG_INFO, "Generated Error response: %d\n", ret);
    }
    else {
        IncrementCompleted(conn);  /* success on request */
    }

    ret = DoSend(conn);
    /* send it, response is now in request buffer */
    if (ret < 0) {
        XLOG(EVT_LOG_ERROR, "DoSend failed: %d\n", ret);
        CertConnFree(conn);
        return;
    }
    XLOG(EVT_LOG_INFO, "Sent Response\n");

    /* reset request size for next request */
    conn->requestSz = 0;
}


/* return number of bytes read, 0 on wouldblock, < 0 on error */
static int DoRead(struct bufferevent* bev, certConn* conn)
{
    int ret = 0;

    if (usingSSL == 0) {
        ret = evbuffer_remove(bufferevent_get_input(bev),
                              conn->request + conn->requestSz,
                              sizeof(conn->request) - conn->requestSz);
    } else if (conn->ssl) {
        ret = wolfSSL_read(conn->ssl,
                              conn->request + conn->requestSz,
                              sizeof(conn->request) - conn->requestSz);
        if (ret < 0) {
            int err = wolfSSL_get_error(conn->ssl, 0);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                ret = 0;     /* translate to 0 wouldblock */
            else if (err > 0)
                ret = -err;  /* keep negative */
            else
                ret = err;

            if (ret != 0)
                XLOG(EVT_LOG_ERROR, "wolfSSL_read err = %s",
                                    wolfSSL_ERR_reason_error_string(err));
        }
    } else {
       XLOG(EVT_LOG_ERROR, "DoRead() usingSSL but no SSL object");
       ret = -1;
    }

    return ret;
}


/* our read callback */
static void ReadCb(struct bufferevent* bev, void* ctx)
{
    certConn* conn = (certConn*)ctx;
    int       ret;

    if (bev == NULL || conn == NULL) {
        XLOG(EVT_LOG_ERROR, "Bad ReadCb pointers\n");
        return;
    }

    ret = DoRead(bev, conn);

    if (ret == 0) {
        /* EWOULDBLOCK, ok */
        return;
    }
    else if (ret > 0) {
        conn->requestSz += ret;
        return DoRequest(conn);
    }
    else {
        /* ret < 0, we have an actual error */
        XLOG(EVT_LOG_ERROR, "DoRead error %d\n", ret);
        CertConnFree(conn);
    }
}


/* Process an incoming connection item, called when input is placed on event
   wakeup pipe */
static void ThreadEventProcess(int fd, short which, void* arg)
{
    char         buffer[1];
    eventThread* me = (eventThread*)arg;
    connItem*    item;

    if (read(fd, buffer, 1) != 1)
        XLOG(EVT_LOG_ERROR, "thread notify receive read error\n");
    else if (buffer[0] == 'c') {   /* on exit get sent 'c' for cancel,  */
        WorkerExit(me);            /* usually 'w' for wakeup */
        return;
    }

    item = ConnQueuePop(me->connections);
    if (item) {
        /* Do new connection here from item->fd */
        int clientFd = item->fd;
        certConn* conn = CertConnNew();

        ConnItemFree(item);  /* no longer need item, give it back */

        if (conn == NULL) {
            XLOG(EVT_LOG_ERROR, "CertConnNew() failed\n");
            close(clientFd);
            return;
        }
        conn->stream = bufferevent_socket_new(me->threadBase, clientFd,
                                 BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
        if (conn->stream == NULL) {
            XLOG(EVT_LOG_ERROR, "bufferevent_socket_new() failed\n");
            CertConnFree(conn);
            close(clientFd);  /* normally CertConnFree would close fd by stream
                                 but since stream is NULL, force it */
            return;
        } else if (usingSSL) {
            conn->ssl = wolfSSL_new(sslCtx);
            if (conn->ssl == NULL) {
                XLOG(EVT_LOG_ERROR, "wolfSSL_New() failed\n");
                CertConnFree(conn);
                return;
            }
            wolfSSL_SetIOReadCtx( conn->ssl, conn->stream);
            wolfSSL_SetIOWriteCtx(conn->ssl, conn->stream);
        }

        bufferevent_setcb(conn->stream, ReadCb, NULL, EventCb, conn);
        bufferevent_set_timeouts(conn->stream, &readto, NULL);
        bufferevent_enable(conn->stream, EV_READ|EV_WRITE);
    }
}


/* set our timeout on connections */
void SetTimeout(struct timeval to)
{
    readto = to;
}


/* Individual thread setup */
static void SetupThread(eventThread* me)
{
    /* thread base */
    me->threadBase = event_base_new();
    if (me->threadBase == NULL) {
        XLOG(EVT_LOG_ERROR, "Can't allocate thread's event base\n");
        exit(EXIT_FAILURE);
    }

    /* notify event pipe */
    me->notify = event_new(me->threadBase, me->notifyRecv,
                           EV_READ | EV_PERSIST, ThreadEventProcess, me);
    if (event_add(me->notify, NULL) == -1) {
        XLOG(EVT_LOG_ERROR, "Can't add event for monitor pipe\n");
        exit(EXIT_FAILURE);
    }

    /* create connection queue */
    me->connections = malloc(sizeof(connQueue));
    if (me->connections == NULL) {
        XLOG(EVT_LOG_ERROR, "Can't allocate thread's Connection Queue\n");
        exit(EXIT_FAILURE);
    }
    ConnQueueInit(me->connections);
}


/* Signal Thread setup done and running */
static void SignalSetup(void)
{
    /* signal ready */
    pthread_mutex_lock(&initLock);
        initCount++;
        pthread_cond_signal(&initCond);
    pthread_mutex_unlock(&initLock);
}


/* worker event to signal done with thread setup, starts loop */
static void* WorkerEvent(void* arg)
{
    int    ret;
    word32 idx = 0;
    eventThread* me = (eventThread*)arg;

    /* zero out per thread stats, after creating pool */
    certConn* conn = CertConnNew();
    CertConnFree(conn);
    InitStats(&threadStats);

    /* do per thread rng, key init */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        XLOG(EVT_LOG_ERROR, "RNG Init failed %d\n", ret);
        exit(EXIT_FAILURE);
    }

    wc_ecc_init(&eccKey);
    ret = wc_EccPrivateKeyDecode(keyBuffer, &idx, &eccKey, keyBufferSz);
    if (ret != 0) {
        XLOG(EVT_LOG_ERROR, "EccPrivateKeyDecode failed %d\n", ret);
        exit(EXIT_FAILURE);
    }

    /* tell creator we're ready */
    me->tid = pthread_self();
    SignalSetup();

    /* start thread's loop */
    event_base_loop(me->threadBase, 0);

    return NULL;
}


/* Make a new Worker thread */
static void MakeWorker(void* (*f)(void*), void* arg)
{
    pthread_t      thread;
    pthread_attr_t attr;

    pthread_attr_init(&attr);

    if (pthread_create(&thread, &attr, f, arg) != 0) {
        XLOG(EVT_LOG_ERROR, "Can't make work worker\n");
        exit(EXIT_FAILURE);
    }
}


/* wolfSSL I/O Receive CallBack */
static int wolfsslRecvCb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int ret;
    struct bufferevent* bev = (struct bufferevent*)ctx;

    (void)ssl;

    if (bev == NULL) {
        XLOG(EVT_LOG_ERROR, "wolfSSL ReceiveCb NULL ctx\n");
        return -1;
    }

    ret = evbuffer_remove(bufferevent_get_input(bev), buf, sz);
    if (ret == 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;  /* ok, wouldblock */
    }
    else if (ret < 0)
        XLOG(EVT_LOG_ERROR, "wolfssl ReceiveCb error\n");

    return ret;
}


/* wolfSSL I/O Send CallBack */
static int wolfsslSendCb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int ret;
    struct bufferevent* bev = (struct bufferevent*)ctx;

    (void)ssl;

    if (bev == NULL) {
        XLOG(EVT_LOG_ERROR, "wolfSSL SendCb NULL ctx\n");
        return -1;
    }

    ret = evbuffer_add(bufferevent_get_output(bev), buf, sz);
    if (ret == 0) {
        return sz;
    }
    else if (ret < 0)
        XLOG(EVT_LOG_ERROR, "wolfssl SendCb error\n");

    return ret;
}


/* setup ssl context */
static void InitSSL(const char* certName)
{
    sslCtx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    if (sslCtx == NULL) {
        XLOG(EVT_LOG_ERROR, "Can't alloc TLS 1.2 context\n");
        exit(EXIT_FAILURE);
    }
    wolfSSL_SetIORecv(sslCtx, wolfsslRecvCb);
    wolfSSL_SetIOSend(sslCtx, wolfsslSendCb);

    if (wolfSSL_CTX_use_certificate_file(sslCtx, certName, SSL_FILETYPE_PEM)
                                        != SSL_SUCCESS) {
        XLOG(EVT_LOG_ERROR, "Can't load TLS cert into context\n");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_CTX_use_PrivateKey_buffer(sslCtx, keyBuffer, keyBufferSz,
                                          SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        XLOG(EVT_LOG_ERROR, "Can't load TLS key into context\n");
        exit(EXIT_FAILURE);
    }
}


/* Initialize all worker threads */
void InitThreads(int numThreads, const char* certName)
{
    int i;
    connItem*  item;

    /* pthread inits */
    pthread_mutex_init(&initLock, NULL);
    pthread_cond_init(&initCond, NULL);
    pthread_mutex_init(&itemLock, NULL);
    pthread_mutex_init(&globalStats.lock, NULL);

    /* get thread memory */
    threads = calloc(numThreads, sizeof(eventThread));
    if (threads == NULL) {
        XLOG(EVT_LOG_ERROR, "Can't allocate thread pool\n");
        exit(EXIT_FAILURE);
    }

    /* pre allocate pool memory */
    item = ConnItemNew();
    ConnItemFree(item);
    InitStats(&globalStats);   /* items above for pre alloc shouldn't count */

    /* when we began */
    globalStats.began = time(NULL);

    /* save copies */
    threadPoolSize = numThreads;

    /* setup each thread */
    for (i = 0; i < numThreads; i++) {
        int fds[2];
        if (pipe(fds)) {
            XLOG(EVT_LOG_ERROR, "Can't make notify pipe\n");
            exit(EXIT_FAILURE);
        }

        threads[i].notifyRecv = fds[0];
        threads[i].notifySend = fds[1];
        SetupThread(&threads[i]);
    }

    /* start threads */
    for (i = 0; i < numThreads; i++)
        MakeWorker(WorkerEvent, &threads[i]);  /* event monitor */

    /* wait until each is ready */
    pthread_mutex_lock(&initLock);
        while (initCount < numThreads)
            pthread_cond_wait(&initCond, &initLock);
    pthread_mutex_unlock(&initLock);

    /* setup ssl ctx */
#ifdef DISABLE_SSL
    usingSSL = 0;    /* build time only disable for now */
#endif
    if (usingSSL)
        InitSSL(certName);
}


/* dispatcher thread accept callback */
void AcceptCB(struct evconnlistener* listener, evutil_socket_t fd,
              struct sockaddr* a, int slen, void* p)
{
    static int lastThread = -1;       /* last used thread ID */

    int  currentId = (lastThread + 1) % threadPoolSize;    /* round robin */
    char w = 'w';    /* send wakeup flag */

    eventThread* thread = threads + currentId;
    connItem*    item = ConnItemNew();

    if (item == NULL) {
        XLOG(EVT_LOG_ERROR, "Unable to process accept request, low memory\n");
        close(fd);
        return;
    }

    lastThread = currentId;

    item->fd = fd;
    assert(slen <= sizeof(item->peerAddr));
    memcpy(item->peerAddr, a, slen);

    TcpNoDelay(fd);

    /* push connection item and notify thread */
    ConnQueuePush(thread->connections, item);

    if (write(thread->notifySend, &w, 1) != 1)
        XLOG(EVT_LOG_ERROR, "Write to thread notify send pipe failed\n");

    XLOG(EVT_LOG_INFO, "Accepted a connection, sent to thread %d\n", currentId);
}


/* make sure rlimt files is at least what user wants */
void SetMaxFiles(int max)
{
    struct rlimit now;

    if (getrlimit(RLIMIT_NOFILE, &now) == 0) {
        if (now.rlim_cur < max)
            now.rlim_cur = max;
        if (now.rlim_max < now.rlim_cur)
            now.rlim_max = now.rlim_cur;

        if (setrlimit(RLIMIT_NOFILE, &now) != 0) {
            XLOG(EVT_LOG_ERROR, "Can't setrlimit max files\n");
            exit(EX_OSERR);
        }
    } else {
        XLOG(EVT_LOG_ERROR, "Can't getrlimit max files\n");
        exit(EX_OSERR);
    }
}


/* make core max file */
void SetCore(void)
{
    struct rlimit old, change;

    if (getrlimit(RLIMIT_CORE, &old) == 0) {
        /* infinity first */
        change.rlim_cur = change.rlim_max = RLIM_INFINITY;
        if (setrlimit(RLIMIT_CORE, &change) != 0) {
            /* ok, just try old max */
            change.rlim_cur = change.rlim_max = old.rlim_max;
            if (setrlimit(RLIMIT_CORE, &change) != 0) {
                XLOG(EVT_LOG_ERROR, "Can't setrlimit core\n");
                exit(EX_OSERR);
            }
        }
    } else {
        XLOG(EVT_LOG_ERROR, "Can't getrlimit core\n");
        exit(EX_OSERR);
    }
}


/* see Advanced Programming in the Unix Environment, chapter 13 */
int MakeDaemon(int chDir)
{
    int fd;

    switch (fork()) {
        case -1:
            return -1;
        case 0:                   /* child */
            break;
        default:
            exit(EXIT_SUCCESS);   /* parent goes bye-bye */
    }

    if (setsid() == -1) {         /* become session leader */
        XLOG(EVT_LOG_ERROR, "setsid\n");
        return -1;
    }

    if (chDir) {
        if (chdir("/") != 0) {    /* change working directory */
            XLOG(EVT_LOG_ERROR, "chdir\n");
            return -1;
        }
    }

    umask(0);                     /* always successful */

    fd = open("/dev/null", O_RDWR, 0);
    if (fd == -1) {
        XLOG(EVT_LOG_ERROR, "open /dev/null\n");
        return -1;
    }

    if (dup2(fd, STDIN_FILENO) < 0 || dup2(fd, STDOUT_FILENO) < 0 ||
                                      dup2(fd, STDERR_FILENO) < 0) {
        XLOG(EVT_LOG_ERROR, "dup2 std filenos\n");
        return -1;
    }

    if (close(fd) < 0) {
        XLOG(EVT_LOG_ERROR, "close\n");
        return -1;
    }

    return 0;
}


/* load our cert file subject (that's always us) into our buffer */
void SetCertFile(const char* fileName)
{
    WOLFSSL_X509_NAME* subject = NULL;
    WOLFSSL_X509*      x509     = wolfSSL_X509_load_certificate_file(fileName,
                                                              SSL_FILETYPE_PEM);
    if (x509 == NULL) {
        XLOG(EVT_LOG_ERROR, "load X509 cert file %s failed\n", fileName);
        exit(EXIT_FAILURE);
    }
    XLOG(EVT_LOG_INFO, "loaded X509 cert file %s\n", fileName);

    subject = wolfSSL_X509_get_subject_name(x509);
    if (subject == NULL) {
        XLOG(EVT_LOG_ERROR, "get subject name failed\n");
        wolfSSL_X509_free(x509);
        exit(EXIT_FAILURE);
    }

    subjectStr[0] = '\0';
    subjectStr[sizeof(subjectStr)-1] = '\0';
    if (wolfSSL_X509_NAME_oneline(subject, subjectStr, sizeof(subjectStr)-1)
                                                                      == NULL) {
        XLOG(EVT_LOG_ERROR, "get subject name oneline failed\n");
        wolfSSL_X509_free(x509);
        exit(EXIT_FAILURE);
    }
    subjectStrLen = strlen(subjectStr);
    XLOG(EVT_LOG_INFO, "X509 subject %s\n", subjectStr);

    wolfSSL_X509_free(x509);
    /* subject doesn't need to be freed, points into x509 */
}

int GetAddrInfoString(struct evutil_addrinfo* addr, char* buf, size_t bufSz)
{
    int ret = -1;
    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

    if (buf) {
        memset(buf, 0, bufSz);
    }
    if (addr) {
        ret = getnameinfo(
            (struct sockaddr*)addr->ai_addr, 
            (socklen_t)addr->ai_addrlen, 
            hbuf, sizeof(hbuf), 
            sbuf, sizeof(sbuf),
            (NI_NUMERICHOST | NI_NUMERICSERV));
        if (ret == 0) {
            snprintf(buf, bufSz, "%s:%s", hbuf, sbuf);
        }
    }

    return ret;
}

/* password getter for encrypted pem private key, caller should call
 * ClearPassword to wipe and free */
static char* GetPassword(void)
{
    char* passwd = (char*)malloc(MAX_PASSWORD_SZ);
    if (passwd == NULL) {
        XLOG(EVT_LOG_ERROR, "Memory failure for password\n");
        exit(EXIT_FAILURE);
    }

    memset(passwd, 0, MAX_PASSWORD_SZ);
    strncpy(passwd, EVT_DEFAULT_KEY_PASSWORD, MAX_PASSWORD_SZ);
    passwd[MAX_PASSWORD_SZ-1] = '\0';

    return passwd;
}


/* Wipe and Free password */
static int ClearPassword(char* passwd)
{
    volatile char* p   = (volatile char*)passwd;
    size_t         len = strlen(passwd);

    while (len--)
        *p++ = '\0';

    free(passwd);

    return 0;
}


/* load the key file name into our buffer  */
void SetKeyFile(const char* fileName)
{
    FILE*  tmpFile;
    size_t bytesRead;
    int    ret;
    char*  passwd;

    if (CheckCtcSettings() != 1) {
        XLOG(EVT_LOG_ERROR, "CyaSSL math library mismatch in settings\n");
        exit(EXIT_FAILURE);
    }

#ifdef USE_FAST_MATH
    if (CheckFastMathSettings() != 1) {
        XLOG(EVT_LOG_ERROR, "CyaSSL fast math library mismatch\n");
        exit(EXIT_FAILURE);
    }
#endif

    if (fileName == NULL) {
        XLOG(EVT_LOG_ERROR, "Key file name is null\n");
        exit(EXIT_FAILURE);
    }

    tmpFile = fopen(fileName, "rb");
    if (tmpFile == NULL) {
        XLOG(EVT_LOG_ERROR, "Key file %s can't be opened for reading\n",
                            fileName);
        exit(EXIT_FAILURE);
    }

    bytesRead = fread(keyBuffer, 1, sizeof(keyBuffer), tmpFile);
    fclose(tmpFile);

    if (bytesRead == 0) {
        XLOG(EVT_LOG_ERROR, "Key file %s can't be read\n", fileName);
        exit(EXIT_FAILURE);
    }

    passwd = GetPassword();
    ret = wolfSSL_KeyPemToDer(keyBuffer, bytesRead, keyBuffer,
                           sizeof(keyBuffer), passwd);
    ClearPassword(passwd);
    if (ret <= 0) {
        XLOG(EVT_LOG_ERROR, "Can't convert Key file from PEM to DER: %d\n",ret);
        exit(EXIT_FAILURE);
    }
    keyBufferSz = ret;

    XLOG(EVT_LOG_INFO, "loaded key file %s\n", fileName);
}


/* Check for already running process using exclusive lock on pidfile.
 * Returns NULL if process is already running, otherwise writes pid to
 * pidfile and returns FILE pointer to pidfile with an exclusive lock.
 */
FILE* GetPidFile(const char* pidFile, pid_t pid)
{
    FILE* f;
    int   fd;

    if (!pidFile) {
        XLOG(EVT_LOG_ERROR, "Missing pidfile path\n");
        return NULL; /* Fail */
    }

    /* Open pidfile for writing.  If already exists, do not truncate,
     * but otherwise create it. */
    if ((f = fopen(pidFile, "r+")) == NULL) {
        if (errno != ENOENT) {
            XLOG(EVT_LOG_ERROR, "fopen %s\n", strerror(errno));
            return NULL; /* Fail */
        }
        if ((f = fopen(pidFile, "w")) == NULL) {
            XLOG(EVT_LOG_ERROR, "fopen %s\n", strerror(errno));
            return NULL; /* Fail */
        }
    }

    fd = fileno(f);
    if (fd == -1) {
        XLOG(EVT_LOG_ERROR, "fileno %s\n", strerror(errno));
        return NULL; /* Fail */
    }

    if (lockf(fd, F_TLOCK, 0) == -1) {
        XLOG(EVT_LOG_ERROR, "lockf %s\n", strerror(errno));
        return NULL; /* Fail */
    }

    /* Truncate pidfile */
    if (ftruncate(fd, 0) == -1) {
        XLOG(EVT_LOG_ERROR, "ftruncate %s\n", strerror(errno));
        return NULL; /* Fail */
    }

    /* Write pid */
    fprintf(f, "%ld\n", (long)pid);
    if (fflush(f) == EOF) {
        XLOG(EVT_LOG_ERROR, "fflush %s\n", strerror(errno));
        return NULL;
    }

    return f;
}
