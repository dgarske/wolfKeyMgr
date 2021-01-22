/* sock_mgr.c
*
* Copyright (C) 2021 wolfSSL Inc.
*
* This file is part of wolf key manager
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
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "keymanager.h"

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

static WOLFSSL_CTX* sslCtx;             /* ssl context factory */
static int usingTLS = 1;                /* ssl is on by default */

static __thread svcConn* freeSvcConns = NULL;  /* per thread conn list */


/* listener list */
typedef struct listener listener;
struct listener {
    struct evconnlistener* ev_listen;   /* event listener */
    listener* next;                     /* next on list */
};

static listener* listenerList = NULL;  /* main list of listeners */



/* turn on TCP NODELAY for socket */
static inline void TcpNoDelay(int fd)
{
    int flags = 1;

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*)&flags, sizeof(flags))
                   < 0)
        XLOG(WOLFKM_LOG_INFO, "setsockopt TCP_NODELAY failed\n");
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
        XLOG(WOLFKM_LOG_INFO, "SIGINT handled.\n");
    else if (sigId == SIGTERM)
        XLOG(WOLFKM_LOG_INFO, "SIGTERM handled.\n");
    else {
        XLOG(WOLFKM_LOG_INFO, "Got unknown signal %d\n", sigId);
    }

    /* end main loop */
    XLOG(WOLFKM_LOG_INFO, "Ending main thread loop\n");
    event_base_loopexit(sigArg->base, NULL);

    /* cancel each thread */
    XLOG(WOLFKM_LOG_INFO, "Sending cancel to threads\n");
    for (i = 0; i < threadPoolSize; i++)
        if (write(threads[i].notifySend, &c, 1) != 1) {
            XLOG(WOLFKM_LOG_ERROR, "Write to cancel thread notify failed\n");
            return;
        }

    /* join each thread */
    XLOG(WOLFKM_LOG_INFO, "Joining threads\n");
    for (i = 0; i < threadPoolSize; i++) {
        int ret = pthread_join(threads[i].tid, NULL);

        XLOG(WOLFKM_LOG_DEBUG, "Join ret = %d\n", ret);
    }

    /* free custom resources */
    wolfSSL_CTX_free(sslCtx);
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
static inline void IncrementCompleted(svcConn* conn)
{
    threadStats.completedRequests++;
    threadStats.responseTime += wolfKeyMgr_GetCurrentTime() - conn->start;
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
    XLOG(WOLFKM_LOG_ERROR, "Current stats:\n"
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

    XLOG(WOLFKM_LOG_ERROR, "Got an error %d (%s) on the listener. \n",
                                      err, evutil_socket_error_to_string(err));

    if (err == EMFILE || err == ENFILE || err == ENOMEM) {
        XLOG(WOLFKM_LOG_WARN, "Backing off listener, no open files\n");
        usleep(WOLFKM_BACKOFF_TIME);
    }
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
static connItem* ConnItemNew(svcInfo* svc)
{
    connItem* item;

    pthread_mutex_lock(&itemLock);

        if ( (item = freeConnItems) )
            freeConnItems = item->next;

    pthread_mutex_unlock(&itemLock);

    if (item == NULL) {
        /* free list empty, add more items to the free list pool */
        XLOG(WOLFKM_LOG_INFO, "Setting up new %s conn item pool\n", svc->desc);
        item = (connItem*)malloc(sizeof(connItem) * WOLFKM_CONN_ITEMS);
        if (item) {
            int i;

            /* the first one is the new item */
            for (i = 1; i < WOLFKM_CONN_ITEMS; i++)
                item[i].next = &item[i+1];

            pthread_mutex_lock(&itemLock);

                item[WOLFKM_CONN_ITEMS-1].next = freeConnItems;
                freeConnItems = &item[1];

            pthread_mutex_unlock(&itemLock);
        }
        else
            XLOG(WOLFKM_LOG_ERROR, "ConnItemNew pool malloc error\n");
    }

    if (item) {
        item->next = NULL;
        item->fd   = -1;
        item->svc  = svc;
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
static void ServiceConnFree(svcConn* conn)
{
    if (conn == NULL)
        return;

    XLOG(WOLFKM_LOG_DEBUG, "Freeing Service Connection\n");
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
    conn->next    = freeSvcConns;
    freeSvcConns = conn;
}


/* get a new cert connection, handle stats */
static svcConn* ServiceConnNew(eventThread* me)
{
    svcInfo* svc = me->svc;
    svcConn* conn;

    if ( (conn = freeSvcConns) )
        freeSvcConns = conn->next;

    if (conn == NULL) {
        /* free list empty, add more items to the free list pool */
        XLOG(WOLFKM_LOG_INFO, "Setting up new %s service conn pool\n", svc->desc);
        conn = (svcConn*)malloc(sizeof(svcConn) * WOLFKM_CONN_ITEMS);
        if (conn) {
            int i;

            /* the first one is the new item */
            for (i = 1; i < WOLFKM_CONN_ITEMS; i++)
                conn[i].next = &conn[i+1];

            conn[WOLFKM_CONN_ITEMS-1].next = freeSvcConns;
            freeSvcConns = &conn[1];
        }
        else
            XLOG(WOLFKM_LOG_ERROR, "ServiceConnNew pool malloc error\n");
    }

    if (conn) {
        /* per connection inits */
        conn->next      = NULL;
        conn->stream    = NULL;
        conn->ssl       = NULL;
        conn->start     = 0.0f;
        conn->requestSz = 0;
        conn->svc       = svc;
        conn->svcCtx    = me->svcCtx;
        IncrementTotalConnections();
    }

    return conn;
}


/* worker event has been canceled, clean up */
static void WorkerExit(void* arg)
{
    eventThread* me = (eventThread*)arg;

    if (me->svc && me->svc->freeCb) {
        me->svc->freeCb(me->svc, me);
    }

    event_del(me->notify);
    event_base_loopexit(me->threadBase, NULL);

    XLOG(WOLFKM_LOG_INFO, "Worker thread exiting, tid = %ld\n",
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


/* our event callback */
static void EventCb(struct bufferevent* bev, short what, void* ctx)
{
    XLOG(WOLFKM_LOG_INFO, "EventCb what = %d\n", what);

    if (what & BEV_EVENT_TIMEOUT) {
        XLOG(WOLFKM_LOG_INFO, "Got timeout on connection, closing\n");
        ServiceConnFree(ctx);
        IncrementTimeouts();
        return;
    }

    if (what & BEV_EVENT_EOF) {
        XLOG(WOLFKM_LOG_INFO, "Peer ended connection, closing\n");
        ServiceConnFree(ctx);
        return;
    }

    if (what & BEV_EVENT_ERROR) {
        XLOG(WOLFKM_LOG_INFO, "Generic connection error, closing\n");
        ServiceConnFree(ctx);
        return;
    }
}



/* return sent bytes or < 0 on error */
int DoSend(svcConn* conn)
{
    int ret = -1;

    if (usingTLS == 0) {
        ret = evbuffer_add( bufferevent_get_output(conn->stream),
                            conn->request, conn->requestSz);
    } else if (conn->ssl) {
        ret = wolfSSL_write(conn->ssl,
                            conn->request, conn->requestSz);
        if (ret < 0) {
            int err = wolfSSL_get_error(conn->ssl, 0);
            XLOG(WOLFKM_LOG_ERROR, "wolfSSL_write err = %s",
                                 wolfSSL_ERR_reason_error_string(err));
        }
    } else {
       XLOG(WOLFKM_LOG_ERROR, "DoSend() usingTLS but no SSL object");
       ret = -1;
    }

    return ret;
}



/* return number of bytes read, 0 on wouldblock, < 0 on error */
static int DoRead(struct bufferevent* bev, svcConn* conn)
{
    int ret = 0;

    if (usingTLS == 0) {
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
                XLOG(WOLFKM_LOG_ERROR, "wolfSSL_read err = %s",
                                    wolfSSL_ERR_reason_error_string(err));
        }
    } else {
       XLOG(WOLFKM_LOG_ERROR, "DoRead() usingTLS but no SSL object");
       ret = -1;
    }

    return ret;
}


/* our read callback */
static void ReadCb(struct bufferevent* bev, void* ctx)
{
    svcConn* conn = (svcConn*)ctx;
    int       ret;

    if (bev == NULL || conn == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ReadCb pointers\n");
        return;
    }

    ret = DoRead(bev, conn);

    if (ret == 0) {
        /* EWOULDBLOCK, ok */
        return;
    }
    else if (ret > 0) {
        conn->requestSz += ret;

        /* handle request with callback */
        if (conn->svc && conn->svc->requestCb) {
            ret = conn->svc->requestCb(conn);
            if (ret < 0) {
                /* error */
                ServiceConnFree(conn);
                conn = NULL;
            }
            else {
                /* success on request */
                IncrementCompleted(conn);
            }
        }
        if (conn) {
            /* reset request size for next request */
            conn->requestSz = 0;
        }
    }
    else {
        /* ret < 0, we have an actual error */
        XLOG(WOLFKM_LOG_ERROR, "DoRead error %d\n", ret);
        ServiceConnFree(conn);
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
        XLOG(WOLFKM_LOG_ERROR, "thread notify receive read error\n");
    else if (buffer[0] == 'c') {   /* on exit get sent 'c' for cancel,  */
        WorkerExit(me);            /* usually 'w' for wakeup */
        return;
    }

    item = ConnQueuePop(me->connections);
    if (item) {
        /* Do new connection here from item->fd */
        int clientFd = item->fd;
        svcConn* conn = ServiceConnNew(me);

        ConnItemFree(item);  /* no longer need item, give it back */

        if (conn == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "ServiceConnNew() failed\n");
            close(clientFd);
            return;
        }
        conn->stream = bufferevent_socket_new(me->threadBase, clientFd,
                                 BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
        if (conn->stream == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "bufferevent_socket_new() failed\n");
            ServiceConnFree(conn);
            close(clientFd);  /* normally ServiceConnFree would close fd by stream
                                 but since stream is NULL, force it */
            return;
        } else if (usingTLS) {
            conn->ssl = wolfSSL_new(sslCtx);
            if (conn->ssl == NULL) {
                XLOG(WOLFKM_LOG_ERROR, "wolfSSL_New() failed\n");
                ServiceConnFree(conn);
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
static void SetupThread(svcInfo* svc, eventThread* me)
{
    /* thread base */
    me->threadBase = event_base_new();
    if (me->threadBase == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Can't allocate thread's event base\n");
        exit(EXIT_FAILURE);
    }

    /* notify event pipe */
    me->notify = event_new(me->threadBase, me->notifyRecv,
                           EV_READ | EV_PERSIST, ThreadEventProcess, me);
    if (event_add(me->notify, NULL) == -1) {
        XLOG(WOLFKM_LOG_ERROR, "Can't add event for monitor pipe\n");
        exit(EXIT_FAILURE);
    }

    /* create connection queue */
    me->connections = malloc(sizeof(connQueue));
    if (me->connections == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Can't allocate thread's Connection Queue\n");
        exit(EXIT_FAILURE);
    }
    ConnQueueInit(me->connections);

    /* issue callback to service to init */
    me->svc = svc;
    if (svc->initCb) {
        svc->initCb(svc, me);
    }
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
    eventThread* me = (eventThread*)arg;

    /* zero out per thread stats, after creating pool */
    svcConn* conn = ServiceConnNew(me);
    ServiceConnFree(conn);
    InitStats(&threadStats);

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
        XLOG(WOLFKM_LOG_ERROR, "Can't make work worker\n");
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
        XLOG(WOLFKM_LOG_ERROR, "wolfSSL ReceiveCb NULL ctx\n");
        return -1;
    }

    ret = evbuffer_remove(bufferevent_get_input(bev), buf, sz);
    if (ret == 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;  /* ok, wouldblock */
    }
    else if (ret < 0)
        XLOG(WOLFKM_LOG_ERROR, "wolfssl ReceiveCb error\n");

    return ret;
}


/* wolfSSL I/O Send CallBack */
static int wolfsslSendCb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int ret;
    struct bufferevent* bev = (struct bufferevent*)ctx;

    (void)ssl;

    if (bev == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "wolfSSL SendCb NULL ctx\n");
        return -1;
    }

    ret = evbuffer_add(bufferevent_get_output(bev), buf, sz);
    if (ret == 0) {
        return sz;
    }
    else if (ret < 0)
        XLOG(WOLFKM_LOG_ERROR, "wolfssl SendCb error\n");

    return ret;
}


/* setup ssl context */
static int InitServerTLS(svcInfo* svc, const char* certName)
{
    int ret;
    sslCtx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    if (sslCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Can't alloc TLS 1.2 context\n");
        return MEMORY_E;
    }
    wolfSSL_SetIORecv(sslCtx, wolfsslRecvCb);
    wolfSSL_SetIOSend(sslCtx, wolfsslSendCb);

    ret = wolfSSL_CTX_use_certificate_file(sslCtx, certName, WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        XLOG(WOLFKM_LOG_ERROR, "Can't load TLS cert into context\n");
        wolfSSL_CTX_free(sslCtx); sslCtx = NULL;
        return ret;
    }

    ret = wolfSSL_CTX_use_PrivateKey_buffer(sslCtx, 
        svc->keyBuffer, svc->keyBufferSz, WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        XLOG(WOLFKM_LOG_ERROR, "Can't load TLS key into context\n");
        wolfSSL_CTX_free(sslCtx); sslCtx = NULL;
        return ret;
    }
    return 0;
}


/* Initialize all worker threads */
int InitThreads(svcInfo* svc, int numThreads, const char* certName)
{
    int ret = 0, i;
    connItem*  item;

    /* pthread inits */
    pthread_mutex_init(&initLock, NULL);
    pthread_cond_init(&initCond, NULL);
    pthread_mutex_init(&itemLock, NULL);
    pthread_mutex_init(&globalStats.lock, NULL);

    /* get thread memory */
    threads = calloc(numThreads, sizeof(eventThread));
    if (threads == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Can't allocate thread pool\n");
        return MEMORY_E;
    }

    /* pre allocate pool memory */
    item = ConnItemNew(svc);
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
            XLOG(WOLFKM_LOG_ERROR, "Can't make notify pipe\n");
            return -1; /* TOOD: Add return code */
        }

        threads[i].notifyRecv = fds[0];
        threads[i].notifySend = fds[1];
        SetupThread(svc, &threads[i]);
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
    usingTLS = 0;    /* build time only disable for now */
#endif
    if (usingTLS)
        ret = InitServerTLS(svc, certName);

    return ret;
}


/* dispatcher thread accept callback */
void AcceptCB(struct evconnlistener* listener, evutil_socket_t fd,
              struct sockaddr* a, int slen, void* p)
{
    static int lastThread = -1;       /* last used thread ID */

    int  currentId = (lastThread + 1) % threadPoolSize;    /* round robin */
    char w = 'w';    /* send wakeup flag */

    eventThread* thread = threads + currentId;
    connItem*    item = ConnItemNew((svcInfo*)p);

    if (item == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Unable to process accept request, low memory\n");
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
        XLOG(WOLFKM_LOG_ERROR, "Write to thread notify send pipe failed\n");

    XLOG(WOLFKM_LOG_INFO, "Accepted a connection, sent to thread %d\n", currentId);
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
            XLOG(WOLFKM_LOG_ERROR, "Can't setrlimit max files\n");
            exit(EX_OSERR);
        }
    } else {
        XLOG(WOLFKM_LOG_ERROR, "Can't getrlimit max files\n");
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
                XLOG(WOLFKM_LOG_ERROR, "Can't setrlimit core\n");
                exit(EX_OSERR);
            }
        }
    } else {
        XLOG(WOLFKM_LOG_ERROR, "Can't getrlimit core\n");
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
        XLOG(WOLFKM_LOG_ERROR, "setsid\n");
        return -1;
    }

    if (chDir) {
        if (chdir("/") != 0) {    /* change working directory */
            XLOG(WOLFKM_LOG_ERROR, "chdir\n");
            return -1;
        }
    }

    umask(0);                     /* always successful */

    fd = open("/dev/null", O_RDWR, 0);
    if (fd == -1) {
        XLOG(WOLFKM_LOG_ERROR, "open /dev/null\n");
        return -1;
    }

    if (dup2(fd, STDIN_FILENO) < 0 || dup2(fd, STDOUT_FILENO) < 0 ||
                                      dup2(fd, STDERR_FILENO) < 0) {
        XLOG(WOLFKM_LOG_ERROR, "dup2 std filenos\n");
        return -1;
    }

    if (close(fd) < 0) {
        XLOG(WOLFKM_LOG_ERROR, "close\n");
        return -1;
    }

    return 0;
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



/* Check for already running process using exclusive lock on pidfile.
 * Returns NULL if process is already running, otherwise writes pid to
 * pidfile and returns FILE pointer to pidfile with an exclusive lock.
 */
FILE* GetPidFile(const char* pidFile, pid_t pid)
{
    FILE* f;
    int   fd;

    if (!pidFile) {
        XLOG(WOLFKM_LOG_ERROR, "Missing pidfile path\n");
        return NULL; /* Fail */
    }

    /* Open pidfile for writing.  If already exists, do not truncate,
     * but otherwise create it. */
    if ((f = fopen(pidFile, "r+")) == NULL) {
        if (errno != ENOENT) {
            XLOG(WOLFKM_LOG_ERROR, "fopen %s\n", strerror(errno));
            return NULL; /* Fail */
        }
        if ((f = fopen(pidFile, "w")) == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "fopen %s\n", strerror(errno));
            return NULL; /* Fail */
        }
    }

    fd = fileno(f);
    if (fd == -1) {
        XLOG(WOLFKM_LOG_ERROR, "fileno %s\n", strerror(errno));
        return NULL; /* Fail */
    }

    if (lockf(fd, F_TLOCK, 0) == -1) {
        XLOG(WOLFKM_LOG_ERROR, "lockf %s\n", strerror(errno));
        return NULL; /* Fail */
    }

    /* Truncate pidfile */
    if (ftruncate(fd, 0) == -1) {
        XLOG(WOLFKM_LOG_ERROR, "ftruncate %s\n", strerror(errno));
        return NULL; /* Fail */
    }

    /* Write pid */
    fprintf(f, "%ld\n", (long)pid);
    if (fflush(f) == EOF) {
        XLOG(WOLFKM_LOG_ERROR, "fflush %s\n", strerror(errno));
        return NULL;
    }

    return f;
}


/* try to add listeners on interface version
 * return count of listener interfaces added.
 */
int AddListeners(int af_v, char* listenPort, struct event_base* mainBase,
    svcInfo* svc)
{
    int                     err;
    int                     addCount = 0;
    struct evutil_addrinfo  hints;
    struct evutil_addrinfo* answer = NULL;
    struct evutil_addrinfo* current = NULL;  /* list traversal */
    char addrStr[100];

    /* listening addr info */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = af_v;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;         /* TCP */
    hints.ai_flags    = EVUTIL_AI_PASSIVE;   /* any addr */

    err = evutil_getaddrinfo(NULL, listenPort, &hints, &answer);
    if (err < 0 || answer == NULL) {
        XLOG(WOLFKM_LOG_WARN, "Failed to evutil_getaddrinfo for listen\n");
        return -1;
    }
    current = answer;

    while (current) {
        listener* ls = (listener*)malloc(sizeof(listener));
        if (ls == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "Failed to alloc listener\n");
            exit(EXIT_FAILURE);
        }

        GetAddrInfoString(current, addrStr, sizeof(addrStr));
        XLOG(WOLFKM_LOG_INFO, "Binding listener %s\n", addrStr);

        ls->ev_listen = evconnlistener_new_bind(mainBase, AcceptCB, svc,
            (LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE),
            -1, current->ai_addr, current->ai_addrlen);
        if (ls->ev_listen == NULL) {
            XLOG(WOLFKM_LOG_WARN, "Failed to bind listener: Error %d: %s\n", 
                errno, strerror(errno));
            free(ls);
            ls = NULL;
        }
        current = current->ai_next;
        
        if (ls) {
            addCount++;
            evconnlistener_set_error_cb(ls->ev_listen, OurListenerError);
            ls->next = listenerList;  /* prepend to list */
            listenerList = ls;
        }
    }
    evutil_freeaddrinfo(answer);

    return addCount;
}


/* release listener resources */
void FreeListeners(void)
{
    while (listenerList) {
        listener* next = listenerList->next;

        evconnlistener_free(listenerList->ev_listen);
        free(listenerList);
        listenerList = next;
    }
}
