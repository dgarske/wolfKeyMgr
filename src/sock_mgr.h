/* sock_mgr.h
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

#ifndef SOCK_MGR_H
#define SOCK_MGR_H

#include <stdlib.h>
#include <string.h>
#include <pthread.h>               /* thread header */
#include <sysexits.h>              /* exit status header */
#include <event2/event-config.h>   /* event headers */
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/dns.h>

#include "visibility.h"

/* wolfssl headers */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>


#ifdef __cplusplus
extern "C" {
#endif

/* string constants */

/* program constants */
#define MAX_SOCKADDR_SZ   32
#define MAX_REQUEST_SIZE (16*1024)

/* program types */

/* signal processing holder */
typedef struct {
    struct event_base* base;       /* base event that setup signal handler */
    struct event*      ev;         /* actual signal event */
} signalArg;

/* forward declarations */
typedef struct connItem connItem;
typedef struct svcConn svcConn;
typedef struct svcInfo svcInfo;
typedef struct eventThread eventThread;

/* service connection */
typedef int  (*svcRequestFunc)(svcConn*);
typedef int  (*initThreadFunc)(svcInfo*, void**);
typedef void (*freeThreadFunc)(svcInfo*, void*);

struct svcInfo {
    const char* desc;

    /* service callbacks */
    initThreadFunc  initThreadCb;
    svcRequestFunc  requestCb;
    freeThreadFunc  freeThreadCb;
    
    /* TLS certificate / key - As DER/ASN.1*/
    byte*       keyBuffer;
    byte*       certBuffer;
    word32      keyBufferSz;
    word32      certBufferSz;
};

/* each connection item */
struct connItem {
    connItem* next;                        /* next item on freeList */
    int       fd;                          /* file descriptor */
    char      peerAddr[MAX_SOCKADDR_SZ];   /* copy of peer sockaddr */
    svcInfo*  svc;
};

struct svcConn {
    struct bufferevent* stream;     /* buffered stream */
    WOLFSSL*            ssl;        /* ssl object */
    unsigned int        requestSz;  /* bytes in request buffer */
    unsigned char       request[MAX_REQUEST_SIZE]; /* full input request */
    svcInfo*            svc;
    void*               svcCtx;
    double              start;      /* response processing time start */
    svcConn*            next;       /* for free list */
};

/* queue for connections, shared between main thread and worker threads */
typedef struct {
    connItem*       head;     /* head of queue */
    connItem*       tail;     /* tail of queue */
    pthread_mutex_t lock;     /* queue lock */
} connQueue;


/* overall statistics */
typedef struct {
    pthread_mutex_t lock;                   /* stats lock, only global uses */
    uint64_t        totalConnections;       /* total connections ever */
    uint64_t        completedRequests;      /* completed requests ever */
    uint32_t        timeouts;               /* total requests that timed out */
    uint32_t        currentConnections;     /* current active connections */
    uint32_t        maxConcurrent;          /* max concurrent connections */
    time_t          began;                  /* time we started */
    double          responseTime;           /* total response time */
} stats;


/* each thread in the pool has some unique data */
struct eventThread {
    pthread_t          tid;             /* this thread's ID */
    struct event_base* threadBase;      /* base handle for this thread */
    struct event*      notify;          /* listen event for notify pipe */
    connQueue*         connections;     /* queue for new connections */
    int                notifyRecv;      /* receiving end of notification pipe */
    int                notifySend;      /* sending  end of notification pipe */
    svcInfo*           svc;
    void*              svcCtx;
};


/* Key Manager Functions */
int  wolfKeyMgr_MakeDaemon(int chDir);
void wolfKeyMgr_SetMaxFiles(int max);
void wolfKeyMgr_SetCore(void);
void wolfKeyMgr_SignalCb(evutil_socket_t fd, short event, void* arg);
int  wolfKeyMgr_SigIgnore(int sig);
void wolfKeyMgr_ShowStats(void);
FILE* wolfKeyMgr_GetPidFile(const char* pidFile, pid_t pid);
void wolfKeyMgr_SetTimeout(struct timeval);
int wolfKeyMgr_GetAddrInfoString(struct evutil_addrinfo* addr, char* buf, size_t bufSz);

int wolfKeyMgr_AddListeners(svcInfo* svc, int af_v, char* listenPort, struct event_base* mainBase);
int wolfKeyMgr_InitService(svcInfo* svc, int numThreads);
void wolfKeyMgr_FreeListeners(void);

int wolfKeyMgr_DoSend(svcConn* conn);

int wolfKeyMgr_LoadFileBuffer(const char* fileName, byte** buffer, word32* sz);
int wolfKeyMgr_LoadKeyFile(svcInfo* svc, const char* fileName, int fileType, const char* password);
int wolfKeyMgr_LoadCertFile(svcInfo* svc, const char* fileName, int fileType);




#ifdef __cplusplus
}
#endif

#endif /* SOCK_MGR_H */
