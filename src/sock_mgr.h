/* sock_mgr.h
*
* Copyright (C) 2021 wolfSSL Inc.
*
* This file is part of wolf key manager
*
* All rights reserved.
*
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

#ifdef __cplusplus
extern "C" {
#endif

/* string constants */

/* program constants */
#define MAX_SOCKADDR_SZ 32

/* program types */

/* signal processing holder */
typedef struct {
    struct event_base* base;       /* base event that setup signal handler */
    struct event*      ev;         /* actual signal event */
} signalArg;

typedef struct connItem connItem;

/* each connection item */
struct connItem {
    connItem* next;                        /* next item on freeList */
    int       fd;                          /* file descriptor */
    char      peerAddr[MAX_SOCKADDR_SZ];   /* copy of peer sockaddr */
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
typedef struct {
    pthread_t          tid;             /* this thread's ID */
    struct event_base* threadBase;      /* base handle for this thread */
    struct event*      notify;          /* listen event for notify pipe */
    connQueue*         connections;     /* queue for new connections */
    int                notifyRecv;      /* receiving end of notification pipe */
    int                notifySend;      /* sending  end of notification pipe */
} eventThread;


/* forward headers, see definitions in evt.c for more info on each */
void InitThreads(int numThreads, const char* certName);
int  MakeDaemon(int chDir);
void SetKeyFile(const char* fileName);
void SetCertFile(const char* fileName);
void SetMaxFiles(int max);
void SetCore(void);
void SignalCb(evutil_socket_t fd, short event, void* arg);
int  SigIgnore(int sig);
void ShowStats(void);
FILE* GetPidFile(const char* pidFile, pid_t pid);
void SetTimeout(struct timeval);
int AddListeners(int af_v, char* listenPort, struct event_base* mainBase);
void FreeListeners(void);
void AcceptCB(struct evconnlistener* listener, evutil_socket_t fd,
              struct sockaddr* a, int slen, void* p);
int GetAddrInfoString(struct evutil_addrinfo* addr, char* buf, size_t bufSz);

#ifdef __cplusplus
}
#endif

#endif /* SOCK_MGR_H */
