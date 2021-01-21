/* evt.h
*
* Copyright (C) 2013 wolfSSL Inc.
*
* This file is part of cert service
*
* All rights reserved.
*
*/


#ifndef EVT_BASE_H
#define EVT_BASE_H

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


/* string constants */
#define EVT_DEFAULT_PORT "8118"
#define EVT_DEFAULT_PASSWD_PORT "8119"
#define EVT_DEFAULT_LOG_NAME NULL
#define EVT_DEFAULT_KEY "./certs/test-key.pem"
#define EVT_DEFAULT_CERT "./certs/test-cert.pem"
#define EVT_DEFAULT_PID "./cert.pid"

/* for client tests only */
#define EVT_DEFAULT_HOST "localhost"
#define EVT_DEFAULT_KEY_PASSWORD "wolfssl"
#define EVT_DEFAULT_REQUESTS 100   /* per thread */
#define EVT_ERROR_MODE_MAX 5       /* error mode type for forcing errors */
/* end client tests only */

/* program constants */
enum Misc {
    EVT_DEFAULT_FILES   =  1024,             /* default max open files */
    EVT_DEFAULT_TIMEOUT =     3,             /* default timeout in seconds */
    EVT_CONN_ITEMS      =  1024,             /* new conn item pool size */
    EVT_BACKOFF_TIME    = 10000,             /* in microseconds */
    CERT_HEADER_SZ      =     4,             /* version (1), type(1), len(2) */
    CERT_VERSION        =     1,             /* current version */
    CERT_HEADER_VERSION_OFFSET =   0,        /* at front */
    CERT_HEADER_TYPE_OFFSET    =   1,        /* version (1) */
    CERT_HEADER_SZ_OFFSET      =   2,        /* version (1), type(1) */
    WORD16_LEN                 =   2,        /* sizeof word16 */
    MAX_PASSWORD_SZ            = 160,        /* max password size */
    MAX_SOCKADDR_SZ     =    32              /* won't be bigger */
};


enum SecurityC {
    EVT_DEFAULT_MAX_SIGNS = 5000             /* default max signs b4 re-init */
                                             /* 1,600,000 max / 32 (seed) /
                                              * 10 (our safety) */
};


enum CERT_MESSAGES {
    ERROR_RESPONSE      =     0,             /* error response type */
    CERT_REQUEST        =     1,             /* cert request type */
    CERT_RESPONSE       =     2,             /* cert response type */
    SIGN_REQUEST        =     3,             /* sign request type */
    SIGN_RESPONSE       =     4,             /* sign response type */
    VERIFY_REQUEST      =     5,             /* verify request type */
    VERIFY_RESPONSE     =     6              /* verify response type */
};


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
void SetListenerErrorCb(struct evconnlistener*);
void SignalCb(evutil_socket_t fd, short event, void* arg);
int  SigIgnore(int sig);
void ShowStats(void);
FILE* GetPidFile(const char* pidFile, pid_t pid);
void SetTimeout(struct timeval);
void AcceptCB(struct evconnlistener* listener, evutil_socket_t fd,
              struct sockaddr* a, int slen, void* p);
int GetAddrInfoString(struct evutil_addrinfo* addr, char* buf, size_t bufSz);

#endif /* EVT_BASE_H */
