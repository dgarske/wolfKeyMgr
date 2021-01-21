/* driver.c , drives event processing
*
* Copyright (C) 2013 wolfSSL Inc.
*
* This file is part of cert service
*
* All rights reserved.
*
*/



#include <unistd.h>    /* getopt */
#include <signal.h>    /* SIGPIPE */

#include "evt.h"
#include "evt_log.h"
#include "config.h"


typedef struct listener listener;

/* allow listener list */
struct listener {
    struct evconnlistener* ev_listen;   /* event listener */
    listener* next;                     /* next on list */
};


/* release listener resources */
static void free_listeners(listener* listenerList)
{
    while (listenerList) {
        listener* next = listenerList->next;

        evconnlistener_free(listenerList->ev_listen);
        free(listenerList);
        listenerList = next;
    }
}

static listener* listenerList = NULL;  /* main list */

/* usage help */
static void Usage(void)
{
    printf("%s\n", PACKAGE_STRING);
    printf("-?          Help, print this usage\n");
    printf("-c          Core file max, don't chdir / in daemon mode\n");
    printf("-d          Daemon mode, run in background\n");
    printf("-f <str>    Pid File name, default %s\n", EVT_DEFAULT_PID);
    printf("-k <str>    Key file name, default %s\n", EVT_DEFAULT_KEY);
    printf("-a <str>    CA file name, default %s\n", EVT_DEFAULT_CERT);
    printf("-l <str>    Log file name, default %s\n",
                          EVT_DEFAULT_LOG_NAME ? EVT_DEFAULT_LOG_NAME : "None");
    printf("-m <num>    Max open files, default  %d\n", EVT_DEFAULT_FILES);
    printf("-p <num>    Port to listen on, default %s\n", EVT_DEFAULT_PORT);
    printf("-g <num>    Get Password port, default %s\n",
                                                       EVT_DEFAULT_PASSWD_PORT);
    printf("-s <num>    Seconds to timeout, default %d\n", EVT_DEFAULT_TIMEOUT);
    printf("-t <num>    Thread pool size, default  %ld\n",
                                                 sysconf(_SC_NPROCESSORS_CONF));
    printf("-v <num>    Log Level, default %d\n", EVT_DEFAULT_LOG_LEVEL);
}


/* try to add listeners on interface version, 0 return if at least one added */
static int AddListeners(int af_v, char* listenPort, struct event_base* mainBase)
{
    int                     err;
    int                     gotOne = 0;
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
        XLOG(EVT_LOG_WARN, "Failed to evutil_getaddrinfo for listen\n");
        return -1;
    }
    current = answer;

    while (current) {
        listener* ls = (listener*)malloc(sizeof(listener));
        if (ls == NULL) {
            XLOG(EVT_LOG_ERROR, "Failed to alloc listener\n");
            exit(EXIT_FAILURE);
        }

        GetAddrInfoString(current, addrStr, sizeof(addrStr));
        XLOG(EVT_LOG_INFO, "Binding listener %s\n", addrStr);

        ls->ev_listen = evconnlistener_new_bind(mainBase, AcceptCB, NULL,
            (LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE),
            -1, current->ai_addr, current->ai_addrlen);
        if (ls->ev_listen == NULL) {
            XLOG(EVT_LOG_WARN, "Failed to bind listener: Error %d: %s\n", 
                errno, strerror(errno));
            free(ls);
            ls = NULL;
        }
        current = current->ai_next;
        
        if (ls) {
            gotOne++;
            SetListenerErrorCb(ls->ev_listen);
            ls->next = listenerList;  /* prepend to list */
            listenerList = ls;
        }
    }
    evutil_freeaddrinfo(answer);

    return gotOne ? 0 : -1;
}


int main(int argc, char** argv)
{
    int ch;
    int daemon        = 0;
    int core          = 0;
    int poolSize      = (int)sysconf(_SC_NPROCESSORS_CONF);
    int maxFiles      = EVT_DEFAULT_FILES;
    enum log_level_t logLevel = EVT_DEFAULT_LOG_LEVEL;
    char*  listenPort = EVT_DEFAULT_PORT;
    char*  passwdPort = EVT_DEFAULT_PASSWD_PORT;
    char*  logName    = EVT_DEFAULT_LOG_NAME;
    char*  keyName    = EVT_DEFAULT_KEY;
    char*  certName   = EVT_DEFAULT_CERT;
    char*  pidName    = EVT_DEFAULT_PID;
    struct timeval          ourTimeout;
    struct event*           signalEvent; /* signal event handle */
    struct event_base*      mainBase;    /* main thread's base  */
    signalArg               sigArg;
    FILE*                   pidF;

    ourTimeout.tv_sec  = EVT_DEFAULT_TIMEOUT;
    ourTimeout.tv_usec = 0;

    /* argument processing */
    while ((ch = getopt(argc, argv, "?dcnp:g:s:t:m:l:k:a:f:v:")) != -1) {
        switch (ch) {
            case '?' :
                Usage();
                exit(EXIT_SUCCESS);
            case 'd' :
                daemon = 1;
                break;
            case 'c' :
                core = 1;
                break;
            case 'p' :
                listenPort = optarg;
                break;
            case 'g' :
                passwdPort = optarg;
                break;
            case 's' :
                ourTimeout.tv_sec = atoi(optarg);
                if (ourTimeout.tv_sec < 0) {
                    perror("timeout positive values only accepted");
                    exit(EX_USAGE);
                }
                break;
            case 't' :
                poolSize = atoi(optarg);
                break;
            case 'm' :
                maxFiles = atoi(optarg);
                break;
            case 'l' :
                logName = optarg;
                break;
            case 'k' :
                keyName = optarg;
                break;
            case 'a' :
                certName = optarg;
                break;
            case 'f' :
                pidName = optarg;
                break;
            case 'v' :
                logLevel = atoi(optarg);
                if (logLevel < EVT_LOG_DEBUG || logLevel > EVT_LOG_ERROR) {
                    perror("loglevel [1:4] only");
                    exit(EX_USAGE);
                }
                break;

            default:
                Usage();
                exit(EX_USAGE);
        }
    }

    /* Create daemon */
    if (daemon) {
        if (logName == NULL) {
            perror("daemon mode needs a log file, can't write to stderr");
            exit(EXIT_FAILURE);
        }
        if (MakeDaemon(core == 0) == -1) {
            perror("Failed to make into daemon");
            exit(EXIT_FAILURE);
        }
    }
    else
        setbuf(stderr, NULL);

    /* start log */
    SetLogFile(logName, daemon, logLevel);
    XLOG(EVT_LOG_INFO, "Starting\n");

    /* main thread base event */
    mainBase = event_base_new();
    if (mainBase == NULL) {
        XLOG(EVT_LOG_ERROR, "Failed to event_base_new\n");
        exit(EXIT_FAILURE);
    }

    /* setup signal stuff */
    if (SigIgnore(SIGPIPE) == -1) {
        XLOG(EVT_LOG_ERROR, "Failed to ignore SIGPIPE\n");
        exit(EX_OSERR);
    }

    /* setup listening events, bind before .pid file creation */
    AddListeners(AF_INET6, listenPort, mainBase);  /* 6 may contain a 4 */
    AddListeners(AF_INET, listenPort, mainBase);   /* should be first */

    if (listenerList == NULL) {
        XLOG(EVT_LOG_ERROR, "Failed to bind at least one listener,"
                            "already running?\n");
        exit(EXIT_FAILURE);
    }

    pidF = GetPidFile(pidName, getpid());
    if (pidF == NULL) {
        XLOG(EVT_LOG_ERROR, "Failed to get pidfile (already running?)\n");
        exit(EXIT_FAILURE);
    }

    /* max files, key, and timeout */
    SetKeyFile(keyName);
    SetMaxFiles(maxFiles);
    SetCertFile(certName);
    SetTimeout(ourTimeout);

    /* thread setup */
    InitThreads(poolSize, certName);

    /* SIGINT handler */
    signalEvent = event_new(mainBase, SIGINT, EV_SIGNAL|EV_PERSIST, SignalCb,
                            &sigArg);
    sigArg.ev   = signalEvent;
    sigArg.base = mainBase;
    if (event_add(signalEvent, NULL) == -1) {
        XLOG(EVT_LOG_ERROR, "Can't add event for signal\n");
        exit(EXIT_FAILURE);
    }

    /* start main loop */
    event_base_dispatch(mainBase);

    /* we're done with loop */
    XLOG(EVT_LOG_INFO, "Done with main thread dispatching\n");
    ShowStats();

    /* Cleanup pid file */
    if (pidF) {
        fclose(pidF);
        unlink(pidName);
    }

    free_listeners(listenerList);
    event_del(signalEvent);
    event_base_free(mainBase);

    exit(EXIT_SUCCESS);
}
