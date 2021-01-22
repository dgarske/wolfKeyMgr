/* keymanager.c
*
* Copyright (C) 2021 wolfSSL Inc.
*
* This file is part of wolf key manager
*
* All rights reserved.
*
*/

#include "keymanager.h"

#include <unistd.h>    /* getopt */
#include <signal.h>    /* SIGPIPE */

/* usage help */
static void Usage(void)
{
    printf("%s\n", PACKAGE_STRING);
    printf("-?          Help, print this usage\n");
    printf("-c          Core file max, don't chdir / in daemon mode\n");
    printf("-d          Daemon mode, run in background\n");
    printf("-f <str>    Pid File name, default %s\n", WOLFKM_DEFAULT_PID);
    printf("-k <str>    Key file name, default %s\n", WOLFKM_DEFAULT_KEY);
    printf("-a <str>    CA file name, default %s\n", WOLFKM_DEFAULT_CERT);
    printf("-l <str>    Log file name, default %s\n",
                          WOLFKM_DEFAULT_LOG_NAME ? WOLFKM_DEFAULT_LOG_NAME : "None");
    printf("-m <num>    Max open files, default  %d\n", WOLFKM_DEFAULT_FILES);
    printf("-p <num>    Port to listen on, default %s\n", WOLFKM_DEFAULT_CERT_PORT);
    printf("-s <num>    Seconds to timeout, default %d\n", WOLFKM_DEFAULT_TIMEOUT);
    printf("-t <num>    Thread pool size, default  %ld\n",
                                                 sysconf(_SC_NPROCESSORS_CONF));
    printf("-v <num>    Log Level, default %d\n", WOLFKM_DEFAULT_LOG_LEVEL);
}


/* load our cert file subject (that's always us) into our buffer */
static int SetCertFile(svcInfo* svc, const char* fileName)
{
    WOLFSSL_X509_NAME* subject = NULL;
    WOLFSSL_X509*      x509    = wolfSSL_X509_load_certificate_file(fileName,
                                                              SSL_FILETYPE_PEM);
    if (x509 == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "load X509 cert file %s failed\n", fileName);
        return MEMORY_E;
    }
    XLOG(WOLFKM_LOG_INFO, "loaded X509 cert file %s\n", fileName);

    subject = wolfSSL_X509_get_subject_name(x509);
    if (subject == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "get subject name failed\n");
        wolfSSL_X509_free(x509);
        return MEMORY_E;
    }

    svc->subjectStr[0] = '\0';
    svc->subjectStr[sizeof(svc->subjectStr)-1] = '\0';
    if (wolfSSL_X509_NAME_oneline(subject, svc->subjectStr, sizeof(svc->subjectStr)-1)
                                                                      == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "get subject name oneline failed\n");
        wolfSSL_X509_free(x509);
        return WOLFKM_BAD_X509_GET_NAME;
    }
    svc->subjectStrLen = strlen(svc->subjectStr);
    XLOG(WOLFKM_LOG_INFO, "X509 subject %s\n", svc->subjectStr);

    wolfSSL_X509_free(x509);
    /* subject doesn't need to be freed, points into x509 */

    return 0;
}

/* password getter for encrypted pem private key, caller should call
 * ClearPassword to wipe and free */
static char* GetPassword(void)
{
    char* passwd = (char*)malloc(MAX_PASSWORD_SZ);
    if (passwd == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Memory failure for password\n");
        exit(EXIT_FAILURE);
    }

    memset(passwd, 0, MAX_PASSWORD_SZ);
    strncpy(passwd, WOLFKM_DEFAULT_KEY_PASSWORD, MAX_PASSWORD_SZ);
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
static int SetKeyFile(svcInfo* svc, const char* fileName)
{
    FILE*  tmpFile;
    size_t bytesRead;
    int    ret;
    char*  passwd;

    if (CheckCtcSettings() != 1) {
        XLOG(WOLFKM_LOG_ERROR, "CyaSSL math library mismatch in settings\n");
        exit(EXIT_FAILURE);
    }

#ifdef USE_FAST_MATH
    if (CheckFastMathSettings() != 1) {
        XLOG(WOLFKM_LOG_ERROR, "CyaSSL fast math library mismatch\n");
        exit(EXIT_FAILURE);
    }
#endif

    if (fileName == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Key file name is null\n");
        exit(EXIT_FAILURE);
    }

    tmpFile = fopen(fileName, "rb");
    if (tmpFile == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Key file %s can't be opened for reading\n",
                            fileName);
        exit(EXIT_FAILURE);
    }

    bytesRead = fread(svc->keyBuffer, 1, sizeof(svc->keyBuffer), tmpFile);
    fclose(tmpFile);

    if (bytesRead == 0) {
        XLOG(WOLFKM_LOG_ERROR, "Key file %s can't be read\n", fileName);
        exit(EXIT_FAILURE);
    }

    passwd = GetPassword();
    ret = wolfSSL_KeyPemToDer(svc->keyBuffer, bytesRead, svc->keyBuffer,
                           sizeof(svc->keyBuffer), passwd);
    ClearPassword(passwd);
    if (ret <= 0) {
        XLOG(WOLFKM_LOG_ERROR, "Can't convert Key file from PEM to DER: %d\n",ret);
        exit(EXIT_FAILURE);
    }
    svc->keyBufferSz = ret;

    XLOG(WOLFKM_LOG_INFO, "loaded key file %s\n", fileName);
    return 0;
}



int main(int argc, char** argv)
{
    int ch;
    int daemon        = 0;
    int core          = 0;
    int poolSize      = (int)sysconf(_SC_NPROCESSORS_CONF);
    int maxFiles      = WOLFKM_DEFAULT_FILES;
    enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;
    char*  listenPort = WOLFKM_DEFAULT_CERT_PORT;
    char*  logName    = WOLFKM_DEFAULT_LOG_NAME;
    char*  keyName    = WOLFKM_DEFAULT_KEY;
    char*  certName   = WOLFKM_DEFAULT_CERT;
    char*  pidName    = WOLFKM_DEFAULT_PID;
    struct timeval          ourTimeout;
    struct event*           signalEvent; /* signal event handle */
    struct event_base*      mainBase;    /* main thread's base  */
    signalArg               sigArg;
    FILE*                   pidF;

    static svcInfo certService = {
        .desc = "Certificate",
        .requestCb = wolfCertSvc_DoRequest,
        .initCb = wolfCertSvc_Init,
        .freeCb = wolfCertSvc_Free,
    };

    ourTimeout.tv_sec  = WOLFKM_DEFAULT_TIMEOUT;
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
                if (logLevel < WOLFKM_LOG_DEBUG || logLevel > WOLFKM_LOG_ERROR) {
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
    wolfKeyMgr_SetLogFile(logName, daemon, logLevel);
    XLOG(WOLFKM_LOG_INFO, "Starting\n");

    /* main thread base event */
    mainBase = event_base_new();
    if (mainBase == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to event_base_new\n");
        exit(EXIT_FAILURE);
    }

    /* setup signal stuff */
    if (SigIgnore(SIGPIPE) == -1) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to ignore SIGPIPE\n");
        exit(EX_OSERR);
    }

    /* setup listening events, bind before .pid file creation */
    ch =  AddListeners(AF_INET6, listenPort, mainBase, &certService);  /* 6 may contain a 4 */
    ch += AddListeners(AF_INET, listenPort, mainBase, &certService);   /* should be first */
    if (ch < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to bind at least one listener,"
                            "already running?\n");
        exit(EXIT_FAILURE);
    }

    pidF = GetPidFile(pidName, getpid());
    if (pidF == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to get pidfile (already running?)\n");
        exit(EXIT_FAILURE);
    }

    /* max files, key, and timeout */
    SetKeyFile(&certService, keyName);
    SetCertFile(&certService, certName);
    SetMaxFiles(maxFiles);
    SetTimeout(ourTimeout);

    /* thread setup */
    InitThreads(&certService, poolSize, certName);

    /* SIGINT handler */
    signalEvent = event_new(mainBase, SIGINT, EV_SIGNAL|EV_PERSIST, SignalCb,
                            &sigArg);
    sigArg.ev   = signalEvent;
    sigArg.base = mainBase;
    if (event_add(signalEvent, NULL) == -1) {
        XLOG(WOLFKM_LOG_ERROR, "Can't add event for signal\n");
        exit(EXIT_FAILURE);
    }

    /* start main loop */
    event_base_dispatch(mainBase);

    /* we're done with loop */
    XLOG(WOLFKM_LOG_INFO, "Done with main thread dispatching\n");
    ShowStats();

    /* Cleanup pid file */
    if (pidF) {
        fclose(pidF);
        unlink(pidName);
    }

    FreeListeners();
    event_del(signalEvent);
    event_base_free(mainBase);

    exit(EXIT_SUCCESS);
}
