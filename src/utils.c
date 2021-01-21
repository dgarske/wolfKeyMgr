/* wolfkm_utils.c
*
* Copyright (C) 2021 wolfSSL Inc.
*
* This file is part of wolf key manager
*
* All rights reserved.
*
*/

#include "utils.h"

#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

/* our log file */
static FILE* logFile = NULL;
static enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;



const char* wolfKeyMgr_GetError(int err)
{
    switch (err) {

        case WOLFKM_BAD_VERIFY_SIZE:
            return "Bad VerifyRequest size parameter";

        case WOLFKM_BAD_ARGS:
            return "Bad Function arguments";

        case WOLFKM_BAD_HEADER_SZ:
            return "Bad Header size parameter";

        case WOLFKM_BAD_VERSION:
            return "Bad Header Version";

        case WOLFKM_BAD_REQUEST_TYPE:
            return "Bad Header Request Type";

        case WOLFKM_BAD_X509_D2I:
            return "Bad X509 d2i conversion";

        case WOLFKM_BAD_X509_GET_NAME:
            return "Bad X509 get name";

        case WOLFKM_BAD_X509_ONELINE:
            return "Bad X509 get name oneline";

        case WOLFKM_BAD_X509_MATCH:
            return "Bad X509 issuer name mismatch";

        default:
            XLOG(WOLFKM_LOG_ERROR, "Unknown error %d\n", err); 
            return "Unknown error number";

    }

}

/* set the log file we want to use, use stderr as default  */
void wolfKeyMgr_SetLogFile(const char* fileName, int daemon, enum log_level_t level)
{
    logLevel = level;

    if (daemon == 0 && fileName == NULL)
        logFile = stderr;
    else if (daemon == 1 && fileName == NULL) {
        perror("Daemon needs a log file, can't write to stderr");
        exit(EXIT_FAILURE);
    }
    else {
        /* let's use user specificed log file */
        logFile = fopen(fileName, "a+");
        if (logFile == NULL) {
            perror("Can't open log file for writing");
            exit(EXIT_FAILURE);
        }
    }
}


/* log level string */
const char* wolfKeyMgr_GetLogLevel(enum log_level_t level)
{
    switch (level) {
        case WOLFKM_LOG_INFO:
            return "INFO";

        case WOLFKM_LOG_WARN:
            return "WARNING";

        case WOLFKM_LOG_ERROR:
            return "ERROR";

        case WOLFKM_LOG_DEBUG:
            return "DEBUG";

        default:
            return "UNKNOWN";
    }
}

/* our logging function */
void wolfKeyMgr_Log(enum log_level_t level, const char* fmt, ...)
{
    va_list vlist;
    char    timeStr[80];
    char    msgStr[1024];
    time_t  current;
    struct  tm local;

    if (level < logLevel)
        return;   /* don't need to output */

    if (logFile == NULL)
        return;   /* can't output */

    /* prefix timestamp */
    timeStr[0] = '\0';
    current = time(NULL);
    if (localtime_r(&current, &local)) {
        /* make pretty */
        strftime(timeStr, sizeof(timeStr), "%b %d %T %Y", &local);
    }        
    timeStr[sizeof(timeStr)-1] = '\0';

    /* format msg */
    msgStr[0] = '\0';
    va_start(vlist, fmt);
    vsnprintf(msgStr, sizeof(msgStr), fmt, vlist);
    va_end(vlist);
    msgStr[sizeof(msgStr)-1] = '\0';

    fprintf(logFile, "%s: [%s] %s", 
        timeStr, wolfKeyMgr_GetLogLevel(level), msgStr);
}



#ifndef min
int min(int a, int b)
{
    return a < b ? a : b;
}
#endif

/* convert short to network byte order, no alignment required */
void c16toa(unsigned short u16, unsigned char* c)
{
    c[0] = (u16 >> 8) & 0xff;
    c[1] =  u16 & 0xff;
}

/* convert opaque to 16 bit integer */
void ato16(const unsigned char* c, unsigned short* u16)
{
    *u16 = (c[0] << 8) | (c[1]);
}
