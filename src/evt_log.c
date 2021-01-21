/* evt_log.c
*
* Copyright (C) 2013 wolfSSL Inc.
*
* This file is part of cert service 
*
* All rights reserved.
*
*/


#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include "evt_log.h"


/* our log file */
static FILE* logFile = NULL;
static enum log_level_t logLevel = EVT_DEFAULT_LOG_LEVEL;


/* set the log file we want to use, use stderr as default  */
void SetLogFile(const char* fileName, int daemon, enum log_level_t level)
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
static const char* GetLogStr(enum log_level_t level)
{
    switch (level) {
        case EVT_LOG_INFO:
            return "INFO";

        case EVT_LOG_WARN:
            return "WARNING";

        case EVT_LOG_ERROR:
            return "ERROR";

        case EVT_LOG_DEBUG:
            return "DEBUG";

        default:
            return "UNKNOWN";
    }
}


/* our logging function */
void XLOG(enum log_level_t level, const char* fmt, ...)
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

    fprintf(logFile, "%s: [%s] %s", timeStr, GetLogStr(level), msgStr);
}

