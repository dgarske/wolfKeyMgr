/* evt_log.h
*
* Copyright (C) 2013 wolfSSL Inc.
*
* This file is part of cert service 
*
* All rights reserved.
*
*/


#ifndef EVT_LOG_H
#define EVT_LOG_H

#include <stdio.h>
#include <stdarg.h>

/* Log levels */
enum log_level_t {
    EVT_LOG_ERROR = 4,
    EVT_LOG_WARN  = 3,
    EVT_LOG_INFO  = 2,
    EVT_LOG_DEBUG = 1,
    EVT_DEFAULT_LOG_LEVEL = EVT_LOG_DEBUG
};


void XLOG(enum log_level_t, const char* fmt, ...)
    __attribute__((format(printf, 2, 3)));

void SetLogFile(const char* fileName, int daemon, enum log_level_t level);


#endif /* _EVT_LOG_H_ */

