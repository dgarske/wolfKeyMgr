/* utils.h
*
* Copyright (C) 2021 wolfSSL Inc.
*
* This file is part of wolf key manager
*
* All rights reserved.
*
*/


#ifndef WOLFKM_UTILS_H
#define WOLFKM_UTILS_H

#include <stdio.h>
#include <stdarg.h>

/* key manager errors */
enum  {
    WOLFKM_BAD_VERIFY_SIZE   = -1001,
    WOLFKM_BAD_ARGS          = -1002,
    WOLFKM_BAD_HEADER_SZ     = -1003,
    WOLFKM_BAD_VERSION       = -1004,
    WOLFKM_BAD_REQUEST_TYPE  = -1005,
    WOLFKM_BAD_X509_D2I      = -1006,
    WOLFKM_BAD_X509_GET_NAME = -1007,
    WOLFKM_BAD_X509_ONELINE  = -1008,
    WOLFKM_BAD_X509_MATCH    = -1009,

    WOLFKM_ERROR_BEGIN = WOLFKM_BAD_VERIFY_SIZE
};

/* Log levels */
enum log_level_t {
    WOLFKM_LOG_ERROR = 4,
    WOLFKM_LOG_WARN  = 3,
    WOLFKM_LOG_INFO  = 2,
    WOLFKM_LOG_DEBUG = 1,
    WOLFKM_DEFAULT_LOG_LEVEL = WOLFKM_LOG_DEBUG
};


#define XLOG wolfKeyMgr_Log

#ifdef __GNUC__
#define ATT_STRFUNC __attribute__((format(printf, 2, 3)))
#else
#define ATT_STRFUNC
#endif

/* Helper / Utility Functions */
const char* wolfKeyMgr_GetError(int err);
const char* wolfKeyMgr_GetLogLevel(enum log_level_t level);
void wolfKeyMgr_Log(enum log_level_t, const char* fmt, ...) ATT_STRFUNC;
void wolfKeyMgr_SetLogFile(const char* fileName, int daemon, enum log_level_t level);

/* misc functions */
void c16toa(unsigned short, unsigned char*);
void ato16(const unsigned char*, unsigned short*);
#if !defined(min) && !defined(WOLFSSL_HAVE_MIN)
int min(int a, int b);
#endif


#endif /* WOLFKM_UTILS_H */
