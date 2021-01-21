/* keymanager.h
*
* Copyright (C) 2021 wolfSSL Inc.
*
* This file is part of wolf key manager
*
* All rights reserved.
*
*/

#include "config.h"
#include "visibility.h"
#include "sock_mgr.h"
#include "utils.h"
#include "svc_cert.h"
#include "svc_etsi.h"


/* string constants */
#define WOLFKM_DEFAULT_LOG_NAME     NULL
#define WOLFKM_DEFAULT_KEY_PASSWORD "wolfssl"
#define WOLFKM_DEFAULT_KEY          "./certs/test-key.pem"
#define WOLFKM_DEFAULT_CERT         "./certs/test-cert.pem"
#define WOLFKM_DEFAULT_PID          "./cert.pid"


/* program constants */
enum ProgramConstMisc {
    WOLFKM_DEFAULT_FILES       =  1024,        /* default max open files */
    WOLFKM_DEFAULT_TIMEOUT     =     3,        /* default timeout in seconds */
    WOLFKM_CONN_ITEMS          =  1024,        /* new conn item pool size */
    WOLFKM_BACKOFF_TIME        = 10000,        /* in microseconds */
    CERT_HEADER_SZ             =     4,        /* version (1), type(1), len(2) */
    CERT_VERSION               =     1,        /* current version */
    CERT_HEADER_VERSION_OFFSET =     0,        /* at front */
    CERT_HEADER_TYPE_OFFSET    =     1,        /* version (1) */
    CERT_HEADER_SZ_OFFSET      =     2,        /* version (1), type(1) */
    WORD16_LEN                 =     2,        /* sizeof word16 */
    MAX_PASSWORD_SZ            =   160,        /* max password size */
};
