/* keymanager.h
*
* Copyright (C) 2021 wolfSSL Inc.
*
* This file is part of wolf key manager
*
* All rights reserved.
*
*/

#ifndef KEYMANAGER_H
#define KEYMANAGER_H

/* Key Manager Headers */
#include "config.h"
#include "visibility.h"
#include "sock_mgr.h"
#include "utils.h"
#include "svc_cert.h"
#include "svc_etsi.h"

/* wolfssl headers */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>


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
};


#endif /* KEYMANAGER_H */
