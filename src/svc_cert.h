/* svc_cert.h
*
* Copyright (C) 2021 wolfSSL Inc.
*
* This file is part of wolf key manager
*
* All rights reserved.
*
*/


#ifndef WOLFKM_SVC_CERT_H
#define WOLFKM_SVC_CERT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "keymanager.h"

#define WOLFKM_DEFAULT_CERT_PORT    "8118"

enum CertServiceMisc {
    CERT_HEADER_SZ             =     4,        /* version (1), type(1), len(2) */
    CERT_VERSION               =     1,        /* current version */
    CERT_HEADER_VERSION_OFFSET =     0,        /* at front */
    CERT_HEADER_TYPE_OFFSET    =     1,        /* version (1) */
    CERT_HEADER_SZ_OFFSET      =     2,        /* version (1), type(1) */
    WORD16_LEN                 =     2,        /* sizeof word16 */
    MAX_PASSWORD_SZ            =   160,        /* max password size */

    WOLFKM_DEFAULT_MAX_SIGNS   = 5000          /* default max signs b4 re-init */
                                               /* 1,600,000 max / 32 (seed) /
                                                * 10 (our safety) */
};

enum CertMessageTypes {
    ERROR_RESPONSE      =     0,             /* error response type */
    CERT_REQUEST        =     1,             /* cert request type */
    CERT_RESPONSE       =     2,             /* cert response type */
    SIGN_REQUEST        =     3,             /* sign request type */
    SIGN_RESPONSE       =     4,             /* sign response type */
    VERIFY_REQUEST      =     5,             /* verify request type */
    VERIFY_RESPONSE     =     6              /* verify response type */
};


int wolfCertSvc_Init(svcInfo* svc, eventThread* thread);
int wolfCertSvc_DoRequest(svcConn* conn);
void wolfCertSvc_Free(svcInfo* svc, eventThread* thread);


#ifdef __cplusplus
}
#endif

#endif /* WOLFKM_SVC_CERT_H */