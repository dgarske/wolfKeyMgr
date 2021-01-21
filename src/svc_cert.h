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

#define WOLFKM_DEFAULT_CERT_PORT    "8118"

enum SecurityC {
    WOLFKM_DEFAULT_MAX_SIGNS = 5000            /* default max signs b4 re-init */
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



#ifdef __cplusplus
}
#endif

#endif /* WOLFKM_SVC_CERT_H */
