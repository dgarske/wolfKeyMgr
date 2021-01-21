/* evt_err.c
*
* Copyright (C) 2013 wolfSSL Inc.
*
* This file is part of cert service 
*
* All rights reserved.
*
*/


#include "evt_err.h"
#include "evt_log.h"



const char* GetEvtError(int err)
{
    switch (err) {

        case EVT_BAD_VERIFY_SIZE:
            return "Bad VerifyRequest size parameter";

        case EVT_BAD_ARGS:
            return "Bad Function arguments";

        case EVT_BAD_HEADER_SZ:
            return "Bad Header size parameter";

        case EVT_BAD_VERSION:
            return "Bad Header Version";

        case EVT_BAD_REQUEST_TYPE:
            return "Bad Header Request Type";

        case EVT_BAD_X509_D2I:
            return "Bad X509 d2i conversion";

        case EVT_BAD_X509_GET_NAME:
            return "Bad X509 get name";

        case EVT_BAD_X509_ONELINE:
            return "Bad X509 get name oneline";

        case EVT_BAD_X509_MATCH:
            return "Bad X509 issuer name mismatch";

        default:
            XLOG(EVT_LOG_ERROR, "Unknown GetEvtError %d\n", err); 
            return "Unknown error number";

    }

}

