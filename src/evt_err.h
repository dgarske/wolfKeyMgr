/* evt_err.h
*
* Copyright (C) 2013 wolfSSL Inc.
*
* This file is part of cert service 
*
* All rights reserved.
*
*/


#ifndef EVT_ERR_H
#define EVT_ERR_H

#include <stdio.h>
#include <stdarg.h>

/* evt errors */
enum  {
    EVT_BAD_VERIFY_SIZE   = -1001,
    EVT_BAD_ARGS          = -1002,
    EVT_BAD_HEADER_SZ     = -1003,
    EVT_BAD_VERSION       = -1004,
    EVT_BAD_REQUEST_TYPE  = -1005,
    EVT_BAD_X509_D2I      = -1006,
    EVT_BAD_X509_GET_NAME = -1007,
    EVT_BAD_X509_ONELINE  = -1008,
    EVT_BAD_X509_MATCH    = -1009,

    EVT_ERROR_BEGIN = EVT_BAD_VERIFY_SIZE
};



const char* GetEvtError(int err);


#endif /* EVT_ERR_H */

