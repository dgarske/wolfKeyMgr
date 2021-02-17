/* mod_etsi.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolf Key Manager.
 *
 * wolfKeyMgr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfKeyMgr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFKM_ETSI_H
#define WOLFKM_ETSI_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wkm_types.h"
#include "mod_socket.h"

typedef struct EtsiClientCtx EtsiClientCtx;

typedef enum EtsiClientType {
    ETSI_CLIENT_UNKNOWN,
    ETSI_CLIENT_GET,
    ETSI_CLIENT_PUSH,
} EtsiClientType;


WOLFKM_API EtsiClientCtx* wolfKeyMgr_EtsiClientNew(void);

WOLFKM_API int wolfKeyMgr_EtsiClientConnect(EtsiClientCtx* client, 
    const char* host, word16 port);

WOLFKM_API int wolfKeyMgr_EtsiClientGet(EtsiClientCtx* client, 
    EtsiClientType type, const char* fingerprint, int timeoutSec,
    byte* response, word32* responseSz);

WOLFKM_API void wolfKeyMgr_EtsiClientFree(EtsiClientCtx* client);

WOLFKM_API int wolfKeyMgr_EtsiLoadKey(ecc_key* key, byte* buffer, word32 length);

#ifdef __cplusplus
}
#endif

#endif /* WOLFKM_ETSI_H */
