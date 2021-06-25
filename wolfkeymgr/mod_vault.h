/* mod_vault.h
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

#ifndef WOLFKM_VAULT_H
#define WOLFKM_VAULT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wolfkeymgr/wkm_types.h"
#include "wolfkeymgr/wkm_utils.h"

/* wolfssl headers */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

#ifndef WOLFKM_VAULT_NAME_MAX_SZ
#define WOLFKM_VAULT_NAME_MAX_SZ 64
#endif

/* opaque type for wolfVaultCtx (pointer reference only) */
typedef struct wolfVaultCtx wolfVaultCtx;

typedef struct wolfVaultItem {
    char        name[WOLFKM_VAULT_NAME_MAX_SZ]; /* name is hash of public key or leading bits from it */
    word32      type;
    word32      timestamp;
    word32      size;
    const byte* data; /* always dynamic - only free using wolfVaultFreeItem */
} wolfVaultItem;

/* open vault file using password */
WOLFKM_API int wolfVaultOpen(wolfVaultCtx** ctx, const char* file, const char* password);
/* add item to vault */
WOLFKM_API int wolfVaultAdd(wolfVaultCtx* ctx, const char* name, word32 type, const byte* data, word32 dataSz);
/* get copy of item from vault */
WOLFKM_API int wolfVaultGet(wolfVaultCtx* ctx, wolfVaultItem* item, const char* name, word32 type, byte* data, word32* dataSz);
/* search and return item from vault */
WOLFKM_API int wolfVaultFind(wolfVaultCtx* ctx, wolfVaultItem* item, word32 type, word32 timestamp);
/* search next and return item from vault */
WOLFKM_API int wolfVaultFindNext(wolfVaultCtx* ctx, wolfVaultItem* item, word32 type, word32 timestamp);
/* free a wolfVaultItem structure */
WOLFKM_API int wolfVaultFreeItem(wolfVaultItem* item);
/* delete a single item from the vault */
WOLFKM_API int wolfVaultDelete(wolfVaultCtx* ctx, const char* name, word32 type);
/* archive items older than specified date from vault */
WOLFKM_API int wolfVaultArchive(wolfVaultCtx* ctx, word32 timestamp);
/* close vault file */
WOLFKM_API void wolfVaultClose(wolfVaultCtx* ctx);


#ifdef __cplusplus
}
#endif

#endif /* WOLFKM_VAULT_H */