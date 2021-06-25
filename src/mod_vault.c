/* mod_vault.c
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

#include "wolfkeymgr/mod_vault.h"
#include "wolfssl/wolfcrypt/pwdbased.h"
#include <stdio.h>

struct wolfVaultCtx {
    FILE* fd;
    wolfSSL_Mutex lock;
};

#define VAULT_HEADER_ID  0x576F6C66U /* Wolf */
#define VAULT_HEADER_VER 1

#define VAULT_SEC_TYPE_NONE             0 /* no encryption */
#define VAULT_SEC_TYPE_RSA_AESXTS256    1 /* use RSA private key to decrypt the AES symmetric key */
#define VAULT_SEC_TYPE_PBKDF2_AESXTS256 2 /* derive symmetric key using wc_PBKDF2 from password */


typedef struct wolfVaultHeader {
    uint32_t id;
    uint32_t version;
    uint32_t securityType;
    size_t   size;
} wolfVaultHeader;

size_t wolfVaultGetSize(wolfVaultCtx* ctx)
{
    size_t sz = 0;
    if (ctx && fseek(ctx->fd, 0, SEEK_END) == 0) {
        sz = ftell(ctx->fd);
        rewind(ctx->fd);
    }
    return sz;
}

//int wolfVaultDecrypt(wolfVaultCtx* ctx)
/* use the ETSI server RSA private key (WOLFKM_ETSISVC_KEY) to decrypt the AES symmetric key */
//wc_PBKDF2

int wolfVaultOpen(wolfVaultCtx** ctx, const char* file, const char* password)
{
    int ret = 0;
    wolfVaultCtx* ctx_new;
    wolfVaultHeader header;
    size_t fileSize;

    if (ctx == NULL) 
        return WOLFKM_BAD_ARGS;

    ctx_new = (wolfVaultCtx*)malloc(sizeof(wolfVaultCtx));
    if (ctx_new == NULL)
        return WOLFKM_BAD_MEMORY;

    memset(ctx_new, 0, sizeof(wolfVaultCtx));
    wc_InitMutex(&ctx_new->lock);

    /* try opening vault file */
    ctx_new->fd = fopen(file, "rb+");
    if (ctx_new->fd == NULL) {
        /* create vault file */
        ctx_new->fd = fopen(file, "wb+");
        if (ctx_new->fd != NULL) {
            /* write header */
            memset(&header, 0, sizeof(header));
            header.id = VAULT_HEADER_ID;
            header.version = VAULT_HEADER_VER;
            /* TODO: PBKDF2 with VAULT_SEC_TYPE_PBKDF2_AESXTS256 */
            header.securityType = VAULT_SEC_TYPE_NONE;
            (void)password;
            header.size = sizeof(header);
            ret = (int)fwrite(&header, 1, sizeof(header), ctx_new->fd);
            ret = (ret == sizeof(header)) ? 0 : WOLFKM_BAD_FILE;
        }
        else {
            ret = WOLFKM_BAD_FILE;
        }
    }
    else {
        /* read header */
        ret = fread(&header, 1, sizeof(header), ctx_new->fd);
        ret = (ret == sizeof(header)) ? 0 : WOLFKM_BAD_FILE;

        fileSize = wolfVaultGetSize(ctx_new);
    }
    
    /* validate vault */
    if (ret == 0 && header.id != VAULT_HEADER_ID) {
        XLOG(WOLFKM_LOG_ERROR, "Header ID mismatch %u != %u\n",
            VAULT_HEADER_ID, header.id);
        ret = WOLFKM_BAD_FILE;
    }
    if (ret == 0 && header.version != VAULT_HEADER_VER) {
        XLOG(WOLFKM_LOG_ERROR, "Header version mismatch %u != %u\n",
            VAULT_HEADER_VER, header.version);
        ret = WOLFKM_BAD_FILE;
    }
    if (ret == 0 && header.size != fileSize) {
        XLOG(WOLFKM_LOG_ERROR, "Header size does not match actual %lu != %lu\n",
            fileSize, header.size);
        ret = WOLFKM_BAD_FILE;
    }
    
    if (ret == 0) {
        XLOG(WOLFKM_LOG_INFO, "Vault %s opened (%d bytes)\n", file, fileSize);
    }

    if (ret != 0) {
        fclose(ctx_new->fd);
        free(ctx_new);
        ctx_new = NULL;
    }

    /* Derive key based on password */
    *ctx = ctx_new;

    return ret;
}

int wolfVaultAdd(wolfVaultCtx* ctx, const char* name, word32 type,
    const byte* data, word32 dataSz)
{

}

int wolfVaultGet(wolfVaultCtx* ctx, wolfVaultItem* item, const char* name,
    word32 type, byte* data, word32* dataSz)
{
    
}

int wolfVaultFind(wolfVaultCtx* ctx, wolfVaultItem* item, word32 type,
    word32 timestamp)
{

}

int wolfVaultFindNext(wolfVaultCtx* ctx, wolfVaultItem* item, word32 type,
    word32 timestamp)
{

}

int wolfVaultFreeItem(wolfVaultItem* item)
{

}


int wolfVaultDelete(wolfVaultCtx* ctx, const char* name, word32 type)
{
}

int wolfVaultArchive(wolfVaultCtx* ctx, word32 timestamp)
{

}

void wolfVaultClose(wolfVaultCtx* ctx)
{
    if (ctx) {
        wc_FreeMutex(&ctx->lock);
        free(ctx);
    }
}
