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


#define VAULT_HEADER_ID  0x576F6C66U /* Wolf */
#define VAULT_HEADER_VER 1

#define VAULT_SEC_TYPE_NONE             0 /* no encryption */
#define VAULT_SEC_TYPE_RSA_AESXTS256    1 /* use RSA private key to decrypt the AES symmetric key */
#define VAULT_SEC_TYPE_PBKDF2_AESXTS256 2 /* derive symmetric key using wc_PBKDF2 from password */

/* setup a callback function for the key - or encrypt / decrypt  */
/* feature: HMAC of file or just hash */
/* feature: index file to improve ky search time */

/* Packed struct version of header stored */
typedef struct VaultHeader {
    uint32_t id;
    uint32_t version;
    uint32_t securityType;
    size_t   size;
    uint8_t  keyEncrypted[32];
    uint8_t  hash[16]; /* SHA256 hash of entire file */
} VaultHeader_t;

typedef struct VaultItem {
    char        name[WOLFKM_VAULT_NAME_MAX_SZ]; /* name is hash of public key or leading bits from it */
    word32      type;
    time_t      timestamp;
    size_t      headerPos; /* position for start of header */
    size_t      dataSz;
} VaultItem_t;

struct wolfVaultCtx {
    FILE*          fd;
    wolfSSL_Mutex  lock;
    VaultHeader_t  header;
    VaultItem_t    item; /* cache last item */
};

size_t wolfVaultGetSize(wolfVaultCtx* ctx)
{
    size_t sz = 0;
    if (ctx && fseek(ctx->fd, 0, SEEK_END) == 0) {
        sz = ftell(ctx->fd);
        rewind(ctx->fd);
    }
    return sz;
}

#if 0
static int wolfVaultDecrypt(wolfVaultCtx* ctx)
{
    /* VAULT_SEC_TYPE_RSA_AESXTS256: 
     * use the ETSI server RSA private key (WOLFKM_ETSISVC_KEY) 
     * to decrypt the AES symmetric key 
     */

    /* VAULT_SEC_TYPE_PBKDF2_AESXTS256:
     * wc_PBKDF2
     */
}
#endif

int wolfVaultOpen(wolfVaultCtx** ctx, const char* file, const char* password)
{
    int ret = 0;
    wolfVaultCtx* ctx_new;
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
            memset(&ctx_new->header, 0, sizeof(ctx_new->header));
            ctx_new->header.id = VAULT_HEADER_ID;
            ctx_new->header.version = VAULT_HEADER_VER;
            /* TODO: PBKDF2 with VAULT_SEC_TYPE_PBKDF2_AESXTS256 */
            ctx_new->header.securityType = VAULT_SEC_TYPE_NONE;
            (void)password;
            ctx_new->header.size = sizeof(ctx_new->header);
            ret = (int)fwrite(&ctx_new->header, 1, sizeof(ctx_new->header), ctx_new->fd);
            ret = (ret == sizeof(ctx_new->header)) ? 0 : WOLFKM_BAD_FILE;
        }
        else {
            ret = WOLFKM_BAD_FILE;
        }
    }
    else {
        /* read header */
        ret = fread(&ctx_new->header, 1, sizeof(ctx_new->header), ctx_new->fd);
        ret = (ret == sizeof(ctx_new->header)) ? 0 : WOLFKM_BAD_FILE;

        fileSize = wolfVaultGetSize(ctx_new);
    }
    
    /* validate vault */
    if (ret == 0 && ctx_new->header.id != VAULT_HEADER_ID) {
        XLOG(WOLFKM_LOG_ERROR, "Header ID mismatch %u != %u\n",
            VAULT_HEADER_ID, ctx_new->header.id);
        ret = WOLFKM_BAD_FILE;
    }
    if (ret == 0 && ctx_new->header.version != VAULT_HEADER_VER) {
        XLOG(WOLFKM_LOG_ERROR, "Header version mismatch %u != %u\n",
            VAULT_HEADER_VER, ctx_new->header.version);
        ret = WOLFKM_BAD_FILE;
    }
    if (ret == 0 && ctx_new->header.size != fileSize) {
        XLOG(WOLFKM_LOG_ERROR, "Header size does not match actual %lu != %lu\n",
            fileSize, ctx_new->header.size);
        ret = WOLFKM_BAD_FILE;
    }
    
    if (ret == 0) {
        XLOG(WOLFKM_LOG_INFO, "Vault %s opened (%lu bytes)\n", file, fileSize);
    }
    else {
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
    int ret;

    if (ctx == NULL)
        return WOLFKM_BAD_ARGS;
    
    ret = wc_LockMutex(&ctx->lock);
    if (ret != 0)
        return ret;

    memset(&ctx->item, 0, sizeof(ctx->item));
    strncpy(ctx->item.name, name, sizeof(ctx->item.name));
    ctx->item.type = type;
    ctx->item.timestamp = wolfGetCurrentTimeT();
    ctx->item.dataSz = dataSz;

    ret = fseek(ctx->fd, 0, SEEK_END);
    if (ret == 0) {
        ctx->item.headerPos = ftell(ctx->fd);

        ret = (int)fwrite(&ctx->item, 1, sizeof(ctx->item), ctx->fd);
        ret = (ret == (int)sizeof(ctx->item)) ? 0 : WOLFKM_BAD_FILE;
    }
    if (ret == 0) {
        ret = (int)fwrite(data, 1, dataSz, ctx->fd);
        ret = (ret == dataSz) ? 0 : WOLFKM_BAD_FILE;        
    }
    if (ret == 0) {
        ctx->header.size += sizeof(ctx->item) + dataSz;
        /* TODO: Extend SHA or HMAC */
    }
    wc_UnLockMutex(&ctx->lock);
    return ret;
}

int wolfVaultGet(wolfVaultCtx* ctx, wolfVaultItem* item, const char* name,
    word32 type)
{
    int ret;
    if (ctx == NULL || item == NULL)
        return WOLFKM_BAD_ARGS;

    memset(item, 0, sizeof(*item));

    ret = wc_LockMutex(&ctx->lock);
    if (ret != 0)
        return ret;

    /* If last item is a match... use it */
    if (ctx->item.type == type && 
        (strncmp(ctx->item.name, name, sizeof(ctx->item.name)) == 0))
    {
        strncpy(item->name, name, sizeof(item->name));
        item->type = type;
        item->timestamp = ctx->item.timestamp;
        item->size = ctx->item.dataSz;
        ret = fseek(ctx->fd, ctx->item.headerPos + sizeof(VaultItem_t), SEEK_SET);
        if (ret != 0)
            ret = WOLFKM_BAD_MEMORY;
        if (ret == 0) {
            item->data = malloc(item->size);
            if (item->data == NULL)
                ret = WOLFKM_BAD_MEMORY;
        }
        if (ret == 0) {
            ret = (int)fread(item->data, 1, item->size, ctx->fd);
            ret = (ret == item->size) ? 0 : WOLFKM_BAD_FILE;
        }
    }
    else {
        /* TODO: Find item */
    }

    /* on error release allocated memory */
    if (ret != 0 && item->data) {
        free(item->data);
        item->data = NULL;
    }
    
    wc_UnLockMutex(&ctx->lock);
    return ret;
}

int wolfVaultFind(wolfVaultCtx* ctx, wolfVaultItem* item, word32 type,
    word32 timestamp)
{
    /* TODO: Implement find */
    (void)ctx;
    (void)item;
    (void)type;
    (void)timestamp;
    return WOLFKM_BAD_ARGS;
}

int wolfVaultFindNext(wolfVaultCtx* ctx, wolfVaultItem* item, word32 type,
    word32 timestamp)
{
    /* TODO: Implement find next */
    (void)ctx;
    (void)item;
    (void)type;
    (void)timestamp;
    return WOLFKM_BAD_ARGS;
}

int wolfVaultFreeItem(wolfVaultItem* item)
{
    if (item && item->data != NULL) {
        free(item->data);
        item->data = NULL;
    }
    return 0;
}

int wolfVaultDelete(wolfVaultCtx* ctx, const char* name, word32 type)
{
    /* TODO: Implement delete */
    (void)ctx;
    (void)name;
    (void)type;
    return WOLFKM_BAD_ARGS;
}

int wolfVaultArchive(wolfVaultCtx* ctx, word32 timestamp)
{
    /* TODO: Implement archive */
    (void)ctx;
    (void)timestamp;
    return WOLFKM_BAD_ARGS;
}

void wolfVaultClose(wolfVaultCtx* ctx)
{
    if (ctx) {
        wc_FreeMutex(&ctx->lock);
        free(ctx);
    }
}
