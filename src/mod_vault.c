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

#ifdef WOLFKM_VAULT

#define VAULT_HEADER_ID  0x666C6F57U /* Wolf - little endian */
#define VAULT_ITEM_ID    0x6B636150U /* Pack - little endian */
#define VAULT_HEADER_VER 1

/* struct stored to file */
typedef struct VaultHeader {
    uint32_t id;           /* should be VAULT_HEADER_ID */
    uint32_t version;      /* should be VAULT_HEADER_VER */
    uint32_t headerSz;     /* size of header including id/version */

    uint32_t securityType; /* see VAULT_SEC_TYPE_* */
    uint32_t vaultCount;   /* number of items in vault */
    size_t   vaultSz;      /* size not including header */
    uint8_t  keyEnc[32];   /* encrypted key */
    uint8_t  hash[16];     /* hash or hmac of vault file */
} VaultHeader_t;

typedef struct VaultItem {
    uint32_t id;           /* should be VAULT_ITEM_ID */
    uint32_t type;
    uint32_t nameSz;
    uint32_t dataSz;
    time_t   timestamp;
    uint8_t  name[WOLFKM_VAULT_NAME_MAX_SZ]; /* actual size stored is nameSz */
    /* then data */
} VaultItem_t;

#define VAULT_ITEM_PRE_SZ()      (sizeof(VaultItem_t) -  WOLFKM_VAULT_NAME_MAX_SZ)
#define VAULT_ITEM_HEAD_SZ(item) (VAULT_ITEM_PRE_SZ() + (item)->nameSz)
#define VAULT_ITEM_SZ(item)      (VAULT_ITEM_HEAD_SZ(item) + (item)->dataSz)

struct wolfVaultCtx {
    FILE*          fd;
    wolfSSL_Mutex  lock;
    VaultHeader_t  header;
    VaultItem_t    item;    /* cached last item */
    size_t         itemPos; /* cached last item position in file */
};

static size_t wolfVaultGetSize(wolfVaultCtx* ctx)
{
    size_t sz = 0;
    if (ctx && fseek(ctx->fd, 0, SEEK_END) == 0) {
        sz = ftell(ctx->fd);
        rewind(ctx->fd);
    }
    return sz;
}

int wolfVaultOpen(wolfVaultCtx** ctx, const char* file)
{
    int ret = 0;
    wolfVaultCtx* ctx_new;
    size_t vaultSz;

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
            memset(&ctx_new->header, 0, sizeof(VaultHeader_t));
            ctx_new->header.id = VAULT_HEADER_ID;
            ctx_new->header.version = VAULT_HEADER_VER;
            ctx_new->header.headerSz = sizeof(VaultHeader_t);
            ctx_new->header.securityType = VAULT_SEC_TYPE_NONE;
            ret = (int)fwrite(&ctx_new->header, 1, sizeof(VaultHeader_t),
                ctx_new->fd);
            ret = (ret == sizeof(VaultHeader_t)) ? 0 : WOLFKM_BAD_FILE;
            vaultSz = 0;
        }
        else {
            ret = WOLFKM_BAD_FILE;
        }
    }
    else {
        byte* headPtr = (byte*)&ctx_new->header;
        uint32_t headSz = (uint32_t)sizeof(uint32_t)*3;

        /* read header - front (id, version and size) */
        ret = fread(headPtr, 1, headSz, ctx_new->fd);
        ret = (ret == headSz) ? 0 : WOLFKM_BAD_FILE;
        headPtr += headSz;

        /* validate vault header */
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

        if (ret == 0 && ctx_new->header.headerSz > sizeof(VaultHeader_t)) {
            XLOG(WOLFKM_LOG_ERROR, "Header size invalid! %u != %u\n",
                (uint32_t)sizeof(VaultHeader_t), ctx_new->header.headerSz);
            ret = WOLFKM_BAD_FILE;
        }

        /* read remainder */
        headSz = ctx_new->header.headerSz-headSz;
        ret = (int)fread(headPtr, 1, headSz, ctx_new->fd);
        ret = (ret == headSz) ? 0 : WOLFKM_BAD_FILE;

        vaultSz = wolfVaultGetSize(ctx_new);
        if (vaultSz > ctx_new->header.headerSz)
            vaultSz -= ctx_new->header.headerSz;
        if (ret == 0 && ctx_new->header.vaultSz != vaultSz) {
            XLOG(WOLFKM_LOG_ERROR, "Vault size does not match actual %lu != %lu\n",
                vaultSz, ctx_new->header.vaultSz);
            ret = WOLFKM_BAD_FILE;
        }
    }

    if (ret == 0) {
        XLOG(WOLFKM_LOG_INFO, "Vault %s opened (%lu bytes)\n", file, vaultSz);
    }
    else {
        fclose(ctx_new->fd);
        free(ctx_new);
        ctx_new = NULL;
    }

    *ctx = ctx_new;

    return ret;
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
/* TODO: PBKDF2 with VAULT_SEC_TYPE_PBKDF2_AESXTS256 */
            ctx_new->header.securityType = VAULT_SEC_TYPE_NONE;
            (void)password;
    /* Derive key based on password */
#endif

int wolfVaultAuth(wolfVaultCtx* ctx, word32 secType, const char* fileOrPassword)
{
    (void)ctx;
    (void)secType;
    (void)fileOrPassword;
    return 0;
}

int wolfVaultAuthCb(wolfVaultCtx* ctx, word32 secType, VaultAuthCbFunc cb)
{
    (void)ctx;
    (void)secType;
    (void)cb;
    return 0;
}

int wolfVaultAdd(wolfVaultCtx* ctx, word32 type, const byte* name, word32 nameSz,
    const byte* data, word32 dataSz)
{
    int ret;
    word32 headSz;

    if (ctx == NULL)
        return WOLFKM_BAD_ARGS;
    
    ret = wc_LockMutex(&ctx->lock);
    if (ret != 0)
        return ret;

    memset(&ctx->item, 0, sizeof(VaultItem_t));
    if (nameSz > WOLFKM_VAULT_NAME_MAX_SZ)
        nameSz = WOLFKM_VAULT_NAME_MAX_SZ;
    ctx->item.id = VAULT_ITEM_ID;
    ctx->item.type = type;
    ctx->item.nameSz = nameSz;
    memcpy(ctx->item.name, name, nameSz);
    ctx->item.timestamp = wolfGetCurrentTimeT();
    ctx->item.dataSz = dataSz;
    headSz = (word32)VAULT_ITEM_HEAD_SZ(&ctx->item);

    ret = fseek(ctx->fd, 0, SEEK_END);
    if (ret == 0) {
        ctx->itemPos = ftell(ctx->fd);

        ret = (int)fwrite(&ctx->item, 1, headSz, ctx->fd);
        ret = (ret == (int)headSz) ? 0 : WOLFKM_BAD_FILE;
    }
    if (ret == 0) {
        ret = (int)fwrite(data, 1, dataSz, ctx->fd);
        ret = (ret == dataSz) ? 0 : WOLFKM_BAD_FILE;        
    }
    if (ret == 0) {
        ctx->header.vaultCount++;
        ctx->header.vaultSz += headSz + dataSz;
        /* TODO: Extend SHA or HMAC */
    }
    wc_UnLockMutex(&ctx->lock);
    return ret;
}

static int wolfVaultGetItemHeader(wolfVaultCtx* ctx, size_t itemPos)
{
    int ret = fseek(ctx->fd, itemPos, SEEK_SET);
    word32 headSz = VAULT_ITEM_PRE_SZ();
    if (ret == 0) {
        /* read pre-header */
        ret = (int)fread(&ctx->item, 1, headSz, ctx->fd);
        ret = (ret == (int)headSz) ? 0 : WOLFKM_BAD_FILE;
    }
    if (ret == 0 && ctx->item.id != VAULT_ITEM_ID) {
        ret = WOLFKM_BAD_FILE;
    }
    if (ret == 0) {
        if (ctx->item.nameSz > WOLFKM_VAULT_NAME_MAX_SZ)
            ctx->item.nameSz = WOLFKM_VAULT_NAME_MAX_SZ;
        /* read name */
        ret = (int)fread(&ctx->item.name, 1, ctx->item.nameSz, ctx->fd);
        ret = (ret == (int)ctx->item.nameSz) ? 0 : WOLFKM_BAD_FILE;
    }
    if (ret == 0) {
        ctx->itemPos = itemPos; /* store last cached position */
    }
    return ret;
}

static int wolfVaultGetItemData(wolfVaultCtx* ctx, wolfVaultItem* item)
{
    int ret = 0;

    /* populate header */
    memset(item, 0, sizeof(wolfVaultItem));
    item->type = ctx->item.type;
    item->nameSz = ctx->item.nameSz;
    if (item->nameSz > WOLFKM_VAULT_NAME_MAX_SZ)
        item->nameSz = WOLFKM_VAULT_NAME_MAX_SZ;
    memcpy(item->name, ctx->item.name, item->nameSz);
    item->timestamp = ctx->item.timestamp;
    item->dataSz = ctx->item.dataSz;
    item->data = malloc(item->dataSz);
    if (item->data == NULL)
        ret = WOLFKM_BAD_MEMORY;
    if (ret == 0) {
        ret = (int)fread(item->data, 1, item->dataSz, ctx->fd);
        ret = (ret == item->dataSz) ? 0 : WOLFKM_BAD_FILE;
    }
    /* on error release allocated memory */
    if (ret != 0 && item->data) {
        free(item->data);
        item->data = NULL;
    }
    return ret;
}

int wolfVaultGet(wolfVaultCtx* ctx, wolfVaultItem* item, word32 type,
    const byte* name, word32 nameSz)
{
    int ret;
    size_t itemPos;
    int rolloverCount = 0;

    if (ctx == NULL || item == NULL)
        return WOLFKM_BAD_ARGS;

    ret = wc_LockMutex(&ctx->lock);
    if (ret != 0)
        return ret;

    itemPos = ctx->itemPos; /* start from last cached position */
    while (ret == 0) {
        ret = wolfVaultGetItemHeader(ctx, itemPos);
        if (ret == 0) {
            if (ctx->item.type == type && ctx->item.nameSz == nameSz &&
                (memcmp(ctx->item.name, name, ctx->item.nameSz) == 0)) {
                /* found item, get data and return */
                ret = wolfVaultGetItemData(ctx, item);
                break;
            }
        }

        /* skip to next item */
        itemPos += VAULT_ITEM_SZ(&ctx->item);
        /* check if at end of file */
        if (itemPos > ctx->header.headerSz + ctx->header.vaultSz) {
            if (rolloverCount++ > 1) {
                ret = WOLFKM_BAD_FILE; /* not found */
                break;
            }
            itemPos = ctx->header.headerSz; /* reset to top of data */
        }
    };
    
    wc_UnLockMutex(&ctx->lock);
    return ret;
}

int wolfVaultFind(wolfVaultCtx* ctx, wolfVaultItem* item, word32 type,
    word32 timestamp)
{
    int ret;

    if (ctx == NULL || item == NULL)
        return WOLFKM_BAD_ARGS;

    ret = wc_LockMutex(&ctx->lock);
    if (ret != 0)
        return ret;

    /* TODO: Implement find */
    (void)ctx;
    (void)item;
    (void)type;
    (void)timestamp;
    wc_UnLockMutex(&ctx->lock);
    return WOLFKM_BAD_ARGS;
}

int wolfVaultFindNext(wolfVaultCtx* ctx, wolfVaultItem* item, word32 type,
    word32 timestamp)
{
    int ret;

    if (ctx == NULL || item == NULL)
        return WOLFKM_BAD_ARGS;

    ret = wc_LockMutex(&ctx->lock);
    if (ret != 0)
        return ret;

    /* TODO: Implement find next */
    (void)ctx;
    (void)item;
    (void)type;
    (void)timestamp;
    wc_UnLockMutex(&ctx->lock);
    return WOLFKM_BAD_ARGS;
}

void wolfVaultFreeItem(wolfVaultItem* item)
{
    if (item && item->data != NULL) {
        free(item->data);
        item->data = NULL;
    }
}

int wolfVaultDelete(wolfVaultCtx* ctx, word32 type, const byte* name,
    word32 nameSz)
{
    int ret;

    if (ctx == NULL || name == NULL)
        return WOLFKM_BAD_ARGS;

    ret = wc_LockMutex(&ctx->lock);
    if (ret != 0)
        return ret;

    /* TODO: Implement delete */
    (void)ctx;
    (void)name;
    (void)type;
    wc_UnLockMutex(&ctx->lock);
    return WOLFKM_BAD_ARGS;
}

int wolfVaultArchive(wolfVaultCtx* ctx, word32 timestamp)
{
    int ret;

    if (ctx == NULL)
        return WOLFKM_BAD_ARGS;

    ret = wc_LockMutex(&ctx->lock);
    if (ret != 0)
        return ret;

    /* TODO: Implement archive */
    (void)ctx;
    (void)timestamp;
    wc_UnLockMutex(&ctx->lock);
    return WOLFKM_BAD_ARGS;
}

void wolfVaultClose(wolfVaultCtx* ctx)
{
    int ret;

    if (ctx == NULL)
        return;

    ret = wc_LockMutex(&ctx->lock);
    if (ret == 0) {
        /* update with final header */
        fseek(ctx->fd, 0, SEEK_SET);
        ret = (int)fwrite(&ctx->header, 1, sizeof(ctx->header), ctx->fd);
        ret = (ret == sizeof(ctx->header)) ? 0 : WOLFKM_BAD_FILE;

        wc_UnLockMutex(&ctx->lock);
    }

    fclose(ctx->fd);
    wc_FreeMutex(&ctx->lock);
    free(ctx);
}

void wolfVaultPrintInfo(wolfVaultCtx* ctx)
{
    if (ctx == NULL)
        return;

    XLOG(WOLFKM_LOG_INFO, "Version: %d\n", ctx->header.version);
    XLOG(WOLFKM_LOG_INFO, "Header Size: %d\n", ctx->header.headerSz);
    XLOG(WOLFKM_LOG_INFO, "Security Type: %d\n", ctx->header.securityType);
    XLOG(WOLFKM_LOG_INFO, "Item Count: %d\n", ctx->header.vaultCount);
    XLOG(WOLFKM_LOG_INFO, "Total Size: %lu\n", ctx->header.vaultSz);    
}

#endif /* WOLFKM_VAULT */
