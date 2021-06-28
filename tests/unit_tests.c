/* api.c
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

static int vault_test(void)
{
    int ret;
    wolfVaultCtx* ctx = NULL;
    wolfVaultItem item;
    const char* testFile = "vault.bin";
    const char* testPass = "password";
    const char* testName = "testname";
    const char* testData = "testdata";
    word32 testType = 1;

    ret = wolfVaultOpen(&ctx, testFile, testPass);
    if (ret == 0) {
        ret = wolfVaultAdd(ctx, testName, testType,
            (const byte*)testData, strlen(testData)+1);
        if (ret == 0) {
            ret = wolfVaultGet(ctx, &item, testName, testType);
            if (ret == 0) {
                if (memcmp(item.data, testData, strlen(testData)+1) != 0) {
                    printf("Vault item data test failed\n");
                    ret = -1;
                }
                wolfVaultFreeItem(&item);
            }
        }

        wolfVaultClose(ctx);
    }
    return ret;
}

int main(int argc, char** argv)
{
    int ret;
    enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;

    /* log setup */
    wolfKeyMgr_SetLogFile(NULL, 0, logLevel);
    printf("Key Manager Unit Test\n");

    ret = vault_test();
    printf("Vault Open Test: %s\n", ret == 0 ? "pass" : "fail");


    return ret;
}
