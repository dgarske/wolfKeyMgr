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

int main(int argc, char** argv)
{
    int ret;
    enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;
    wolfVaultCtx* ctx = NULL;

    /* log setup */
    wolfKeyMgr_SetLogFile(NULL, 0, logLevel);
    printf("Key Manager Unit Test\n");

    ret = wolfVaultOpen(&ctx, "vault.bin", "password");

    printf("Vault Open Test: %s\n", ret == 0 ? "pass" : "fail");

    wolfVaultClose(ctx);

    return ret;
}
