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

int wolfVaultOpen(wolfVault_t* ctx, const char* file, const char* password)
{
    (void)ctx;
    (void)file;
    (void)password;
    return 0;
}

#if 0
int wolfVaultAdd()
int wolfVaultDel()
int wolfVaultGetFirst()
int wolfVaultGetNext()
#endif

int wolfVaultClose(wolfVault_t* ctx)
{
    (void)ctx;
    return 0;
}
