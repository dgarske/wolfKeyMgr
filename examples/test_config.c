/* test_config.c
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

#include "examples/test_config.h"

static EtsiClientCtx* gEtsiClient = NULL;

/* ETSI Client Helpers */
int test_esti_client_connect(const char* urlStr)
{
    int ret = 0;
    static char urlStrCopy[HTTP_MAX_URI];
    static HttpUrl url;

    /* setup key manager connection */
    if (gEtsiClient == NULL) {
        wolfEtsiClientInit();

        gEtsiClient = wolfEtsiClientNew();
        if (gEtsiClient) {
            wolfEtsiClientAddCA(gEtsiClient, ETSI_TEST_CLIENT_CA);
            wolfEtsiClientSetKey(gEtsiClient,
                ETSI_TEST_CLIENT_KEY, ETSI_TEST_CLIENT_PASS,
                ETSI_TEST_CLIENT_CERT, WOLFSSL_FILETYPE_PEM);

            if (urlStr) {
                strncpy(urlStrCopy, urlStr, HTTP_MAX_URI);
                memset(&url, 0, sizeof(url));
                wolfHttpUrlDecode(&url, urlStrCopy);
            }

            ret = wolfEtsiClientConnect(gEtsiClient, url.domain, url.port,
                ETSI_TEST_TIMEOUT_MS);
            if (ret != 0) {
                printf("Error connecting to ETSI server %s! %d\n", urlStr, ret);
                test_etsi_client_cleanup();
            }
        }
        else {
            ret = WOLFKM_BAD_MEMORY;
        }
    }
    return ret;
}

int test_etsi_client_get(const char* urlStr, EtsiKey* key, int keyType)
{
    int ret;
    const char* keyStr = wolfEtsiKeyGetTypeStr(keyType);
    if (keyStr == NULL) {
        return WOLFKM_NOT_COMPILED_IN;
    }

    ret = test_esti_client_connect(urlStr);
    if (ret == 0 && key != NULL) {
        /* Get and set a static ephemeral for each supported key type */
        ret = wolfEtsiClientGet(gEtsiClient, key, keyType, NULL, NULL,
            ETSI_TEST_TIMEOUT_MS);
        /* positive return means new key returned */
        /* zero means, same key is used */
        /* negative means error */
        if (ret < 0) {
            printf("Error getting ETSI %s static ephemeral key! %d\n", keyStr, ret);
            test_etsi_client_cleanup();
        }
        else if (ret > 0) {
            /* got new key */
            printf("Got ETSI %s static ephemeral key (%d bytes)\n", keyStr, key->responseSz);
            wolfEtsiKeyPrint(key);
        }
        else {
            /* key has not changed */
            printf("ETSI %s Key Cached (valid for %lu sec)\n",
                keyStr, key->expires - wolfGetCurrentTimeT());
        }
    }
    return ret;
}

int test_etsi_client_get_all(const char* urlStr, test_etsi_client_key_cb cb,
    void* cbCtx)
{
    int ret;
    static EtsiKey keyEcc, keyDh, keyX25519;

    /* Get static ephemeral for each supported key type */
    ret = test_etsi_client_get(urlStr, &keyEcc, ETSI_KEY_TYPE_SECP256R1);
    if (ret >= 0 && cb != NULL) {
        ret = cb(&keyEcc, cbCtx);
    }
    if (ret == 0 || ret == WOLFKM_NOT_COMPILED_IN) {
        ret = test_etsi_client_get(urlStr, &keyDh, ETSI_KEY_TYPE_FFDHE_2048);
        if (ret >= 0 && cb != NULL) {
            ret = cb(&keyDh, cbCtx);
        }
    }
    if (ret == 0 || ret == WOLFKM_NOT_COMPILED_IN) {
        ret = test_etsi_client_get(urlStr, &keyX25519, ETSI_KEY_TYPE_X25519);
        if (ret >= 0 && cb != NULL) {
            ret = cb(&keyX25519, cbCtx);
        }
    }
    if (ret > 0 || ret == WOLFKM_NOT_COMPILED_IN) {
        ret = 0; /* success */
    }

    return ret;
}

int test_etsi_client_find(const char* urlStr, EtsiKey* key, int namedGroup,
    const byte* pub, word32 pubSz)
{
    int ret;

    if (key == NULL)
        return BAD_FUNC_ARG;

    ret = test_esti_client_connect(urlStr);
    if (ret == 0) {
        char fpStr[ETSI_MAX_FINGERPRINT_STR];
        word32 fpStrSz = (word32)sizeof(fpStr);

        ret = wolfEtsiCalcTlsFingerprint((EtsiKeyType)namedGroup, pub, pubSz,
            fpStr, &fpStrSz);
        if (ret == 0) {
            ret = wolfEtsiClientFind(gEtsiClient, key, namedGroup, fpStr,
                NULL, ETSI_TEST_TIMEOUT_MS);
        }
        if (ret < 0) {
            printf("Error finding ETSI static ephemeral key! %d\n", ret);
            test_etsi_client_cleanup();
        }
        else {
            printf("Found ETSI static ephemeral key (%d bytes)\n",
                key->responseSz);
            wolfEtsiKeyPrint(key);
        }
        (void)fpStrSz;
    }
    return ret;
}

void test_etsi_client_cleanup(void)
{
    if (gEtsiClient) {
        wolfEtsiClientFree(gEtsiClient);
        gEtsiClient = NULL;

        wolfEtsiClientCleanup();
    }
}
