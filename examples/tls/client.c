/* client.c
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

#include "mod_tls.h"
#include "mod_http.h"
#include "tls_config.h"

int main(int argc, char* argv[])
{
    int ret;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl = NULL;
    HttpRsp rsp;
    byte data[TLS_TEST_MAX_DATA];
    int dataSz = (int)sizeof(data);
    
    wolfSSL_Init();

    /* log setup */
    //wolfSSL_Debugging_ON();
    wolfKeyMgr_SetLogFile(NULL, 0, WOLFKM_LOG_DEBUG);

    ctx = wolfTlsClientNew();
    if (ctx == NULL) { ret = WOLFKM_BAD_MEMORY; goto exit; }

    ret = wolfTlsAddCA(ctx, TLS_TEST_CA);
    if (ret != 0) goto exit;

    printf("TLS Connect %s:%d\n", TLS_TEST_HOST, TLS_TEST_PORT);
    ret = wolfTlsConnect(ctx, &ssl, TLS_TEST_HOST, TLS_TEST_PORT,
        TLS_TEST_TIMEOUT_SEC);
    if (ret != 0) goto exit;

    dataSz = (int)sizeof(data);
    ret = wolfHttpClient_EncodeRequest(HTTP_METHOD_GET, TEST_HTTP_GET_REQUEST,
        data, (word32*)&dataSz, NULL, 0);
    if (ret != 0) goto exit;
    printf("HTTPS Sending: %s\n", data);

    ret = wolfTlsWrite(ssl, data, dataSz);
    if (ret < 0) goto exit;

    dataSz = (int)sizeof(data);
    ret = wolfTlsRead(ssl, data, &dataSz, TLS_TEST_TIMEOUT_SEC);
    if (ret < 0) goto exit;

    ret = wolfHttpClient_ParseResponse(&rsp, (char*)data, dataSz);
    if (ret != 0) goto exit;

    wolfHttpResponsePrint(&rsp);
    /* print body */
    printf("%s\n", rsp.body);

exit:

    if (ret < 0) {
        printf("TLS Client Error %d: %s\n", ret, wolfTlsGetErrorStr(ret));
    }

    if (ssl)
        (void)wolfTlsClose(ssl, ret == 0 ? 1 : 0);

    if (ctx)
        wolfTlsFree(ctx);

    wolfSSL_Cleanup();

    return ret;
}
