/* tls_config.h
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

#ifndef TLS_CONFIG_H
#define TLS_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#define TLS_TEST_HOST        "localhost"
#define TLS_TEST_PORT        11111
#define TLS_TEST_TIMEOUT_SEC 30
#define TLS_TEST_MAX_DATA    512

/* see ./certs/test-cert.sh for generation and signing */
/* this is a self signed test cert server presents */
#define TLS_TEST_CA          "certs/test-cert.pem"
#define TLS_TEST_CERT        "certs/test-cert.pem"
#define TLS_TEST_KEY         "certs/test-key.pem"

#ifdef __cplusplus
}
#endif

#endif /* TLS_CONFIG_H */
