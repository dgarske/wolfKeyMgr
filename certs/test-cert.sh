#!/bin/bash

# Script to generated a self-signed TLS server certificate
# test-key.pem password is "wolfssl"

openssl req -new -x509 -nodes -key test-key.pem -out test-cert.pem -sha256 -days 7300 -batch -subj "/C=US/ST=CA/L=Seattle/O=wolfSSL/OU=Development/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"
