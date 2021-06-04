# TLS Examples

These examples demonstrate a basic HTTPS server and client for testing the ETSI middle box decryption with the wolf Key Manager tool.

## TlS Server

Usage: `./examples/tls/server`

```
TLS Server: Port 443
TLS Accept 127.0.0.1
Jun 04 13:51:27 2021: [DEBUG] HTTP GET
Jun 04 13:51:27 2021: [DEBUG] 	Version: HTTP/1.1
Jun 04 13:51:27 2021: [DEBUG] 	URI: /
Jun 04 13:51:27 2021: [DEBUG] 	Headers: 1
Jun 04 13:51:27 2021: [DEBUG] 		Host: : localhost
```

Note: Chrome limits use of self-signed certificates with localhost. You can use `chrome://flags/#allow-insecure-localhost` in chrome to enable support.

