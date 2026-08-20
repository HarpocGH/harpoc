/**
 * A self-signed loopback certificate for the in-process SMTP/IMAP fakes.
 *
 * The core mail fakes present the `fixture.example.com` certificate
 * (`packages/core/src/__fixtures__/certs`), which cannot be exercised through
 * the real `VaultEngine`: the injectors run an SSRF pre-flight
 * (`validateHostPort`) that pins the dialed address, so a `secret.use` can only
 * reach a host that is either loopback (permitted) or publicly resolvable —
 * `fixture.example.com` is neither. Driving the real injector therefore needs a
 * certificate whose identity matches a loopback host the SSRF floor allows.
 *
 * This pair is CN `harpoc-loopback`, SAN `DNS:localhost, IP:127.0.0.1`, valid
 * until 2126. It is embedded (not read from disk) so the fakes are independent
 * of CWD, dist layout and any fixture-path convention. Test-only, and never a
 * trust root anywhere in production — the fakes pin it as the mail group's
 * `tls.ca` for exactly one connection.
 */

/** The host the fakes' certificate is valid for — the `action.host` to use. */
export const LOOPBACK_HOST = "localhost";

export const LOOPBACK_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDMzCCAhugAwIBAgIUcKh7AKn8oa2nCqOWbDzo80JVWqkwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPaGFycG9jLWxvb3BiYWNrMCAXDTI2MDgyMDA4NTU1NFoY
DzIxMjYwNzI3MDg1NTU0WjAaMRgwFgYDVQQDDA9oYXJwb2MtbG9vcGJhY2swggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCu05j6x4/LtSkvQc6GJj0sPhrg
OEKt6toFsvAmDe4kZrbJIrbU4bHXppK49/TsnpIBwrCAPioWxKwrwLc9CknH7EK4
xZ4FFW5QaS5T6Aj/QVguMORy+ZTibqANz3g/TTNAekhQWq5TW8jZV+6aGRxVDsYD
kxZ/cFMyQ8NbtJVDsISAgYbh5E6s9N7vM6t/A80HTo2QTbXT4gQRsRis9sgK0P/q
awWZnLse0Zi3EaDNYWSC8p0OsBbku5fehHW2DELSWnHZ7P7bpGrjlgojAGB3kESO
gcJ1m9d5Nep8/KRSo9jhzg9UF2m2qaYYzCkMo7CT8x9UvDZkSOHLQZXP6swvAgMB
AAGjbzBtMB0GA1UdDgQWBBQmk4DJ6VdEXuEKtdcmno+CzcgzbzAfBgNVHSMEGDAW
gBQmk4DJ6VdEXuEKtdcmno+CzcgzbzAPBgNVHRMBAf8EBTADAQH/MBoGA1UdEQQT
MBGCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAWvNPGcx1vLC+
VwXapK0EvuyN6pUToVv+607H00dMPi9OeeXVsiw8LAjFBc8zbCOGGFbjUvJHy190
ew/yby+HCKdTJZQdFuDYbV5XmwkUkbr+ZakYOm47vLtqLwoXTgNFZtyZTorgqCD/
JB6BtH1l1vrlp8gdLkyU0ZL9b6C9CT+6S0M16tophkleWVoLmUF0+CdjKBJcvD36
kiixJS8DJAIDKStMzFW2iH9W91t41nO9obIUj4645shvD5+SkoK6mB8cwzXxybr1
+lt3+1UNzfVTE8J05td8pkyxlZDitF32UvHmfkRk4KpQ26eQF0JO8uPktsfl8nHH
9+wWAB+F6Q==
-----END CERTIFICATE-----
`;

export const LOOPBACK_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu05j6x4/LtSkv
Qc6GJj0sPhrgOEKt6toFsvAmDe4kZrbJIrbU4bHXppK49/TsnpIBwrCAPioWxKwr
wLc9CknH7EK4xZ4FFW5QaS5T6Aj/QVguMORy+ZTibqANz3g/TTNAekhQWq5TW8jZ
V+6aGRxVDsYDkxZ/cFMyQ8NbtJVDsISAgYbh5E6s9N7vM6t/A80HTo2QTbXT4gQR
sRis9sgK0P/qawWZnLse0Zi3EaDNYWSC8p0OsBbku5fehHW2DELSWnHZ7P7bpGrj
lgojAGB3kESOgcJ1m9d5Nep8/KRSo9jhzg9UF2m2qaYYzCkMo7CT8x9UvDZkSOHL
QZXP6swvAgMBAAECggEAD86O7uG7RSJYmm67QxLTBhyJZot/r+TjmI9QukgZJ45n
6XCrkjzjzQlBC9tTeE9wCRu2xKmaOZvHq18N0kWLXTml4LnxaylAY6HW7/wzUAzy
8Z43EZQyW3TAIO+IwkRzJVnJDwbb6yqJ0ujp6GHr117yFWGnr5cS1qEc2T5PHqMB
VMvOnue8yl61N3GuOsqZul148OMvYsaSI46FYPv77rByIO3dgABJimKqBF8V16is
eIwtzrEz47X3DD7zRxDZgXaTWKANgJvqCIS4008WJh//Ap3w6QTNGavM9mthVZ38
KrI45cfdBBIWIxAe85tEjrn0TmPSgd/MIq1oQHwGmQKBgQDdJnYLjdlnxeJP5bdZ
Tx1cEoczXLpiubUKU6hG2p2AwIFpTcpgDIpZ93fNoFP5TWQFTgcuRkzQKtsC/xFp
T78bmSiMTngmuN8BmIxXDf6KuXZ+qjmAOppB9QDDuCwpKzoLugptiL4XFOGQjv5z
lT6pjXRJfkj6ZWdDmob6bf1dmQKBgQDKYF49qxTUiWL6QrZr9X804jxl31Lwr/Dt
S1hLZR2Y1CJRwGDcQIDkKOAowGqm4nLsBIaU1CN7vXKj2u9Mr2VB6M/ghkbDPXlp
MCIHlgP0Jf903ALO/OoIgLDblf0vcM0zEEnAgvjyCFzo7LS3GSjAhKXjtm5bWkOq
ve+6bbtFBwKBgADLAYNbF9t6ZyxYK4cjdHx/CIMTowt1lQObdzAB2qy6g/xHriEY
Cmr2KzTOjV6Ie4JVXEs7L01TygNBvOM+yPWlX/LY2S9yXEJaNK6fOzluHtGndJtU
GneAFGefQnFHWWbvXNg1tFDK32AwUxNBBr9+5VraHBLhyDQC2tcNC+qJAoGAX/F7
/ESFZZWUpQzHqzsCCbJP7AQKMC1ZTUZxH51agL/hXVyVDxZNhN2UF/3REjk9PoOO
wjQodluEZAZBeNuWZ77V/p3qIlmcm6/EElCeozr4dxBvDG5/DXTlY9Uh6UHTJqhM
LsZo+2XXll3R9xQoa8z3UJOGkiyi8+mEI6AuLjUCgYEA2XNlEdyDxp9f3MmOjXWN
4ofIjeKVlXlxexw6cpFvh8XkZQyTpFrIOHxloXvgNgC5gtfmYvoaaYf65ClLTkqR
6og6Q/Jtgx3HaltV15bMRicBOCAK4rKxq/GlUI08YMltZIWcBWT0ZCAVs5VlB8Xx
W65VPcIR2qhk835fzXxtWb0=
-----END PRIVATE KEY-----
`;
