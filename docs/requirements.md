# Requirements

| ID | Requirement | State |
| --- | --- | --- |
| AUTH-01 | The first visit creates the only account: setup code, username, password, and SimpleLogin API key. The setup page is not shown after the account exists. | Done |
| AUTH-02 | The setup code is at least 128 bits, printed once at startup, and stored only as a hash. Wrong codes share the login throttle. | Done |
| AUTH-03 | Passwords are at least 15 characters, blocked by a local common-password list, and checked with Have I Been Pwned by SHA-1 prefix. HIBP failure fails open. | Done |
| AUTH-04 | Passwords are stored as Argon2id. The API key is stored as AES-256-GCM ciphertext. The key file is outside the database directory. | Done |
| AUTH-05 | Sessions are server-side, idle out after 14 days, and use an `HttpOnly` `SameSite=Lax` cookie. State-changing forms send a CSRF token. | Done |
| SEND-01 | An exact alias match is used. A missing alias is created when a suffix fits. The contact create is idempotent. | Done |
| SEND-02 | The page shows `reverse_alias_address` and opens Proton Mail with that address in To. | Done |
| OPS-01 | `docker-compose.yaml` runs `simplelogin_adapter` on port 4189 with the `./simplelogin_adapter` volume and a health check. | Done |
| OPS-02 | `TZ` is an IANA name. Unset stays `Etc/UTC`. | Done |
| OPS-03 | Logs go to stdout and omit the password, API key, session id, and HIBP prefix. | Done |
| OPS-04 | GitHub Actions builds the image and pushes `:latest` and `:<git sha>` to GHCR on push to `main`. | Done |
| OPS-05 | An empty or unusable `PORT`, `HOST`, `COOKIE_SECURE`, `SIMPLELOGIN_BASE_URL`, `DATA_DIR`, or `SECRET_PATH` exits with one error line. | Done |

There is no test suite.

Replacing the API key or the password is not supported. Delete the database and the secret file, then create the account again.
