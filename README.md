# SimpleLogin Adapter

Web form that turns an alias and a recipient into a SimpleLogin reverse-alias address, then opens Proton Mail with that address in To.

Proton Mail still sends from your Proton mailbox. SimpleLogin rewrites the message so the recipient sees the alias.

## Run

```bash
docker compose up -d
docker compose logs -f
```

The image is `ghcr.io/thenathanspace/simplelogin-contact-creator:latest`. GitHub Actions publishes that name on push to `main`.

Open port 5982. The setup code is in the container log.

A missing or unusable `PORT`, `HOST`, `COOKIE_SECURE`, `SIMPLELOGIN_BASE_URL`, `DATA_DIR`, or `SECRET_PATH` exits the process with one `ERROR` line. `restart: unless-stopped` starts the container again until the setting is fixed. `TZ` unset or unknown stays `Etc/UTC`.

For HTTP without TLS, set `COOKIE_SECURE=0`. A `Secure` cookie is not stored on `http://`.

## First account

The setup page is shown only while no account exists. It asks for the setup code, a username, a password, and a SimpleLogin API key.

| Rule | Detail |
| --- | --- |
| Length | At least 15 characters. No uppercase, digit, or symbol rule. |
| Local list | [SecLists](https://github.com/danielmiessler/SecLists) top 10,000 common passwords (MIT), case-insensitive. |
| Have I Been Pwned | The server sends the first 5 characters of the SHA-1 hash. The password stays on the server. |
| HIBP down | Setup continues. The local list still applies. |

A restart before setup finishes prints a new setup code. The previous code stops working.

The API key is checked with `GET /api/user_info` before it is saved. It is encrypted with AES-256-GCM. The password is stored as an Argon2id hash.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `TZ` | `Etc/UTC` | IANA name for log timestamps, such as `America/Denver`. Unset or unknown stays `Etc/UTC`. |
| `TRUSTED_PROXIES` | empty | Comma-separated proxy addresses allowed to supply `X-Forwarded-For`. |
| `COOKIE_SECURE` | `1` | `0` only for HTTP without TLS. |
| `SIMPLELOGIN_BASE_URL` | `https://app.simplelogin.io` | API host. Set this for a self-hosted SimpleLogin. |
| `DATA_DIR` | `/config/data` in the image | SQLite directory. |
| `SECRET_PATH` | `/config/secret` in the image | AES key file. |
| `PORT` | `5982` | Listen port. |

## Volume

`./simplelogin_contacts` mounts at `/config`.

| Path | Contents |
| --- | --- |
| `/config/data` | SQLite database. Mode `0700` on the directory, `0600` on the file. |
| `/config/secret` | Encryption key. Mode `0600`. |

A copy of `/config/data` does not include the key. A copy of the whole volume does.

## Reverse proxy

Terminate HTTPS in front of port 5982. Send HSTS with `max-age` of at least six months. Set `TRUSTED_PROXIES` to the proxy address. Leave `COOKIE_SECURE` at `1`.

Login is still required.

## Send

Enter the alias and the recipient. The page shows the reverse-alias address and a link that opens Proton Mail with that address in To.

| Result | Behavior |
| --- | --- |
| Alias missing | Created when the address matches an available suffix, on the default verified mailbox. |
| Suffix does not match | No alias is created. The page shows the error. |
| Contact | Created, or the existing reverse alias is returned. |
| Alias disabled | The address is still shown, with a disabled notice. |

The app does not send the message.

## Logs

Stdout. Timestamps use `TZ`.

Startup logs the listen address, the timezone, and either `account exists` or the setup code. Later lines cover setup rejected or saved, login, logout, and each send.

The password, API key, session id, and HIBP prefix are not logged. Successful health checks are not logged.

## Sessions

The cookie is `__Host-session` when `COOKIE_SECURE=1`, and `session` when it is `0`. It is `HttpOnly`, `SameSite=Lax`, `Path=/`, and has no `Domain`. The database stores the SHA-256 hash of the cookie value. A session ends after 14 days without a request.

Five failed logins or five wrong setup codes from one IP within 15 minutes are rejected until that window passes. The IP is the socket peer unless that peer is listed in `TRUSTED_PROXIES`.
