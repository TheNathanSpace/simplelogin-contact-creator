# Status

Last updated: 2026-11-10 — default listen port 5982.

Latest change: Default port is 5982 in the app, image, and compose file. Compose image is lowercase. Service, container, and volume are `simplelogin_contacts`.

## State

| ID | State |
| --- | --- |
| AUTH-01 | Done |
| AUTH-02 | Done |
| AUTH-03 | Done |
| AUTH-04 | Done |
| AUTH-05 | Done |
| SEND-01 | Done |
| SEND-02 | Done |
| OPS-01 | Done |
| OPS-02 | Done |
| OPS-03 | Done |
| OPS-04 | Done |
| OPS-05 | Done |

## UI

| Path | Page |
| --- | --- |
| `/setup` | First account. Absent after the account exists. |
| `/login` | Username and password. |
| `/send` | Alias, recipient, reverse alias, Proton Mail link. |
| `/health` | Process check. No login. |

## Next session

Run setup from the code in the container log.

The API key and password cannot be changed in the app. A new database is required.
