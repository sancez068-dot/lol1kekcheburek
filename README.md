# KM2.0 License API — Python 3.12.11 / FastAPI

Admin panel + PostgreSQL-backed license activation/validation API.

## Deploy to Render
1. Keep the ZIP and repository private. The included `.env` contains a generated admin password and the key-hashing secret.
2. Upload this directory, including `.env`, to a **private GitHub repository**.
3. In Render choose **New → Blueprint**, select the repository and apply `render.yaml`.
4. Render provisions PostgreSQL and sets `DATABASE_URL` automatically. That environment variable takes precedence over the SQLite fallback in `.env`; no manual environment variables are needed.
5. Wait for the health check to pass. Open `https://lol1kekcheburek.onrender.com/admin`.
6. Admin username is `admin`. The initial password is in `.env` as `ADMIN_PASSWORD`.

**Security warning:** because you requested zero manual configuration, the initial credentials are bundled in `.env`. Never publish this repository or ZIP publicly, and change `ADMIN_PASSWORD` after first login if you can set it in Render. Keep `KEY_PEPPER` stable after creating keys; rotating it invalidates existing license hashes. PostgreSQL is persistent; the SQLite URL is only a local fallback.

## API
`POST /api/activate`
```json
{"key":"KM20-...","deviceId":"stable-app-scoped-device-id","deviceLabel":"optional"}
```
Binds a key to the first device ID that successfully activates it.

`POST /api/validate`
```json
{"key":"KM20-...","deviceId":"stable-app-scoped-device-id"}
```
Returns `200 {"ok":true,"status":"active","expiresAt":...}` if active, unexpired, and bound to the same device. Invalid, expired, revoked, or mismatched keys return HTTP 403.

Admin endpoints use HTTP Basic auth over HTTPS:
- `POST /api/admin/keys` JSON `{"hours":0,"days":30,"note":"optional"}` (set exactly one duration nonzero; both zero means unlimited)
- `GET /api/admin/keys`
- `DELETE /api/admin/keys/{id}` (revoke)
- `POST /api/admin/keys/{id}/reset-device`
- `PATCH /api/admin/keys/{id}/note` JSON `{"note":"..."}`

## Important client integration notes
- First launch: ask for key, call `/api/activate`, then store the key and app-scoped device ID using Android Keystore-backed encrypted storage where available.
- Subsequent launches: do not show the key prompt again while the locally stored key is present; call `/api/validate` silently. Re-prompt if the server returns 403.
- For strict online revocation, don't enable licensed features if validation fails due to network/server errors. If offline grace is desired, design a short signed lease explicitly; don't silently treat network failure as success.
- The server cannot stop a modified APK from deleting its own local check. For critical resources, enforce entitlement on the server.
- Client-provided device IDs can be spoofed by a modified client. Consider Android Play Integrity if distribution/signing supports it.
- The in-memory throttle is per process. For multiple replicas, add an edge/WAF rate limit. Never log keys or send them to analytics.
- `/docs` and `/openapi.json` are disabled in production.
