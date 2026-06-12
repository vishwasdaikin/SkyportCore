# Frontend Handoff — Skyport-Core Auth Hardening

For the **SkyportHome** SPA agent. This captures the behavioral changes from the
Skyport-Core auth remediation. The `/auth/me` **response shape and status codes are
unchanged** — the contract still passes — but a few behaviors changed that the SPA must
absorb.

## TL;DR — what the SPA must do

1. Treat **HTTP 401 from any Core call** (`/auth/me`, `/smartsheet/sheet`, future APIs) as
   "session is gone → redirect to `/auth/login`". Centralize this in one shared fetch wrapper.
2. **Sign out only via `POST /auth/logout`** (the form-POST + 303 you already use). `GET`
   is no longer supported.
3. Expect **shorter sessions** (8h default vs the old 7d), so 401s will happen mid-session
   more often. The shared 401 handler above covers this.
4. Treat `role` as **UI-only**; Core enforces authorization server-side.

## Unchanged (no action needed)

- `GET /auth/me` still returns:
  - Authenticated: `200 { "authenticated": true, "user": { "sub", "email", "name", "role" } }`
  - Unauthenticated/expired/invalid: `401 { "authenticated": false }`
- `GET /auth/login?returnTo=...&prompt=login` still starts the OAuth redirect.
- Session is still an httpOnly cookie (`skyport_session`); JS never reads a token.
- All calls still use `credentials: 'include'`.
- `?auth_error=access_denied&detail=...` on disallowed sign-in still works.

## Changes the SPA must absorb

### 1. 401 is now the single source of truth for "logged out"
Sessions are shorter and stateless, so the cookie can become invalid at any time. Any Core
response with status `401` means re-authenticate. Recommended shared wrapper:

```js
export async function apiFetch(path, opts = {}) {
  const res = await fetch(`${API_BASE}${path}`, { credentials: 'include', ...opts })
  if (res.status === 401) {
    const returnTo = encodeURIComponent(location.pathname + location.search)
    location.assign(`${API_BASE}/auth/login?returnTo=${returnTo}`)
    throw new Error('unauthenticated')
  }
  return res
}
```
Wire `RequireAuth.jsx` / `AuthNav.jsx` and every data call (including Smartsheet) through this.

### 2. `/smartsheet/sheet` now requires a session
Previously open; it now returns `401 { authenticated: false }` when unauthenticated. Route
this call through the same `apiFetch`/401 handler. (Other statuses are unchanged: `503`
when unconfigured, `502`/`4xx` on upstream errors with `{ error, status, message }`.)

### 3. Logout must be POST
`GET /auth/logout` now returns `405 { error: "method_not_allowed" }`. Keep using the
full-page **POST form** to `/auth/logout` (Core replies `303` back to `/?signed_out=1` and
clears the cookie). Do not link/navigate to it with GET.

Note: Core also validates the `Origin`/`Referer` on the logout POST. A normal same-origin
form submit from the SPA passes automatically; no extra header is required.

### 4. `role` is advisory on the client
Core writes `role` (`admin` | `editor`) into the session and can enforce it server-side
(e.g. a future admin route returns `403 { error: "forbidden" }`). Use `role` only to
show/hide UI; never rely on it for actual access control. If you call a role-gated endpoint,
handle `403` distinctly from `401` (403 = signed in but not allowed; do not redirect to login).

### 5. `auth_error` detail no longer leaks internals
Token-exchange/ID-token failures now redirect with generic codes
(`auth_error=token_exchange`, `invalid_id_token`, `server_error`, `invalid_oauth_state`)
and no upstream JSON in the URL. If the SPA parsed `detail` for messaging, fall back to a
generic message for these codes. `access_denied` still includes a human-readable `detail`.

## Quick contract reference

| Endpoint | Method | Authed response | Unauthed / error |
|----------|--------|-----------------|------------------|
| `/auth/me` | GET | `200 { authenticated:true, user:{sub,email,name,role} }` | `401 { authenticated:false }` |
| `/auth/login` | GET | 302 → Microsoft | n/a |
| `/auth/logout` | POST | `303 → /?signed_out=1` (cookie cleared) | `403 forbidden_origin` if bad Origin |
| `/auth/logout` | GET | — | `405 method_not_allowed` |
| `/smartsheet/sheet` | GET | `200` sheet JSON | `401 { authenticated:false }` / `503` / `5xx` |
