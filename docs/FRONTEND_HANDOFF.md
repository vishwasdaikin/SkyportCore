# Frontend Handoff — Skyport-Core Auth Hardening

For the **SkyportHome** SPA agent. This captures the behavioral changes from the
Skyport-Core auth remediation. The `/auth/me` **response shape and status codes are
unchanged** — the contract still passes — but a few behaviors changed that the SPA must
absorb.

> **UPDATE — sign-in is now passwordless magic link (no Microsoft SSO).** Core runs with
> `AUTH_MODE=magic`. Users no longer get redirected to Microsoft; instead the SPA shows an
> email-entry screen, Core emails a one-time link, and clicking it signs the user in. The
> session cookie, `/auth/me` contract, logout, RBAC, and 401 handling are all unchanged —
> only the *sign-in entry* changes. See "Magic-link sign-in flow" below and the actionable
> steps in [FRONTEND_AGENT_PLAN.md](FRONTEND_AGENT_PLAN.md).

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
- Session is still an httpOnly cookie (`skyport_session`); JS never reads a token.
- All calls still use `credentials: 'include'`.
- Logout, 401 handling, `role` semantics: unchanged.

## Magic-link sign-in flow (NEW — replaces the Microsoft redirect)

```
1. User hits a protected route while unauthenticated  ->  SPA shows email-entry screen
   (Core's GET /auth/login now 302-redirects to `${FRONTEND_ORIGIN}/login?returnTo=...`
    instead of redirecting to Microsoft.)
2. SPA: POST /api/auth/login/email { email, returnTo }
     - 200 { ok: true }        -> show "check your email"
     - 403 { error:'domain_not_allowed' } -> show "use your @daikincomfort.com / @motili.com email"
     - 400 { error:'invalid_email' }      -> validation message
3. User clicks the emailed link -> GET /api/auth/verify?token=...&returnTo=...
     - valid   -> Core sets the httpOnly session cookie and 303-redirects to returnTo (signed in)
     - invalid -> 303 to `/?auth_error=invalid_or_expired_link`
```

Notes:
- Allowed domains: `daikincomfort.com`, `motili.com` (exact match). Links expire in ~10 min.
- The verify link is served on the SPA origin (`/api/auth/verify`) so the cookie is first-party,
  exactly like the old OAuth callback. No SPA code is needed on the verify route itself — it is
  a Core redirect; the user just lands back on `returnTo` already authenticated.
- In non-production/no-provider setups Core logs the link to its server console instead of
  emailing (for testing).

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

### 5. `auth_error` codes to handle on the landing page
Failures redirect to the SPA root with a generic `?auth_error=<code>`:
- Magic-link: `invalid_or_expired_link`, `domain_not_allowed`.
- Entra (only if `AUTH_MODE` includes `entra`): `token_exchange`, `invalid_id_token`,
  `server_error`, `invalid_oauth_state`, and `access_denied` (still includes a readable `detail`).

Map known codes to friendly copy; do not display raw `detail` JSON for the generic codes.

## Quick contract reference

| Endpoint | Method | Authed response | Unauthed / error |
|----------|--------|-----------------|------------------|
| `/auth/me` | GET | `200 { authenticated:true, user:{sub,email,name,role} }` | `401 { authenticated:false }` |
| `/auth/login` | GET | 302 → `${FRONTEND_ORIGIN}/login?returnTo=...` (magic mode) | n/a |
| `/auth/login/email` | POST | `200 { ok:true }` | `400 invalid_email` / `403 domain_not_allowed` / `502 send_failed` |
| `/auth/verify` | GET | `303 → returnTo` (cookie set) | `303 → /?auth_error=invalid_or_expired_link` |
| `/auth/logout` | POST | `303 → /?signed_out=1` (cookie cleared) | `403 forbidden_origin` if bad Origin |
| `/auth/logout` | GET | — | `405 method_not_allowed` |
| `/smartsheet/sheet` | GET | `200` sheet JSON | `401 { authenticated:false }` / `503` / `5xx` |
