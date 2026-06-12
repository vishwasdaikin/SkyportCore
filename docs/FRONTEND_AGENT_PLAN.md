# Frontend Agent Implementation Plan — SkyportHome SPA

**Audience:** the agent working in `vishwasdaikin/SkyportHome` (Vite + React SPA).
**Why:** Skyport-Core auth was hardened. The `/auth/me` response shape and status codes are
unchanged, but several behaviors changed that the SPA must adopt. This is the actionable
companion to [FRONTEND_HANDOFF.md](FRONTEND_HANDOFF.md) (which is the contract reference).

Do these tasks in order. Each lists the file(s) to touch, the change, and how to verify.

---

## Task 1 — Add a shared, credentialed fetch wrapper with central 401 handling

**Problem:** Sessions are now short-lived (8h default) and stateless, so the cookie can
expire/invalidate at any time. Every Core call must treat `401` as "session gone → login".

**Files:** create `src/api/client.js` (or `src/lib/apiClient.js` to match repo conventions).

**Change:** implement a single wrapper that all Core calls go through.

```js
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '' // '' = same-origin /api rewrite

export class AuthRedirect extends Error {}

export async function apiFetch(path, opts = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: 'include',
    ...opts,
  })
  if (res.status === 401) {
    redirectToLogin()
    throw new AuthRedirect('unauthenticated')
  }
  return res
}

export function redirectToLogin(forceFresh = false) {
  const returnTo = encodeURIComponent(location.pathname + location.search)
  const prompt = forceFresh ? '&prompt=login' : ''
  location.assign(`${API_BASE}/auth/login?returnTo=${returnTo}${prompt}`)
}
```

**Verify:** with no/expired session, any `apiFetch` call navigates to `/auth/login` exactly once.

---

## Task 2 — Route `/auth/me` and the auth context through the wrapper

**Problem:** `RequireAuth.jsx` / `AuthNav.jsx` currently call `/auth/me` directly.

**Files:** `src/auth/RequireAuth.jsx`, `src/auth/AuthNav.jsx` (and any auth context/provider).

**Change:**
- Fetch `/auth/me` via `apiFetch`. On `200`, read `{ authenticated, user: { sub, email, name, role } }`.
- On `401` the wrapper already redirects; treat a thrown `AuthRedirect` as "not authenticated,
  navigation in progress" (render nothing/spinner). Also treat `authenticated: false` the same way.
- Keep `user.role` in context for UI gating only (see Task 4).

**Verify:** signed-in user renders protected routes; signed-out user is redirected to login.

---

## Task 3 — Route the Smartsheet call through the wrapper (now requires auth)

**Problem:** `/smartsheet/sheet` was previously open; it now returns `401` when unauthenticated.

**Files:** wherever the SPA fetches `/smartsheet/sheet`.

**Change:** call it via `apiFetch('/smartsheet/sheet')`. Handle the non-401 error contract
unchanged: `503` (not configured), `502`/`4xx` with `{ error, status, message }`.

```js
const res = await apiFetch('/smartsheet/sheet') // 401 handled centrally
if (!res.ok) {
  const body = await res.json().catch(() => ({}))
  showError(body.message ?? `Smartsheet error (${res.status})`)
  return
}
const sheet = await res.json()
```

**Verify:** unauthenticated load redirects to login; authenticated load returns sheet JSON;
unconfigured backend surfaces the `503` message.

---

## Task 4 — Make logout POST-only

**Problem:** `GET /auth/logout` now returns `405`. Only `POST /auth/logout` clears the cookie
(303 redirect back to `/?signed_out=1`).

**Files:** `src/auth/AuthNav.jsx` (or the sign-out control).

**Change:** sign-out must be a full-page **form POST** (not a link/`location.assign` GET):

```jsx
<form method="POST" action={`${API_BASE}/auth/logout`}>
  <button type="submit">Sign out</button>
</form>
```

Core validates `Origin`/`Referer` on this POST; a normal same-origin form submit passes with
no extra header. Do not switch this to `fetch` unless you also follow the 303 redirect manually.

**Verify:** clicking sign-out lands on `/?signed_out=1` and a subsequent `/auth/me` returns 401.

---

## Task 5 — Treat `role` as UI-only and handle `403` distinctly from `401`

**Problem:** Authorization is now enforced server-side. `role` (`admin` | `editor`) is for
showing/hiding UI only. Role-gated endpoints return `403 { error: 'forbidden' }`.

**Files:** the shared client (`apiFetch`) and any admin-only UI.

**Change:**
- Use `user.role` only to conditionally render admin UI.
- In `apiFetch`, do **not** redirect on `403` (the user is signed in, just not allowed).
  Let callers handle `403` (e.g. show "You don't have access"). `401` still redirects.

**Verify:** an `editor` hitting an admin route gets a clean "forbidden" message, not a login loop.

---

## Task 6 — Generic messaging for `auth_error` codes

**Problem:** Core no longer leaks upstream internals in the redirect `detail`. Error codes are
generic: `token_exchange`, `invalid_id_token`, `invalid_oauth_state`, `server_error`.
`access_denied` still includes a human-readable `detail`.

**Files:** wherever the landing page parses `?auth_error=...&detail=...` (and `?signed_out=1`,
`?skyport_core_setup=1`).

**Change:** map known codes to friendly copy; for `access_denied`, you may still show `detail`.

```js
const params = new URLSearchParams(location.search)
const err = params.get('auth_error')
const msgByCode = {
  access_denied: params.get('detail') || 'Your account is not allowed to sign in.',
  invalid_oauth_state: 'Your sign-in session expired. Please try again.',
  invalid_id_token: 'Sign-in could not be verified. Please try again.',
  token_exchange: 'Sign-in failed. Please try again.',
  server_error: 'Something went wrong during sign-in. Please try again.',
}
if (err) showBanner(msgByCode[err] ?? 'Sign-in failed. Please try again.')
```

**Verify:** triggering each error path shows friendly copy; no raw JSON/secrets in the UI.

---

## Out of scope / no change needed
- Session cookie is still httpOnly `skyport_session`; never read it in JS.
- `GET /auth/login?returnTo=...&prompt=login` unchanged.
- `/auth/me` response shape unchanged (contract preserved).
- Cross-origin cookies are handled by Core (`SameSite=None; Secure` in prod) plus the
  same-origin `/api/*` rewrite; keep `credentials: 'include'` on all calls.

## Acceptance checklist
- [ ] All Core calls go through `apiFetch` with `credentials: 'include'`.
- [ ] `401` from any endpoint redirects to `/auth/login?returnTo=...` exactly once.
- [ ] `/smartsheet/sheet` is fetched via the wrapper and handles 503/5xx messages.
- [ ] Sign-out is a POST form; lands on `/?signed_out=1`; session is gone afterward.
- [ ] `403` is handled without a login redirect; `role` only gates UI.
- [ ] `auth_error` codes render friendly messages; no raw `detail` JSON shown.
