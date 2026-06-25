# Frontend Agent Implementation Plan — SkyportHome SPA

**Audience:** the agent working in `vishwasdaikin/SkyportHome` (Vite + React SPA).
**Why:** Skyport-Core auth was hardened. The `/auth/me` response shape and status codes are
unchanged, but several behaviors changed that the SPA must adopt. This is the actionable
companion to [FRONTEND_HANDOFF.md](FRONTEND_HANDOFF.md) (which is the contract reference).

> **UPDATE — sign-in is now passwordless magic link (Core runs `AUTH_MODE=magic`).** There is
> no more Microsoft redirect. The SPA must render its own email-entry page at `/login`, POST the
> email to Core, and show a "check your email" state. Everything else (session cookie, `/auth/me`,
> logout, RBAC, 401 handling) is unchanged. The new work is **Task 2** below; Task 1 changes only
> where the 401 handler sends the user.

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

export function redirectToLogin() {
  // Magic-link mode: send the user to the SPA's own email-entry page (client route),
  // not to Core. (Hitting Core's GET /auth/login simply 302s back to `/login` anyway.)
  const returnTo = encodeURIComponent(location.pathname + location.search)
  location.assign(`/login?returnTo=${returnTo}`)
}
```

**Verify:** with no/expired session, any `apiFetch` call navigates to `/login` exactly once.

---

## Task 2 — Build the magic-link email login page (NEW)

**Problem:** There is no Microsoft redirect anymore. The SPA owns the sign-in UI: collect the
email, ask Core to send a link, then tell the user to check their inbox.

**Files:** new route/page `src/auth/Login.jsx` mounted at `/login`.

**Change:**

```jsx
// POST the email; Core validates the domain and emails a one-time link.
async function requestLink(email, returnTo) {
  const res = await fetch(`${API_BASE}/auth/login/email`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, returnTo }),
  })
  if (res.ok) return { state: 'sent' }                       // show "check your email"
  if (res.status === 403) return { state: 'domain' }          // not an allowed domain
  if (res.status === 400) return { state: 'invalid' }         // bad email format
  return { state: 'error' }                                   // 502/unknown -> retry
}
```

UI states: form -> on `sent` show "We emailed a sign-in link to {email}. It expires in ~10
minutes." For `domain`, show "Use your @daikincomfort.com or @motili.com email." There is **no**
verify page to build: the emailed link goes to Core (`/api/auth/verify`), which sets the cookie
and redirects the user back to `returnTo` already signed in.

**Verify:** entering an allowed email shows the "check your email" state; in Core's logs (or the
email) the link appears; clicking it lands you back authenticated. A non-allowed domain shows the
domain message.

---

## Task 3 — Route `/auth/me` and the auth context through the wrapper

**Problem:** `RequireAuth.jsx` / `AuthNav.jsx` currently call `/auth/me` directly.

**Files:** `src/auth/RequireAuth.jsx`, `src/auth/AuthNav.jsx` (and any auth context/provider).

**Change:**
- Fetch `/auth/me` via `apiFetch`. On `200`, read `{ authenticated, user: { sub, email, name, role } }`.
- On `401` the wrapper already redirects; treat a thrown `AuthRedirect` as "not authenticated,
  navigation in progress" (render nothing/spinner). Also treat `authenticated: false` the same way.
- Keep `user.role` in context for UI gating only (see Task 6).

**Verify:** signed-in user renders protected routes; signed-out user is redirected to login.

---

## Task 4 — Route the Smartsheet call through the wrapper (now requires auth)

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

## Task 5 — Make logout POST-only

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

## Task 6 — Treat `role` as UI-only and handle `403` distinctly from `401`

**Problem:** Authorization is now enforced server-side. `role` (`admin` | `editor`) is for
showing/hiding UI only. Role-gated endpoints return `403 { error: 'forbidden' }`.

**Files:** the shared client (`apiFetch`) and any admin-only UI.

**Change:**
- Use `user.role` only to conditionally render admin UI.
- In `apiFetch`, do **not** redirect on `403` (the user is signed in, just not allowed).
  Let callers handle `403` (e.g. show "You don't have access"). `401` still redirects.

**Verify:** an `editor` hitting an admin route gets a clean "forbidden" message, not a login loop.

---

## Task 7 — Friendly messaging for `auth_error` codes

**Problem:** Failed sign-ins redirect to the SPA root with a generic `?auth_error=<code>`.

**Files:** wherever the landing page parses `?auth_error=...` (and `?signed_out=1`).

**Change:** map known codes to friendly copy.

```js
const params = new URLSearchParams(location.search)
const err = params.get('auth_error')
const msgByCode = {
  // magic-link
  invalid_or_expired_link: 'That sign-in link is invalid or expired. Request a new one.',
  domain_not_allowed: 'Use your @daikincomfort.com or @motili.com email to sign in.',
  // entra (only if AUTH_MODE includes entra)
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
- The verify route is Core-owned — the SPA does not implement `/auth/verify`; the emailed link
  lands the user back on `returnTo` already authenticated.
- `/auth/me` response shape unchanged (contract preserved).
- Cross-origin cookies are handled by Core (`SameSite=None; Secure` in prod) plus the
  same-origin `/api/*` rewrite; keep `credentials: 'include'` on all calls.

## Acceptance checklist
- [ ] `/login` page collects an email and POSTs to `/api/auth/login/email` with the 3 states.
- [ ] All Core calls go through `apiFetch` with `credentials: 'include'`.
- [ ] `401` from any endpoint redirects to `/login?returnTo=...` exactly once.
- [ ] `/smartsheet/sheet` is fetched via the wrapper and handles 503/5xx messages.
- [ ] Sign-out is a POST form; lands on `/?signed_out=1`; session is gone afterward.
- [ ] `403` is handled without a login redirect; `role` only gates UI.
- [ ] `auth_error` codes (incl. `invalid_or_expired_link`, `domain_not_allowed`) render friendly messages.
