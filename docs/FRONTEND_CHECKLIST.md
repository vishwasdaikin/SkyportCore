# Frontend Checklist — SkyportHome SPA (magic-link auth)

Hand this to the SkyportHome agent. Backend is **live** at `https://skyport-core.vercel.app`
running `AUTH_MODE=magic`. The SPA talks to it same-origin via the `/api/*` rewrite. Full
detail in [FRONTEND_AGENT_PLAN.md](FRONTEND_AGENT_PLAN.md); contract in
[FRONTEND_HANDOFF.md](FRONTEND_HANDOFF.md).

## 0. Wiring / config
- [ ] Confirm the prod `/api/*` rewrite forwards to Core, so these resolve:
      `/api/auth/login/email`, `/api/auth/verify`, `/api/auth/me`, `/api/auth/logout`.
- [ ] `VITE_API_BASE_URL` is empty in prod (same-origin `/api`); set to the Core URL only if not using the rewrite.
- [ ] Every Core request uses `credentials: 'include'`.

## 1. Shared fetch wrapper (central 401 handling)
- [ ] Add one `apiFetch(path, opts)` wrapper used by ALL Core calls.
- [ ] On `401` → redirect to the SPA `/login?returnTo=<current path>` exactly once.
- [ ] On `403` → do NOT redirect (signed in, not allowed); let the caller show "no access".

## 2. Build the `/login` page (NEW — replaces Microsoft redirect)
- [ ] Route `/login` renders an email-entry form.
- [ ] Submit → `POST /api/auth/login/email` with `{ email, returnTo }` and `credentials:'include'`.
- [ ] Handle responses:
  - [ ] `200 { ok:true }` → show "Check your email — we sent a sign-in link to {email} (expires ~10 min)."
  - [ ] `403 { error:'domain_not_allowed' }` → "Use your @daikincomfort.com or @motili.com email."
  - [ ] `400 { error:'invalid_email' }` → inline validation message.
  - [ ] `502 { error:'send_failed' }` → "Couldn't send the link, try again."
- [ ] Do NOT build a verify page — the emailed link hits Core (`/api/auth/verify`), which sets
      the cookie and redirects the user back to `returnTo` already signed in.

## 3. Auth gate / context
- [ ] `RequireAuth` / auth context fetches `/api/auth/me` via `apiFetch`.
- [ ] `200 { authenticated:true, user:{ sub, email, name, role } }` → authed.
- [ ] `401` (handled by wrapper) → send to `/login`.
- [ ] Keep `user.role` for UI gating only (never as real access control).

## 4. Data calls
- [ ] `/api/smartsheet/sheet` goes through `apiFetch` (now returns `401` when unauthenticated).
- [ ] Handle its error contract: `503` (not configured), `502`/`4xx` `{ error, status, message }`.

## 5. Logout
- [ ] Sign-out is a full-page **POST form** to `/api/auth/logout` (GET now returns `405`).
- [ ] After logout the user lands on `/?signed_out=1`; surface a "signed out" notice.

## 6. Landing-page messages (`?auth_error=<code>`)
- [ ] `invalid_or_expired_link` → "That sign-in link is invalid or expired. Request a new one."
- [ ] `domain_not_allowed` → "Use your @daikincomfort.com or @motili.com email."
- [ ] Also handle `?signed_out=1` → "You've been signed out."
- [ ] Do not display raw error `detail` JSON.

## Acceptance test (end-to-end)
- [ ] Unauthenticated visit to a protected route → lands on `/login`.
- [ ] Enter an allowed email → "check your email" state; the link arrives (or appears in Core logs in non-prod).
- [ ] Click the link → returns to `returnTo`, authenticated; `/auth/me` shows the user.
- [ ] Disallowed domain (e.g. gmail) → friendly "domain not allowed" message.
- [ ] Sign out → cookie cleared, redirected to `/?signed_out=1`, protected routes bounce to `/login`.

## Notes
- Sessions last ~8h and are stateless; expect occasional mid-session `401` → the wrapper re-routes to `/login`.
- Sender is currently `login@forgethecosmos.com` (verified Resend domain) until a branded domain is verified — links may land in spam during testing.
- Allowed domains: `daikincomfort.com`, `motili.com` (exact match).
