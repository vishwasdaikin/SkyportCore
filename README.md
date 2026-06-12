# SkyportCore

OAuth2 (Microsoft Entra **Web** client) + session API for [Skyport-Web](https://github.com/vishwasdaikin/SkyportHome).

**Production:** [skyport-core.vercel.app](https://skyport-core.vercel.app) · **Web:** [skyport-home.vercel.app](https://skyport-home.vercel.app) · URL matrix: Skyport-Web `docs/VERCEL_URLS.md`

## Vercel environment variables

| Variable | Description |
|----------|-------------|
| `OAUTH_REDIRECT_URI` | `https://<this-deployment>/oauth/callback` |
| `FRONTEND_ORIGIN` | Skyport-Web URL (CORS + post-login redirect) |
| `FRONTEND_ORIGINS` | Optional comma-separated extra web origins |
| `AUTH_*`, `SESSION_SECRET` | See `.env.example` |
| `OAUTH_ALLOWED_MICROSOFT_EMAIL_DOMAINS` | Optional comma-separated allowlist (e.g. `daikincomfort.com`). Empty = any email. |
| `OAUTH_ADMIN_EMAILS` | Optional comma-separated emails that get `role=admin` in the session payload. |

Azure **Web** redirect URI must match `OAUTH_REDIRECT_URI` exactly.

When the API host ≠ frontend host, the server uses `SameSite=None` session cookies so the browser can send them on `fetch(..., { credentials: 'include' })` from the web app.

## Frontend

Set `VITE_API_BASE_URL=https://<this-core-host>` on the web project. See Skyport-Web `docs/VERCEL_DEPLOY.md`.

Behavioral notes for the SPA (cross-repo contract) live in [docs/FRONTEND_HANDOFF.md](docs/FRONTEND_HANDOFF.md).

## Deployment / ops follow-up

`vercel.json` currently only sets cache-control headers; it has no `rewrites`, `functions`,
or `builds`. A plain Express `app.listen` server does not run as a Vercel serverless function
without a builder/rewrite (or a `api/` entrypoint). Confirm how routes are served in
production (the cache headers in `vercel.json` only apply if requests actually hit this app),
and that `NODE_ENV=production` plus the required env vars (incl. a 32+ char `SESSION_SECRET`
and a tenant GUID) are set — the server now exits at boot if they are missing/weak.
