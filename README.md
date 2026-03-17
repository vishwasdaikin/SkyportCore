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

Azure **Web** redirect URI must match `OAUTH_REDIRECT_URI` exactly.

When the API host ≠ frontend host, the server uses `SameSite=None` session cookies so the browser can send them on `fetch(..., { credentials: 'include' })` from the web app.

## Frontend

Set `VITE_API_BASE_URL=https://<this-core-host>` on the web project. See Skyport-Web `docs/VERCEL_DEPLOY.md`.
