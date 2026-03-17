/**
 * Skyport-Core: OAuth2 auth code flow (Web client) + session cookie.
 * Redirect URI must be registered in Azure as Web (not SPA).
 * Frontend uses Vite proxy: same-origin /api/* → this server so Set-Cookie works on :5173.
 */
import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import crypto from 'crypto'
import * as jose from 'jose'
import dotenv from 'dotenv'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

// Load .env, then .env.local — only non-empty .env.local keys override (empty lines won’t wipe .env secrets).
const coreRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
dotenv.config({ path: join(coreRoot, '.env') })
const localEnv = dotenv.config({ path: join(coreRoot, '.env.local') })
if (localEnv.parsed) {
  for (const [key, value] of Object.entries(localEnv.parsed)) {
    if (value != null && String(value).trim() !== '') {
      process.env[key] = String(value).trim()
    }
  }
}

const {
  AUTH_MICROSOFT_ENTRA_ID_ID: clientId,
  AUTH_MICROSOFT_ENTRA_ID_SECRET: clientSecret,
  AUTH_MICROSOFT_ENTRA_ID_TENANT: tenant,
  OAUTH_REDIRECT_URI: redirectUri,
  FRONTEND_ORIGIN: frontendOrigin = 'http://localhost:5173',
  SESSION_SECRET: sessionSecret,
  PORT = '3001',
} = process.env

const app = express()
app.use(cookieParser())
app.use(express.json())

const allowedOrigin = frontendOrigin.replace(/\/$/, '')
const extraOrigins = String(process.env.FRONTEND_ORIGINS || '')
  .split(',')
  .map((s) => s.trim().replace(/\/$/, ''))
  .filter(Boolean)
const corsAllowed = [...new Set([allowedOrigin, ...extraOrigins])]

/** API host (e.g. skyport-core.vercel.app) vs FRONTEND_ORIGIN host → cross-origin fetch needs SameSite=None session cookies */
let frontendHost = ''
try {
  frontendHost = new URL(allowedOrigin).hostname
} catch (_) {}
const coreHost = (process.env.VERCEL_URL || '').replace(/^https?:\/\//, '').split('/')[0] || ''
const crossSiteSession =
  String(process.env.SESSION_CROSS_SITE || '') === '1' ||
  Boolean(coreHost && frontendHost && coreHost !== frontendHost)

app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true)
      if (corsAllowed.includes(origin)) return cb(null, origin)
      cb(null, false)
    },
    credentials: true,
  })
)

/**
 * Vercel often has the full issuer URL pasted here — that produced
 * login.microsoftonline.com/https://login.microsoftonline.com/.../v2.0 → 404.
 * Accept tenant GUID, or full issuer URL; always emit a single authority host.
 */
function normalizeTenantId(raw) {
  const s = String(raw || 'common').trim()
  if (!s) return 'common'
  const lower = s.toLowerCase()
  if (lower === 'common' || lower === 'organizations' || lower === 'consumers') {
    return lower
  }
  const m = s.match(/login\.microsoftonline\.com\/([^/?#]+)/i)
  if (m) return m[1].replace(/\/v2\.0$/i, '')
  if (/^[a-f0-9-]{36}$/i.test(s)) return s
  return s
}

function tenantBase() {
  return `https://login.microsoftonline.com/${normalizeTenantId(tenant)}`
}

function requireConfig(res) {
  if (!clientId || !clientSecret || !redirectUri || !sessionSecret) {
    res.status(500).json({
      error:
        'Missing env: AUTH_MICROSOFT_ENTRA_ID_ID, AUTH_MICROSOFT_ENTRA_ID_SECRET, OAUTH_REDIRECT_URI, SESSION_SECRET',
    })
    return false
  }
  return true
}

const COOKIE = 'skyport_session'
const STATE_COOKIE = 'skyport_oauth_state'
const RETURN_COOKIE = 'skyport_return_to'

/** Session cookie: lax+insecure on localhost; none+secure when frontend and API are on different hosts (e.g. Vercel). */
const SESSION_COOKIE = crossSiteSession
  ? { httpOnly: true, secure: true, sameSite: 'none', path: '/' }
  : { httpOnly: true, secure: false, sameSite: 'lax', path: '/' }

/** OAuth state lives only on Core top-level navigations → Lax is enough. */
const STATE_COOKIE_OPTS = {
  httpOnly: true,
  secure: crossSiteSession,
  sameSite: 'lax',
  path: '/',
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE, SESSION_COOKIE)
  res.cookie(COOKIE, '', {
    ...SESSION_COOKIE,
    maxAge: 0,
    expires: new Date(0),
  })
}

const secretKey = () =>
  new TextEncoder().encode(sessionSecret || 'dev-only-change-me-min-32-chars!!')

async function signSession(payload) {
  return new jose.SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d')
    .sign(secretKey())
}

async function verifySession(token) {
  try {
    const { payload } = await jose.jwtVerify(token, secretKey())
    return payload
  } catch {
    return null
  }
}

/** Start login → redirect to Microsoft (redirect to app with message if .env.local incomplete — avoids blank JSON page) */
app.get('/auth/login', (req, res) => {
  if (!clientId || !String(clientSecret || '').trim() || !redirectUri || !sessionSecret) {
    const msg =
      'Skyport-Core needs AUTH_MICROSOFT_ENTRA_ID_SECRET in .env or .env.local (plus ID, tenant, OAUTH_REDIRECT_URI, SESSION_SECRET). Restart Core after edits.'
    return res.redirect(
      `${allowedOrigin}/?skyport_core_setup=1&msg=${encodeURIComponent(msg)}`
    )
  }
  const returnTo = String(req.query.returnTo || '/').slice(0, 2048)
  const state = crypto.randomBytes(24).toString('hex')
  res.cookie(STATE_COOKIE, state, { ...STATE_COOKIE_OPTS, maxAge: 600000 })
  res.cookie(RETURN_COOKIE, returnTo, { ...STATE_COOKIE_OPTS, maxAge: 600000 })
  const params = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    response_mode: 'query',
    scope: 'openid profile email offline_access',
    state,
  })
  res.redirect(`${tenantBase()}/oauth2/v2.0/authorize?${params}`)
})

function idTokenClaims(idToken) {
  if (!idToken || typeof idToken !== 'string') return { sub: 'user', name: '', email: '' }
  const parts = idToken.split('.')
  if (parts.length < 2) return { sub: 'user', name: '', email: '' }
  const json = Buffer.from(parts[1], 'base64url').toString('utf8')
  const p = JSON.parse(json)
  return {
    sub: p.sub || p.oid || 'user',
    name: p.name || '',
    email: p.email || p.preferred_username || '',
  }
}

/** OAuth callback (Web redirect URI) */
app.get('/oauth/callback', async (req, res) => {
  if (!requireConfig(res)) return
  const { code, state, error, error_description: errDesc } = req.query
  const savedState = req.cookies[STATE_COOKIE]
  const returnTo = req.cookies[RETURN_COOKIE] || '/'
  res.clearCookie(STATE_COOKIE, STATE_COOKIE_OPTS)
  res.clearCookie(RETURN_COOKIE, STATE_COOKIE_OPTS)
  res.cookie(STATE_COOKIE, '', { ...STATE_COOKIE_OPTS, maxAge: 0, expires: new Date(0) })
  res.cookie(RETURN_COOKIE, '', { ...STATE_COOKIE_OPTS, maxAge: 0, expires: new Date(0) })

  if (error) {
    return res.redirect(
      `${allowedOrigin}/?auth_error=${encodeURIComponent(String(error))}&detail=${encodeURIComponent(String(errDesc || ''))}`
    )
  }
  if (!code || !state || state !== savedState) {
    return res.redirect(`${allowedOrigin}/?auth_error=invalid_oauth_state`)
  }

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code: String(code),
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
    scope: 'openid profile email offline_access',
  })

  const tokenRes = await fetch(`${tenantBase()}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
  const tokenJson = await tokenRes.json().catch(() => ({}))
  if (!tokenRes.ok) {
    return res.redirect(
      `${allowedOrigin}/?auth_error=token_exchange&detail=${encodeURIComponent(JSON.stringify(tokenJson))}`
    )
  }

  const claims = idTokenClaims(tokenJson.id_token)

  const jwt = await signSession(claims)
  res.cookie(COOKIE, jwt, {
    ...SESSION_COOKIE,
    maxAge: 7 * 24 * 60 * 60 * 1000,
  })
  const path = returnTo.startsWith('http') ? '/' : returnTo
  res.redirect(`${allowedOrigin}${path.startsWith('/') ? path : `/${path}`}`)
})

app.post('/auth/logout', (_req, res) => {
  clearSessionCookie(res)
  res.json({ ok: true })
})

app.get('/auth/logout', (_req, res) => {
  clearSessionCookie(res)
  res.redirect(302, allowedOrigin)
})

app.get('/auth/me', async (req, res) => {
  const token = req.cookies[COOKIE]
  if (!token) return res.status(401).json({ authenticated: false })
  const payload = await verifySession(token)
  if (!payload) return res.status(401).json({ authenticated: false })
  res.json({
    authenticated: true,
    user: {
      sub: payload.sub,
      name: payload.name,
      email: payload.email,
    },
  })
})

app.get('/health', (_req, res) => res.json({ ok: true }))

app.listen(Number(PORT), () => {
  const hasSecret = Boolean(clientSecret && String(clientSecret).trim())
  console.log(`Skyport-Core listening on http://localhost:${PORT}`)
  console.log(`Register Web redirect URI: ${redirectUri || '(set OAUTH_REDIRECT_URI)'}`)
  console.log(
    `[env] clientId=${Boolean(clientId)} clientSecret=${hasSecret} redirectUri=${Boolean(redirectUri)} sessionSecret=${Boolean(sessionSecret)} crossSiteSession=${crossSiteSession}`
  )
  if (!hasSecret) {
    console.warn(
      '[env] Put AUTH_MICROSOFT_ENTRA_ID_SECRET in Skyport-Core/.env or .env.local, then restart.'
    )
  }
})
