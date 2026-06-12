/**
 * Skyport-Core: OAuth2 auth code flow (Web client) + session cookie.
 * Redirect URI must be registered in Azure as Web (not SPA).
 * Frontend uses Vite proxy: same-origin /api/* → this server so Set-Cookie works on :5173.
 */
import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
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
  OAUTH_PROMPT: oauthPromptEnv,
  FRONTEND_ORIGIN: frontendOrigin = 'http://localhost:5173',
  SESSION_SECRET: sessionSecret,
  PORT = '3001',
} = process.env

const isProd = String(process.env.NODE_ENV || '').toLowerCase() === 'production'
const allowAnyEmail = String(process.env.OAUTH_ALLOW_ANY_EMAIL || '') === '1'
// On serverless (Vercel/Lambda) a process.exit during cold start becomes an opaque
// FUNCTION_INVOCATION_FAILED. Detect it so boot validation logs instead of hard-exiting;
// security still fails closed per-request (requireConfig + the email allowlist).
const isServerless = Boolean(
  process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.LAMBDA_TASK_ROOT
)

const app = express()
// Behind Vercel/other proxies so express-rate-limit + secure cookies see the real client + scheme.
app.set('trust proxy', 1)

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'self'"],
      },
    },
    referrerPolicy: { policy: 'no-referrer' },
    hsts: { maxAge: 15552000, includeSubDomains: true },
    // API is consumed cross-origin by the SPA via credentialed fetch; don't let CORP block it.
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  })
)
app.use(cookieParser())
app.use(express.json({ limit: '64kb' }))

const allowedOrigin = frontendOrigin.replace(/\/$/, '')
const extraOrigins = String(process.env.FRONTEND_ORIGINS || '')
  .split(',')
  .map((s) => s.trim().replace(/\/$/, ''))
  .filter(Boolean)
const corsAllowed = [...new Set([allowedOrigin, ...extraOrigins])]

/**
 * Sign-in policy ported from the former NextAuth sso-app (auth.ts):
 * - Restrict Microsoft sign-in by email domain.
 * - Mark known emails as `admin` in the session payload (others get `editor`).
 * Empty `OAUTH_ALLOWED_MICROSOFT_EMAIL_DOMAINS` = no allowlist. In production this fails
 * CLOSED (no sign-in) unless OAUTH_ALLOW_ANY_EMAIL=1 is set explicitly.
 */
const allowedDomains = String(process.env.OAUTH_ALLOWED_MICROSOFT_EMAIL_DOMAINS || '')
  .split(',')
  .map((s) => s.trim().toLowerCase().replace(/^@/, ''))
  .filter(Boolean)
const adminEmails = new Set(
  String(process.env.OAUTH_ADMIN_EMAILS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
)

function emailDomain(email) {
  if (!email || typeof email !== 'string') return ''
  const at = email.lastIndexOf('@')
  return at >= 0 ? email.slice(at + 1).toLowerCase() : ''
}

function isEmailAllowed(email) {
  if (allowedDomains.length === 0) {
    // Default-open is only permitted outside production, or with an explicit opt-in.
    return !isProd || allowAnyEmail
  }
  return allowedDomains.includes(emailDomain(email))
}

function roleForEmail(email) {
  return email && adminEmails.has(String(email).toLowerCase()) ? 'admin' : 'editor'
}

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

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
})
const smartsheetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
})

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

const normalizedTenant = normalizeTenantId(tenant)
const isGuidTenant = /^[a-f0-9-]{36}$/i.test(normalizedTenant)

function tenantBase() {
  return `https://login.microsoftonline.com/${normalizedTenant}`
}

/** JWKS for verifying Microsoft-issued ID tokens; jose caches keys internally. */
const idTokenJwks = jose.createRemoteJWKSet(
  new URL(`${tenantBase()}/discovery/v2.0/keys`)
)

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
const NONCE_COOKIE = 'skyport_oauth_nonce'
const PKCE_COOKIE = 'skyport_oauth_verifier'

/** Session lifetime — shortened from 7d; stateless JWTs can't be revoked, so keep TTL tight. */
function parseTtlSeconds(raw) {
  const s = String(raw || '8h').trim()
  const m = s.match(/^(\d+)\s*([smhd])?$/i)
  if (!m) return 8 * 3600
  const n = Number(m[1])
  const u = (m[2] || 's').toLowerCase()
  const mult = u === 's' ? 1 : u === 'm' ? 60 : u === 'h' ? 3600 : 86400
  return n * mult
}
const sessionTtlSeconds = parseTtlSeconds(process.env.SESSION_TTL)

/**
 * Session cookie: lax+insecure only on localhost dev; Secure is forced in production and
 * whenever the cookie must travel cross-site (SameSite=None requires Secure).
 */
const SESSION_COOKIE = {
  httpOnly: true,
  secure: isProd || crossSiteSession,
  sameSite: crossSiteSession ? 'none' : 'lax',
  path: '/',
}

/** Short-lived OAuth handshake cookies (state/nonce/pkce/return) — Lax is enough for top-level redirects. */
const HANDSHAKE_COOKIE_OPTS = {
  httpOnly: true,
  secure: isProd || crossSiteSession,
  sameSite: 'lax',
  path: '/',
}

function clearSessionCookie(res) {
  const o = { ...SESSION_COOKIE, path: '/' }
  res.clearCookie(COOKIE, o)
  res.cookie(COOKIE, '', { ...o, maxAge: 0, expires: new Date(0) })
  if (crossSiteSession) {
    res.append(
      'Set-Cookie',
      `${COOKIE}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=None`
    )
  }
}

function clearHandshakeCookie(res, name) {
  res.clearCookie(name, HANDSHAKE_COOKIE_OPTS)
  res.cookie(name, '', { ...HANDSHAKE_COOKIE_OPTS, maxAge: 0, expires: new Date(0) })
}

function noStoreHeaders(res) {
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    Pragma: 'no-cache',
    Expires: '0',
    'CDN-Cache-Control': 'no-store',
    'Vercel-CDN-Cache-Control': 'no-store',
  })
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a == null ? '' : a))
  const bb = Buffer.from(String(b == null ? '' : b))
  if (ba.length !== bb.length) return false
  return crypto.timingSafeEqual(ba, bb)
}

/** Reject state-changing requests whose Origin/Referer is not an allowed frontend (CSRF defense for SameSite=None). */
function isAllowedRequestOrigin(req) {
  const origin = req.get('origin')
  if (origin) return corsAllowed.includes(origin.replace(/\/$/, ''))
  const referer = req.get('referer')
  if (referer) return corsAllowed.some((a) => referer === a || referer.startsWith(a + '/'))
  // No Origin/Referer (some same-origin form posts / non-browser clients) — allow.
  return true
}

const secretKey = () => {
  if (!sessionSecret) throw new Error('SESSION_SECRET is not set')
  return new TextEncoder().encode(sessionSecret)
}

async function signSession(payload) {
  return new jose.SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${sessionTtlSeconds}s`)
    .sign(secretKey())
}

async function verifySession(token) {
  try {
    const { payload } = await jose.jwtVerify(token, secretKey(), { algorithms: ['HS256'] })
    return payload
  } catch {
    return null
  }
}

/** Centralized guard: validates the session cookie and attaches req.user. */
async function requireAuth(req, res, next) {
  const token = req.cookies[COOKIE]
  if (!token) return res.status(401).json({ authenticated: false })
  const payload = await verifySession(token)
  if (!payload) return res.status(401).json({ authenticated: false })
  req.user = {
    sub: payload.sub,
    name: payload.name,
    email: payload.email,
    role: payload.role || 'editor',
  }
  next()
}

/** Role guard for privileged routes (returns 403 on mismatch). Use after requireAuth. */
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ authenticated: false })
    if (req.user.role !== role) return res.status(403).json({ error: 'forbidden' })
    next()
  }
}

/** Start login → redirect to Microsoft (redirect to app with message if .env.local incomplete — avoids blank JSON page) */
app.get('/auth/login', authLimiter, (req, res) => {
  if (!clientId || !String(clientSecret || '').trim() || !redirectUri || !sessionSecret) {
    const msg =
      'Skyport-Core needs AUTH_MICROSOFT_ENTRA_ID_SECRET in .env or .env.local (plus ID, tenant, OAUTH_REDIRECT_URI, SESSION_SECRET). Restart Core after edits.'
    return res.redirect(
      `${allowedOrigin}/?skyport_core_setup=1&msg=${encodeURIComponent(msg)}`
    )
  }
  const returnTo = String(req.query.returnTo || '/').slice(0, 2048)
  const state = crypto.randomBytes(24).toString('hex')
  const nonce = crypto.randomBytes(24).toString('hex')
  const codeVerifier = crypto.randomBytes(32).toString('base64url')
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url')

  res.cookie(STATE_COOKIE, state, { ...HANDSHAKE_COOKIE_OPTS, maxAge: 600000 })
  res.cookie(NONCE_COOKIE, nonce, { ...HANDSHAKE_COOKIE_OPTS, maxAge: 600000 })
  res.cookie(PKCE_COOKIE, codeVerifier, { ...HANDSHAKE_COOKIE_OPTS, maxAge: 600000 })
  res.cookie(RETURN_COOKIE, returnTo, { ...HANDSHAKE_COOKIE_OPTS, maxAge: 600000 })

  const params = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    response_mode: 'query',
    scope: 'openid profile email offline_access',
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  })
  const allowedPrompt = new Set(['login', 'select_account', 'none', 'consent'])
  const qPrompt = String(req.query.prompt || '').trim()
  if (allowedPrompt.has(qPrompt)) {
    params.set('prompt', qPrompt)
  } else if (oauthPromptEnv && allowedPrompt.has(String(oauthPromptEnv).trim())) {
    params.set('prompt', String(oauthPromptEnv).trim())
  }
  res.redirect(`${tenantBase()}/oauth2/v2.0/authorize?${params}`)
})

/** Verify the Microsoft ID token signature + claims (sig via JWKS, aud, exp, nonce, iss for GUID tenants). */
async function verifyIdToken(idToken, expectedNonce) {
  const { payload } = await jose.jwtVerify(idToken, idTokenJwks, {
    audience: clientId,
    ...(isGuidTenant ? { issuer: `${tenantBase()}/v2.0` } : {}),
  })
  if (!expectedNonce || !safeEqual(payload.nonce, expectedNonce)) {
    throw new Error('nonce_mismatch')
  }
  return {
    sub: payload.sub || payload.oid || 'user',
    name: payload.name || '',
    email: payload.email || payload.preferred_username || '',
  }
}

/** OAuth callback (Web redirect URI) */
app.get('/oauth/callback', authLimiter, async (req, res) => {
  if (!requireConfig(res)) return
  noStoreHeaders(res)
  const { code, state, error, error_description: errDesc } = req.query
  const savedState = req.cookies[STATE_COOKIE]
  const savedNonce = req.cookies[NONCE_COOKIE]
  const codeVerifier = req.cookies[PKCE_COOKIE]
  const returnTo = req.cookies[RETURN_COOKIE] || '/'
  for (const name of [STATE_COOKIE, NONCE_COOKIE, PKCE_COOKIE, RETURN_COOKIE]) {
    clearHandshakeCookie(res, name)
  }

  if (error) {
    return res.redirect(
      `${allowedOrigin}/?auth_error=${encodeURIComponent(String(error))}&detail=${encodeURIComponent(String(errDesc || ''))}`
    )
  }
  if (!code || !state || !savedState || !safeEqual(String(state), savedState)) {
    return res.redirect(`${allowedOrigin}/?auth_error=invalid_oauth_state`)
  }

  try {
    const body = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code: String(code),
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
      scope: 'openid profile email offline_access',
    })
    if (codeVerifier) body.set('code_verifier', codeVerifier)

    const tokenRes = await fetch(`${tenantBase()}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    const tokenJson = await tokenRes.json().catch(() => ({}))
    if (!tokenRes.ok) {
      // Don't leak upstream token-endpoint internals into the redirect URL.
      console.error('[oauth] token exchange failed', tokenRes.status, tokenJson)
      return res.redirect(`${allowedOrigin}/?auth_error=token_exchange`)
    }

    let claims
    try {
      claims = await verifyIdToken(tokenJson.id_token, savedNonce)
    } catch (err) {
      console.error('[oauth] id_token verification failed:', err?.message || err)
      return res.redirect(`${allowedOrigin}/?auth_error=invalid_id_token`)
    }

    if (!isEmailAllowed(claims.email)) {
      clearSessionCookie(res)
      const detail =
        allowedDomains.length === 0
          ? 'sign_in_policy_not_configured'
          : `email_domain_not_allowed: ${emailDomain(claims.email) || '(no email)'}; allowed: ${allowedDomains.join(',')}`
      return res.redirect(
        `${allowedOrigin}/?auth_error=access_denied&detail=${encodeURIComponent(detail)}`
      )
    }

    const jwt = await signSession({ ...claims, role: roleForEmail(claims.email) })
    res.cookie(COOKIE, jwt, {
      ...SESSION_COOKIE,
      maxAge: sessionTtlSeconds * 1000,
    })
    const path = returnTo.startsWith('http') ? '/' : returnTo
    res.redirect(`${allowedOrigin}${path.startsWith('/') ? path : `/${path}`}`)
  } catch (err) {
    console.error('[oauth] callback error:', err?.message || err)
    return res.redirect(`${allowedOrigin}/?auth_error=server_error`)
  }
})

/**
 * Primary logout: browser POST (form from web app). Full navigation processes
 * Set-Cookie reliably; 303 back to web. GET is intentionally not supported
 * (CDN-cacheable + CSRF-able) — the SPA must POST.
 */
app.post('/auth/logout', (req, res) => {
  noStoreHeaders(res)
  if (!isAllowedRequestOrigin(req)) {
    return res.status(403).json({ error: 'forbidden_origin' })
  }
  clearSessionCookie(res)
  const next = `${allowedOrigin.replace(/\/$/, '')}/?signed_out=1`
  res.redirect(303, next)
})

app.get('/auth/logout', (_req, res) => {
  noStoreHeaders(res)
  res.set('Allow', 'POST')
  res.status(405).json({ error: 'method_not_allowed', message: 'Use POST /auth/logout' })
})

app.get('/auth/me', requireAuth, (req, res) => {
  noStoreHeaders(res)
  res.json({ authenticated: true, user: req.user })
})

app.get('/health', (_req, res) => res.json({ ok: true }))

/**
 * Proxy Smartsheet sheet JSON (server holds token). Requires a valid session.
 * Manual: SMARTSHEET_ACCESS_TOKEN=… SMARTSHEET_SHEET_ID=… curl -sS http://localhost:3001/smartsheet/sheet | head
 */
app.get('/smartsheet/sheet', smartsheetLimiter, requireAuth, async (_req, res) => {
  noStoreHeaders(res)
  const accessToken = String(process.env.SMARTSHEET_ACCESS_TOKEN || '').trim()
  const sheetId = String(process.env.SMARTSHEET_SHEET_ID || '').trim()
  if (!accessToken || !sheetId) {
    return res.status(503).json({
      error: true,
      status: 503,
      message: 'Smartsheet is not configured (missing SMARTSHEET_ACCESS_TOKEN or SMARTSHEET_SHEET_ID)',
    })
  }

  const url = `https://api.smartsheet.com/2.0/sheets/${encodeURIComponent(sheetId)}`
  let upstream
  try {
    upstream = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
      },
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Network error'
    return res.status(502).json({ error: true, status: 502, message: msg })
  }

  const text = await upstream.text()
  if (upstream.ok) {
    res.type('application/json')
    return res.status(200).send(text)
  }

  let message = `Smartsheet returned HTTP ${upstream.status}`
  try {
    const parsed = JSON.parse(text)
    if (parsed && typeof parsed.message === 'string' && parsed.message.length > 0) {
      message = parsed.message.slice(0, 500)
    }
  } catch {
    // ignore — use generic message
  }
  return res.status(upstream.status >= 400 && upstream.status < 600 ? upstream.status : 502).json({
    error: true,
    status: upstream.status,
    message,
  })
})

/** Validate required env at boot. Fail fast in production; warn in dev. */
function validateConfigAtBoot() {
  const problems = []
  if (!clientId) problems.push('AUTH_MICROSOFT_ENTRA_ID_ID')
  if (!clientSecret || !String(clientSecret).trim()) problems.push('AUTH_MICROSOFT_ENTRA_ID_SECRET')
  if (!redirectUri) problems.push('OAUTH_REDIRECT_URI')
  if (!sessionSecret) {
    problems.push('SESSION_SECRET')
  } else if (String(sessionSecret).length < 32) {
    problems.push('SESSION_SECRET (must be at least 32 characters)')
  }
  if (isProd && allowedDomains.length === 0 && !allowAnyEmail) {
    problems.push(
      'OAUTH_ALLOWED_MICROSOFT_EMAIL_DOMAINS (empty in production; set it or OAUTH_ALLOW_ANY_EMAIL=1)'
    )
  }
  if (problems.length) {
    const msg = `[env] Invalid/missing configuration: ${problems.join(', ')}`
    if (isProd && !isServerless) {
      // Standalone process: fail fast so the operator notices immediately.
      console.error(msg)
      console.error('[env] Refusing to start in production with invalid auth configuration.')
      process.exit(1)
    } else if (isProd) {
      // Serverless: don't crash the function; auth still fails closed at request time.
      console.error(msg)
      console.error('[env] Auth will fail closed until configuration is fixed.')
    } else {
      console.warn(msg)
    }
  }
  if (!isProd && (!normalizedTenant || normalizedTenant === 'common')) {
    console.warn(
      '[env] AUTH_MICROSOFT_ENTRA_ID_TENANT is "common" — any Microsoft tenant can sign in. Pin a tenant GUID in production.'
    )
  }
}

validateConfigAtBoot()

app.listen(Number(PORT), () => {
  const hasSecret = Boolean(clientSecret && String(clientSecret).trim())
  console.log(`Skyport-Core listening on http://localhost:${PORT}`)
  console.log(`Register Web redirect URI: ${redirectUri || '(set OAUTH_REDIRECT_URI)'}`)
  console.log(
    `[env] clientId=${Boolean(clientId)} clientSecret=${hasSecret} redirectUri=${Boolean(redirectUri)} sessionSecret=${Boolean(sessionSecret)} crossSiteSession=${crossSiteSession} sessionTtlSeconds=${sessionTtlSeconds}`
  )
  console.log(
    `[policy] allowedDomains=${allowedDomains.join(',') || '(none)'} adminEmails=${adminEmails.size} allowAnyEmail=${allowAnyEmail} tenant=${normalizedTenant}`
  )
  if (!hasSecret) {
    console.warn(
      '[env] Put AUTH_MICROSOFT_ENTRA_ID_SECRET in Skyport-Core/.env or .env.local, then restart.'
    )
  }
})
