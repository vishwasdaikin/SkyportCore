/**
 * Skyport-Core: session API for Skyport-Web.
 *
 * Identity providers (selected by AUTH_MODE):
 *   - magic (default): passwordless email magic link (no corporate SSO dependency).
 *   - entra: Microsoft Entra OAuth confidential flow.
 *   - both: both enabled.
 *
 * All providers funnel verified { sub, email, name } claims through issueSession(), so the
 * /auth/me contract and httpOnly session cookie are identical regardless of provider.
 */
import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit, { ipKeyGenerator } from 'express-rate-limit'
import cookieParser from 'cookie-parser'
import crypto from 'crypto'

import {
  isProd,
  isServerless,
  PORT,
  authMode,
  entraEnabled,
  magicEnabled,
  allowedOrigin,
  corsAllowed,
  allowedDomains,
  adminEmails,
  allowAnyEmail,
  sessionSecret,
  sessionTtlSeconds,
  magicTtlSeconds,
  emailFrom,
  resendApiKey,
  clientId,
  clientSecret,
  redirectUri,
  oauthPromptEnv,
  crossSiteSession,
  STATE_COOKIE,
  RETURN_COOKIE,
  NONCE_COOKIE,
  PKCE_COOKIE,
  COOKIE,
  SESSION_COOKIE,
  HANDSHAKE_COOKIE_OPTS,
} from './auth/config.js'
import { emailDomain, isEmailAllowed, isValidEmail, deriveNameFromEmail } from './auth/policy.js'
import {
  noStoreHeaders,
  safeEqual,
  isAllowedRequestOrigin,
  issueSession,
  clearSessionCookie,
  clearHandshakeCookie,
  requireAuth,
} from './auth/session.js'
import { signMagicToken, verifyMagicToken, buildVerifyUrl, sendMagicLink } from './auth/magic.js'
import { tenantBase, normalizedTenant, verifyIdToken, requireConfig } from './auth/entra.js'

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
// Tighter limit for sending magic links — throttle per IP + email to prevent email bombing.
const magicLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  // ipKeyGenerator normalizes IPv6 so per-IP+email limits can't be bypassed.
  keyGenerator: (req) => `${ipKeyGenerator(req.ip)}|${String(req.body?.email || '').toLowerCase()}`,
})
const smartsheetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
})

/** Normalize a returnTo into a safe same-origin path (never an absolute/cross-origin URL). */
function safeReturnPath(returnTo) {
  const r = String(returnTo || '/').slice(0, 2048)
  if (r.startsWith('http')) return '/'
  return r.startsWith('/') ? r : `/${r}`
}

/**
 * Entry point. In magic-only mode this bounces to the SPA's email login page; when Entra
 * is enabled it starts the Microsoft OAuth redirect (with state + nonce + S256 PKCE).
 */
app.get('/auth/login', authLimiter, (req, res) => {
  const returnTo = String(req.query.returnTo || '/').slice(0, 2048)

  if (!entraEnabled) {
    // Magic mode: the SPA owns the email-entry UI.
    return res.redirect(`${allowedOrigin}/login?returnTo=${encodeURIComponent(returnTo)}`)
  }

  if (!clientId || !String(clientSecret || '').trim() || !redirectUri || !sessionSecret) {
    const msg =
      'Skyport-Core needs AUTH_MICROSOFT_ENTRA_ID_SECRET in .env or .env.local (plus ID, tenant, OAUTH_REDIRECT_URI, SESSION_SECRET). Restart Core after edits.'
    return res.redirect(`${allowedOrigin}/?skyport_core_setup=1&msg=${encodeURIComponent(msg)}`)
  }

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

/**
 * Magic-link request: validate domain, sign a short-lived token, email the verify link.
 * Always 200 for allowed domains; 403 for disallowed domains (domain-based, safe to reveal).
 */
app.post('/auth/login/email', magicLoginLimiter, async (req, res) => {
  noStoreHeaders(res)
  if (!magicEnabled) return res.status(404).json({ error: 'not_found' })

  const email = String(req.body?.email || '').trim().toLowerCase()
  const returnTo = String(req.body?.returnTo || '/').slice(0, 2048)
  if (!isValidEmail(email)) return res.status(400).json({ error: 'invalid_email' })
  if (!isEmailAllowed(email)) return res.status(403).json({ error: 'domain_not_allowed' })

  try {
    const token = await signMagicToken({ email, name: deriveNameFromEmail(email) })
    const url = buildVerifyUrl(token, returnTo)
    const { delivered } = await sendMagicLink(email, url)
    return res.json({ ok: true, delivered })
  } catch (err) {
    console.error('[magic] send failed:', err?.message || err)
    return res.status(502).json({ error: 'send_failed' })
  }
})

/** Magic-link verification: validate the token, then issue the session cookie. */
app.get('/auth/verify', authLimiter, async (req, res) => {
  noStoreHeaders(res)
  if (!magicEnabled) return res.status(404).json({ error: 'not_found' })

  const token = String(req.query.token || '')
  const returnTo = String(req.query.returnTo || '/')
  const payload = await verifyMagicToken(token)
  if (!payload || !payload.email) {
    return res.redirect(`${allowedOrigin}/?auth_error=invalid_or_expired_link`)
  }
  const email = String(payload.email).toLowerCase()
  if (!isEmailAllowed(email)) {
    return res.redirect(`${allowedOrigin}/?auth_error=domain_not_allowed`)
  }
  await issueSession(res, {
    sub: email,
    email,
    name: payload.name || deriveNameFromEmail(email),
  })
  res.redirect(303, `${allowedOrigin}${safeReturnPath(returnTo)}`)
})

/** Microsoft Entra OAuth callback (Web redirect URI). */
app.get('/oauth/callback', authLimiter, async (req, res) => {
  noStoreHeaders(res)
  if (!entraEnabled) return res.status(404).json({ error: 'not_found' })
  if (!requireConfig(res)) return

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
      return res.redirect(`${allowedOrigin}/?auth_error=access_denied&detail=${encodeURIComponent(detail)}`)
    }

    await issueSession(res, claims)
    res.redirect(`${allowedOrigin}${safeReturnPath(returnTo)}`)
  } catch (err) {
    console.error('[oauth] callback error:', err?.message || err)
    return res.redirect(`${allowedOrigin}/?auth_error=server_error`)
  }
})

/**
 * Primary logout: browser POST (form from web app). Full navigation processes Set-Cookie
 * reliably; 303 back to web. GET is intentionally not supported (CDN-cacheable + CSRF-able).
 */
app.post('/auth/logout', (req, res) => {
  noStoreHeaders(res)
  if (!isAllowedRequestOrigin(req)) {
    return res.status(403).json({ error: 'forbidden_origin' })
  }
  clearSessionCookie(res)
  res.redirect(303, `${allowedOrigin}/?signed_out=1`)
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

/** Validate required env at boot. Fail fast for standalone prod; log (don't crash) on serverless. */
function validateConfigAtBoot() {
  const problems = []
  if (!sessionSecret) {
    problems.push('SESSION_SECRET')
  } else if (String(sessionSecret).length < 32) {
    problems.push('SESSION_SECRET (must be at least 32 characters)')
  }
  if (entraEnabled) {
    if (!clientId) problems.push('AUTH_MICROSOFT_ENTRA_ID_ID')
    if (!clientSecret || !String(clientSecret).trim()) problems.push('AUTH_MICROSOFT_ENTRA_ID_SECRET')
    if (!redirectUri) problems.push('OAUTH_REDIRECT_URI')
  }
  if (isProd && allowedDomains.length === 0 && !allowAnyEmail) {
    problems.push(
      'OAUTH_ALLOWED_MICROSOFT_EMAIL_DOMAINS / AUTH_ALLOWED_EMAIL_DOMAINS (empty in production; set it or OAUTH_ALLOW_ANY_EMAIL=1)'
    )
  }
  if (magicEnabled && isProd && !resendApiKey) {
    console.warn('[env] AUTH_MODE=magic but RESEND_API_KEY is unset — magic links will only be logged, not emailed.')
  }

  if (problems.length) {
    const msg = `[env] Invalid/missing configuration: ${problems.join(', ')}`
    if (isProd && !isServerless) {
      console.error(msg)
      console.error('[env] Refusing to start in production with invalid auth configuration.')
      process.exit(1)
    } else if (isProd) {
      console.error(msg)
      console.error('[env] Auth will fail closed until configuration is fixed.')
    } else {
      console.warn(msg)
    }
  }
  if (entraEnabled && !isProd && (!normalizedTenant || normalizedTenant === 'common')) {
    console.warn(
      '[env] AUTH_MICROSOFT_ENTRA_ID_TENANT is "common" — any Microsoft tenant can sign in. Pin a tenant GUID in production.'
    )
  }
}

validateConfigAtBoot()

app.listen(Number(PORT), () => {
  console.log(`Skyport-Core listening on http://localhost:${PORT}`)
  console.log(
    `[auth] mode=${authMode} magic=${magicEnabled} entra=${entraEnabled} sessionSecret=${Boolean(sessionSecret)} crossSiteSession=${crossSiteSession} sessionTtlSeconds=${sessionTtlSeconds}`
  )
  if (magicEnabled) {
    console.log(
      `[magic] ttlSeconds=${magicTtlSeconds} emailProvider=${resendApiKey ? 'resend' : 'console-log (no provider)'} from=${emailFrom}`
    )
  }
  if (entraEnabled) {
    console.log(`[entra] tenant=${normalizedTenant} redirectUri=${redirectUri || '(set OAUTH_REDIRECT_URI)'}`)
  }
  console.log(
    `[policy] allowedDomains=${allowedDomains.join(',') || '(none)'} adminEmails=${adminEmails.size} allowAnyEmail=${allowAnyEmail}`
  )
})
