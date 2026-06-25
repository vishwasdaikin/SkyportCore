/** Session issuance/verification, cookie helpers, and the route guards. */
import crypto from 'crypto'
import * as jose from 'jose'
import {
  sessionSecret,
  sessionTtlSeconds,
  SESSION_COOKIE,
  HANDSHAKE_COOKIE_OPTS,
  COOKIE,
  crossSiteSession,
  corsAllowed,
} from './config.js'
import { roleForEmail } from './policy.js'

export function noStoreHeaders(res) {
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    Pragma: 'no-cache',
    Expires: '0',
    'CDN-Cache-Control': 'no-store',
    'Vercel-CDN-Cache-Control': 'no-store',
  })
}

export function safeEqual(a, b) {
  const ba = Buffer.from(String(a == null ? '' : a))
  const bb = Buffer.from(String(b == null ? '' : b))
  if (ba.length !== bb.length) return false
  return crypto.timingSafeEqual(ba, bb)
}

/** Reject state-changing requests whose Origin/Referer is not an allowed frontend (CSRF defense for SameSite=None). */
export function isAllowedRequestOrigin(req) {
  const origin = req.get('origin')
  if (origin) return corsAllowed.includes(origin.replace(/\/$/, ''))
  const referer = req.get('referer')
  if (referer) return corsAllowed.some((a) => referer === a || referer.startsWith(a + '/'))
  // No Origin/Referer (some same-origin form posts / non-browser clients) — allow.
  return true
}

export const secretKey = () => {
  if (!sessionSecret) throw new Error('SESSION_SECRET is not set')
  return new TextEncoder().encode(sessionSecret)
}

export async function signSession(payload) {
  return new jose.SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${sessionTtlSeconds}s`)
    .sign(secretKey())
}

export async function verifySession(token) {
  try {
    const { payload } = await jose.jwtVerify(token, secretKey(), { algorithms: ['HS256'] })
    return payload
  } catch {
    return null
  }
}

/** Single seam every provider funnels through: turn verified claims into a session cookie. */
export async function issueSession(res, { sub, email, name }) {
  const role = roleForEmail(email)
  const jwt = await signSession({ sub, email, name, role })
  res.cookie(COOKIE, jwt, { ...SESSION_COOKIE, maxAge: sessionTtlSeconds * 1000 })
  return { role }
}

export function clearSessionCookie(res) {
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

export function clearHandshakeCookie(res, name) {
  res.clearCookie(name, HANDSHAKE_COOKIE_OPTS)
  res.cookie(name, '', { ...HANDSHAKE_COOKIE_OPTS, maxAge: 0, expires: new Date(0) })
}

/** Centralized guard: validates the session cookie and attaches req.user. */
export async function requireAuth(req, res, next) {
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
export function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ authenticated: false })
    if (req.user.role !== role) return res.status(403).json({ error: 'forbidden' })
    next()
  }
}
