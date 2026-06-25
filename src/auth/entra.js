/** Microsoft Entra OAuth confidential flow (dormant unless AUTH_MODE includes "entra"). */
import * as jose from 'jose'
import { clientId, clientSecret, redirectUri, sessionSecret, tenant } from './config.js'
import { safeEqual } from './session.js'

/**
 * Vercel often has the full issuer URL pasted into the tenant var — that produced
 * login.microsoftonline.com/https://login.microsoftonline.com/.../v2.0 → 404.
 * Accept tenant GUID, or full issuer URL; always emit a single authority host.
 */
export function normalizeTenantId(raw) {
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

export const normalizedTenant = normalizeTenantId(tenant)
export const isGuidTenant = /^[a-f0-9-]{36}$/i.test(normalizedTenant)

export function tenantBase() {
  return `https://login.microsoftonline.com/${normalizedTenant}`
}

/** JWKS for verifying Microsoft-issued ID tokens; jose caches keys internally. */
const idTokenJwks = jose.createRemoteJWKSet(new URL(`${tenantBase()}/discovery/v2.0/keys`))

export function requireConfig(res) {
  if (!clientId || !clientSecret || !redirectUri || !sessionSecret) {
    res.status(500).json({
      error:
        'Missing env: AUTH_MICROSOFT_ENTRA_ID_ID, AUTH_MICROSOFT_ENTRA_ID_SECRET, OAUTH_REDIRECT_URI, SESSION_SECRET',
    })
    return false
  }
  return true
}

/** Verify the Microsoft ID token signature + claims (sig via JWKS, aud, exp, nonce, iss for GUID tenants). */
export async function verifyIdToken(idToken, expectedNonce) {
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
