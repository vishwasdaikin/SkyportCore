/**
 * Central auth configuration: loads env once and exposes parsed/derived settings.
 * Leaf module — imported by every other auth module, so env is loaded before use.
 */
import dotenv from 'dotenv'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

// Load .env, then .env.local — only non-empty .env.local keys override (empty lines won't wipe .env secrets).
const coreRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
dotenv.config({ path: join(coreRoot, '.env') })
const localEnv = dotenv.config({ path: join(coreRoot, '.env.local') })
if (localEnv.parsed) {
  for (const [key, value] of Object.entries(localEnv.parsed)) {
    if (value != null && String(value).trim() !== '') {
      process.env[key] = String(value).trim()
    }
  }
}

export const isProd = String(process.env.NODE_ENV || '').toLowerCase() === 'production'
// On serverless (Vercel/Lambda) a process.exit during cold start becomes an opaque
// FUNCTION_INVOCATION_FAILED. Detect it so boot validation logs instead of hard-exiting.
export const isServerless = Boolean(
  process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.LAMBDA_TASK_ROOT
)

export const PORT = process.env.PORT || '3001'

// Microsoft Entra (only required when AUTH_MODE includes "entra").
export const clientId = process.env.AUTH_MICROSOFT_ENTRA_ID_ID
export const clientSecret = process.env.AUTH_MICROSOFT_ENTRA_ID_SECRET
export const tenant = process.env.AUTH_MICROSOFT_ENTRA_ID_TENANT
export const redirectUri = process.env.OAUTH_REDIRECT_URI
export const oauthPromptEnv = process.env.OAUTH_PROMPT

export const sessionSecret = process.env.SESSION_SECRET

/**
 * AUTH_MODE selects the active identity provider(s):
 * - "magic" (default): passwordless email magic link.
 * - "entra": Microsoft Entra OAuth.
 * - "both": both enabled (/auth/login uses Entra; magic via /auth/login/email).
 */
export const authMode = String(process.env.AUTH_MODE || 'magic').toLowerCase()
export const entraEnabled = authMode === 'entra' || authMode === 'both'
export const magicEnabled = authMode === 'magic' || authMode === 'both'

export const frontendOrigin = (process.env.FRONTEND_ORIGIN || 'http://localhost:5173').replace(/\/$/, '')
export const allowedOrigin = frontendOrigin
const extraOrigins = String(process.env.FRONTEND_ORIGINS || '')
  .split(',')
  .map((s) => s.trim().replace(/\/$/, ''))
  .filter(Boolean)
export const corsAllowed = [...new Set([allowedOrigin, ...extraOrigins])]

// Sign-in policy: domain allowlist + admin emails (shared by every provider).
export const allowedDomains = String(process.env.OAUTH_ALLOWED_MICROSOFT_EMAIL_DOMAINS || process.env.AUTH_ALLOWED_EMAIL_DOMAINS || '')
  .split(',')
  .map((s) => s.trim().toLowerCase().replace(/^@/, ''))
  .filter(Boolean)
export const adminEmails = new Set(
  String(process.env.OAUTH_ADMIN_EMAILS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
)
export const allowAnyEmail = String(process.env.OAUTH_ALLOW_ANY_EMAIL || '') === '1'

// API host vs FRONTEND_ORIGIN host → cross-origin fetch needs SameSite=None session cookies.
let frontendHost = ''
try {
  frontendHost = new URL(allowedOrigin).hostname
} catch (_) {}
const coreHost = (process.env.VERCEL_URL || '').replace(/^https?:\/\//, '').split('/')[0] || ''
export const crossSiteSession =
  String(process.env.SESSION_CROSS_SITE || '') === '1' ||
  Boolean(coreHost && frontendHost && coreHost !== frontendHost)

/** Parse a duration like "30m", "8h", "7d", or raw seconds → seconds. */
export function parseTtlSeconds(raw, fallback = 8 * 3600) {
  const s = String(raw || '').trim()
  if (!s) return fallback
  const m = s.match(/^(\d+)\s*([smhd])?$/i)
  if (!m) return fallback
  const n = Number(m[1])
  const u = (m[2] || 's').toLowerCase()
  const mult = u === 's' ? 1 : u === 'm' ? 60 : u === 'h' ? 3600 : 86400
  return n * mult
}
export const sessionTtlSeconds = parseTtlSeconds(process.env.SESSION_TTL, 8 * 3600)
export const magicTtlSeconds = parseTtlSeconds(process.env.MAGIC_LINK_TTL, 10 * 60)

// Magic-link email delivery.
export const resendApiKey = String(process.env.RESEND_API_KEY || '').trim()
export const emailFrom = String(process.env.EMAIL_FROM || 'Skyport <onboarding@resend.dev>').trim()
// Verify link is served on the SPA origin so the session cookie lands first-party
// (mirrors the Entra redirect_uri going through the /api/* rewrite).
export const magicVerifyBase = String(process.env.MAGIC_VERIFY_BASE || `${allowedOrigin}/api/auth/verify`).trim()

// Cookie names.
export const COOKIE = 'skyport_session'
export const STATE_COOKIE = 'skyport_oauth_state'
export const RETURN_COOKIE = 'skyport_return_to'
export const NONCE_COOKIE = 'skyport_oauth_nonce'
export const PKCE_COOKIE = 'skyport_oauth_verifier'

/** Session cookie: lax+insecure only on localhost dev; Secure in prod or cross-site (SameSite=None needs Secure). */
export const SESSION_COOKIE = {
  httpOnly: true,
  secure: isProd || crossSiteSession,
  sameSite: crossSiteSession ? 'none' : 'lax',
  path: '/',
}

/** Short-lived OAuth handshake cookies — Lax is enough for top-level redirects. */
export const HANDSHAKE_COOKIE_OPTS = {
  httpOnly: true,
  secure: isProd || crossSiteSession,
  sameSite: 'lax',
  path: '/',
}
