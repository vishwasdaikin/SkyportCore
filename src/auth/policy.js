/** Sign-in policy: domain allowlist, role assignment, and email helpers (provider-agnostic). */
import { allowedDomains, adminEmails, isProd, allowAnyEmail } from './config.js'

export function emailDomain(email) {
  if (!email || typeof email !== 'string') return ''
  const at = email.lastIndexOf('@')
  return at >= 0 ? email.slice(at + 1).toLowerCase() : ''
}

export function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || ''))
}

export function isEmailAllowed(email) {
  if (allowedDomains.length === 0) {
    // Default-open is only permitted outside production, or with an explicit opt-in.
    return !isProd || allowAnyEmail
  }
  return allowedDomains.includes(emailDomain(email))
}

export function roleForEmail(email) {
  return email && adminEmails.has(String(email).toLowerCase()) ? 'admin' : 'editor'
}

/** Best-effort display name from the email local-part (e.g. "jordan.grosso" → "Jordan Grosso"). */
export function deriveNameFromEmail(email) {
  const local = String(email || '').split('@')[0] || ''
  if (!local) return ''
  return local
    .split(/[._-]+/)
    .filter(Boolean)
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join(' ')
}
