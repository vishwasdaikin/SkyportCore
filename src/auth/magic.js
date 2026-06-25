/** Passwordless magic-link: short-lived signed token + provider-agnostic email delivery. */
import crypto from 'crypto'
import * as jose from 'jose'
import { magicTtlSeconds, resendApiKey, emailFrom, magicVerifyBase } from './config.js'
import { secretKey } from './session.js'

/** Magic token is a separate-purpose JWT so it can never be used as a session cookie. */
export async function signMagicToken({ email, name }) {
  return new jose.SignJWT({ purpose: 'magic', email, name })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(String(email))
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${magicTtlSeconds}s`)
    .sign(secretKey())
}

export async function verifyMagicToken(token) {
  try {
    const { payload } = await jose.jwtVerify(token, secretKey(), { algorithms: ['HS256'] })
    if (payload.purpose !== 'magic') return null
    return payload
  } catch {
    return null
  }
}

export function buildVerifyUrl(token, returnTo) {
  const u = new URL(magicVerifyBase)
  u.searchParams.set('token', token)
  if (returnTo) u.searchParams.set('returnTo', returnTo)
  return u.toString()
}

const ttlLabel = magicTtlSeconds % 60 === 0 ? `${magicTtlSeconds / 60} minutes` : `${magicTtlSeconds} seconds`

/**
 * Send the magic link. With RESEND_API_KEY set, delivers via the Resend API (no npm dep).
 * Without a provider, logs the link to the server console so the flow can be tested with
 * zero provisioning (the link shows up in Vercel logs).
 */
export async function sendMagicLink(email, url) {
  if (resendApiKey) {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${resendApiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: emailFrom,
        to: [email],
        subject: 'Your Skyport sign-in link',
        text: `Click to sign in to Skyport: ${url}\n\nThis link expires in ${ttlLabel}. If you did not request it, ignore this email.`,
        html:
          `<p>Click to sign in to Skyport:</p>` +
          `<p><a href="${url}">Sign in to Skyport</a></p>` +
          `<p style="color:#666">This link expires in ${ttlLabel}. If you did not request it, ignore this email.</p>`,
      }),
    })
    if (!res.ok) {
      const detail = await res.text().catch(() => '')
      throw new Error(`resend_failed_${res.status}: ${detail.slice(0, 200)}`)
    }
    return { delivered: 'resend' }
  }
  console.log(`[magic-link] no email provider configured — link for ${email}:\n${url}`)
  return { delivered: 'console' }
}
