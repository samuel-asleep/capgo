import { describe, expect, it } from 'vitest'
import { getClientIP } from '../supabase/functions/_backend/utils/rate_limit.ts'

/**
 * Unit tests for getClientIP – verifying that the function is resistant to
 * IP-spoofing via the x-forwarded-for header.
 *
 * Security context: getClientIP is used by the IP-based rate limiter that
 * protects unauthenticated endpoints such as /private/validate_password_compliance.
 * Using the LAST value in x-forwarded-for (added by the infrastructure proxy)
 * rather than the first (which a client can prepend with a forged address)
 * makes it harder for an attacker to bypass rate limiting.
 */

function makeContext(headers: Record<string, string>) {
  return {
    req: {
      header: (name: string) => headers[name.toLowerCase()] ?? undefined,
    },
    get: (_unusedKey: string) => 'test-request-id',
  } as any
}

describe('getClientIP', () => {
  it('uses cf-connecting-ip when present (Cloudflare path)', () => {
    const c = makeContext({ 'cf-connecting-ip': '1.2.3.4' })
    expect(getClientIP(c)).toBe('1.2.3.4')
  })

  it('prefers cf-connecting-ip over x-forwarded-for', () => {
    const c = makeContext({
      'cf-connecting-ip': '1.2.3.4',
      'x-forwarded-for': '9.9.9.9',
    })
    expect(getClientIP(c)).toBe('1.2.3.4')
  })

  it('returns the LAST IP in x-forwarded-for when cf-connecting-ip is absent', () => {
    // Infrastructure proxy appends the real client IP; attacker can prepend
    // a forged IP as the first entry. Taking the last entry defeats this.
    const c = makeContext({ 'x-forwarded-for': 'spoofed-ip, real-client-ip' })
    expect(getClientIP(c)).toBe('real-client-ip')
  })

  it('handles a single IP in x-forwarded-for', () => {
    const c = makeContext({ 'x-forwarded-for': '10.0.0.5' })
    expect(getClientIP(c)).toBe('10.0.0.5')
  })

  it('handles many IPs in x-forwarded-for and takes the last one', () => {
    const c = makeContext({ 'x-forwarded-for': '1.1.1.1, 2.2.2.2, 3.3.3.3' })
    expect(getClientIP(c)).toBe('3.3.3.3')
  })

  it('trims whitespace from the selected x-forwarded-for entry', () => {
    const c = makeContext({ 'x-forwarded-for': '1.1.1.1,   203.0.113.42   ' })
    expect(getClientIP(c)).toBe('203.0.113.42')
  })

  it('falls back to x-real-ip when x-forwarded-for is absent', () => {
    const c = makeContext({ 'x-real-ip': '203.0.113.1' })
    expect(getClientIP(c)).toBe('203.0.113.1')
  })

  it('returns unknown when no IP headers are present', () => {
    const c = makeContext({})
    expect(getClientIP(c)).toBe('unknown')
  })
})
