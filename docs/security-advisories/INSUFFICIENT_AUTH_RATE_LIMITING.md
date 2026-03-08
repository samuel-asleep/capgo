# Security Advisory: Insufficient Failed Authentication Rate Limiting

## Summary (AI generated)

The failed authentication rate limit threshold is set to 20 attempts before blocking, which is too high to effectively prevent brute force attacks. Testing confirmed 15 consecutive failed login attempts from the same IP with no throttling.

## Severity

**Low** — CVSS 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

## Affected Component

- **File:** `supabase/functions/_backend/utils/rate_limit.ts`
- **Lines:** 10–12
- **Code:**
  ```typescript
  // Default limits - set high to catch only severe abuse, not normal usage
  const DEFAULT_FAILED_AUTH_LIMIT = 20 // 20 failed attempts before blocking (catches brute force, allows mistakes)
  const DEFAULT_API_KEY_RATE_LIMIT = 2000 // 2000 requests per minute per API key (catches infinite loops)
  ```

## Description

The application rate-limits failed authentication attempts, but the threshold of 20 failed attempts per 15-minute window is significantly higher than industry best practices (typically 3–5 attempts). This allows an attacker to make 20 password guesses per IP per 15-minute window without being blocked.

Additionally, the API key rate limit of 2,000 requests per minute per key is very permissive and could enable rapid enumeration or data exfiltration if an API key is compromised.

## Proof of Concept

### Test Performed

Sent 15 consecutive failed login attempts from the same IP:

```bash
for i in $(seq 1 15); do
  curl -s -w "%{http_code}\n" -X POST "$SUPA_URL/auth/v1/token?grant_type=password" \
    -H "apikey: $ANON_KEY" \
    -H "Content-Type: application/json" \
    -d '{"email":"brute_test_user@capgo.app","password":"wrongpassword"}'
done
```

### Result

```
15 failed auth attempts all went through without blocking
```

All 15 attempts returned HTTP 400 (invalid credentials) — none returned HTTP 429 (rate limited). The rate limit threshold of 20 was not reached.

## Impact

- An attacker can attempt 20 passwords per IP per 15-minute window
- With IP rotation (common with botnets/VPNs), this becomes unlimited
- Weak or commonly-used passwords are at higher risk of being guessed
- API key rate limit of 2,000 req/min allows significant data exfiltration before detection

## Recommended Fix

1. Reduce `DEFAULT_FAILED_AUTH_LIMIT` from 20 to 5
2. Reduce `DEFAULT_API_KEY_RATE_LIMIT` from 2000 to 600
3. Implement progressive delays (exponential backoff) after 3 failed attempts
4. Add CAPTCHA challenge after 3 failed attempts from same IP

## References

- [OWASP: Brute Force Attack](https://owasp.org/www-community/attacks/Brute_force_attack)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [NIST 800-63B Section 5.2.2](https://pages.nist.gov/800-63-3/sp800-63b.html)
