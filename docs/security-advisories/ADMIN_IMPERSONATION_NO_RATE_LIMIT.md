# Security Advisory: Admin Impersonation Endpoint Missing Rate Limiting

## Summary (AI generated)

The `/private/log_as` endpoint allows admin users to generate JWT tokens for any user account with no rate limiting, enabling rapid bulk impersonation without throttling.

## Severity

**Medium** — CVSS 5.9 (AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N)

## Affected Component

- **File:** `supabase/functions/_backend/private/log_as.ts`
- **Lines:** 15–72
- **Code:**
  ```typescript
  app.post('/', middlewareAuth, async (c) => {
    // ... validates admin via is_admin() RPC
    // ... generates magic link and returns JWT
    // No rate limiting middleware applied
    return c.json({ jwt, refreshToken })
  })
  ```

## Description

The `log_as` endpoint allows admin users to impersonate any user by generating a valid JWT token for that user's account. The endpoint:

1. Has **no rate limiting** — an admin (or an attacker with a compromised admin token) can call it hundreds of times per second
2. Has **no audit logging** — no record is created of who was impersonated, when, or by whom
3. Returns a **full JWT + refresh token** — giving complete session access to the impersonated user's account

## Proof of Concept

### Test Performed

Sent 10 rapid successive requests to the `log_as` endpoint:

```bash
for i in $(seq 1 10); do
  curl -s -w "%{http_code}\n" -X POST "$BASE_URL/private/log_as" \
    -H "Authorization: Bearer $ADMIN_JWT" \
    -H "Content-Type: application/json" \
    -d '{"user_id":"6aa76066-55ef-4238-ade6-0b32334a4097"}'
done
```

### Result

```
Sent 10 rapid log_as requests. Successes: 10/10
```

All 10 requests succeeded with HTTP 200 and returned valid JWT tokens. No request was rate-limited or blocked.

### Verified: Non-Admin Cannot Use Endpoint

```bash
curl -s -w "%{http_code}" -X POST "$BASE_URL/private/log_as" \
  -H "Authorization: Bearer $NON_ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"6aa76066-55ef-4238-ade6-0b32334a4097"}'
```

Result: `HTTP 400` — Non-admin users are properly rejected.

## Impact

- If an admin account is compromised, the attacker can silently impersonate every user in the system
- No rate limit means automated mass impersonation is possible
- No audit trail means the impersonation cannot be detected after the fact
- Compliance risk: admin impersonation without logging violates SOC 2 and GDPR accountability requirements

## Recommended Fix

1. **Add rate limiting**: Limit to 5 impersonations per admin per hour
2. **Add audit logging**: Record `admin_user_id`, `target_user_id`, `timestamp`, `ip_address` to an immutable audit table
3. **Require MFA re-verification**: Before generating the impersonation token

## References

- [OWASP: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
