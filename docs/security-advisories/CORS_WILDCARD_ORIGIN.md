# Security Advisory: Overly Permissive CORS Configuration

## Summary (AI generated)

All backend API endpoints respond with `Access-Control-Allow-Origin: *`, allowing any website to make authenticated cross-origin requests to the Capgo API.

## Severity

**Medium** — CVSS 5.4 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N)

## Affected Component

- **File:** `supabase/functions/_backend/utils/hono.ts`
- **Lines:** 104–108
- **Code:**
  ```typescript
  export const useCors = cors({
    origin: '*',
    allowHeaders: ['Content-Type', 'Authorization', 'capgkey', 'capgo_api', 'x-api-key', 'x-limited-key-id', 'apisecret', 'apikey', 'x-client-info'],
    allowMethods: ['POST', 'GET', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  })
  ```

## Description

The CORS middleware is configured with `origin: '*'`, which tells browsers that **any** website origin is permitted to make cross-origin requests to the API. Combined with the allowed headers list (which includes `Authorization`, `capgkey`, `apikey`, `apisecret`, and `x-api-key`), this means a malicious website could make authenticated API calls on behalf of a user who visits it.

## Proof of Concept

### Test Performed

```bash
curl -s -i -X OPTIONS "http://127.0.0.1:56071/functions/v1/app" \
  -H "Origin: https://evil-attacker.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type,Authorization"
```

### Result

```
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: Content-Type,Authorization
Access-Control-Allow-Methods: POST,GET,PUT,PATCH,DELETE,OPTIONS
```

The server responds with `Access-Control-Allow-Origin: *` regardless of the requesting origin, including `https://evil-attacker.com`.

### Verified Against Multiple Endpoints

| Endpoint   | Origin Tested              | `Access-Control-Allow-Origin` |
|------------|----------------------------|-------------------------------|
| `/app`     | `https://evil-attacker.com`| `*`                           |
| `/bundle`  | `https://phishing-site.com`| `*`                           |

## Impact

- A malicious website could trick a logged-in Capgo user into visiting it, then silently make API calls to Capgo's backend using the user's session credentials
- The attacker's page could read app data, list bundles, modify channels, or perform other API actions the user is authorized for
- This is limited by the fact that `Access-Control-Allow-Credentials` is not set to `true`, so cookie-based auth is not affected, but token/API key auth in headers is

## Recommended Fix

Restrict the CORS `origin` to known Capgo frontend domains:

```typescript
export const useCors = cors({
  origin: ['https://web.capgo.app', 'https://capgo.app'],
  allowHeaders: ['Content-Type', 'Authorization', 'capgkey', 'capgo_api', 'x-api-key', 'x-limited-key-id', 'apisecret', 'apikey', 'x-client-info'],
  allowMethods: ['POST', 'GET', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
})
```

## References

- [MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [OWASP: CORS Misconfiguration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
