# Security Advisory: Stack Traces Serialized to Production Logs

## Summary (AI generated)

The `serializeError()` function in the logging utility includes `err.stack` in the serialized error output, which is sent to production logging infrastructure and may expose internal file paths and code structure.

## Severity

**Low** — CVSS 3.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

## Affected Component

- **File:** `supabase/functions/_backend/utils/logging.ts`
- **Line:** 19
- **Code:**
  ```typescript
  export function serializeError(err: unknown) {
    if (err instanceof Error) {
      return { name: err.name, message: err.message, stack: err.stack, cause: err.cause ? String(err.cause) : undefined }
    }
    // ...
  }
  ```

## Description

The `serializeError()` function captures the full JavaScript stack trace (`err.stack`) from Error objects and includes it in the serialized output. This function is used throughout the backend to log errors to Cloudflare Workers logs and other logging infrastructure.

Stack traces contain:
- Internal file paths revealing project structure
- Line numbers revealing code organization
- Function names revealing business logic naming

While these stack traces are sent to **logs** (not to API responses — which was verified as safe), any compromise of the logging infrastructure would expose detailed internal code structure.

## Proof of Concept

### Code Review Evidence

```bash
$ grep -n "stack" /home/runner/work/capgo/capgo/supabase/functions/_backend/utils/logging.ts
19:    return { name: err.name, message: err.message, stack: err.stack, ... }
22:    return { message: JSON.stringify(err, ...), stack: undefined, ... }
25:    return { message: String(err), stack: undefined, ... }
```

Line 19 includes `err.stack` in the serialized output for all `Error` instances. Lines 22 and 25 correctly set `stack: undefined` for non-Error types.

### API Response Check (SAFE)

```bash
$ curl -s -X POST "$BASE_URL/app" -H "Content-Type: application/json" -d '{"malformed": true}'
{"error":"no_key_provided","message":"No key provided","moreInfo":{}}
```

Stack traces are **not** leaked to API consumers — only to backend logs.

## Impact

- If Cloudflare Workers logs, log aggregation services, or monitoring dashboards are compromised, attackers gain detailed knowledge of the internal code structure
- File paths reveal the project layout and deployment configuration
- Function names in stack traces reveal business logic naming conventions
- This information assists attackers in crafting more targeted exploits

## Recommended Fix

Strip or truncate stack traces before logging in production:

```typescript
export function serializeError(err: unknown) {
  if (err instanceof Error) {
    return {
      name: err.name,
      message: err.message,
      stack: undefined, // Do not log stack traces in production
      cause: err.cause ? String(err.cause) : undefined,
    }
  }
  // ...
}
```

Or conditionally include stack traces only in development:

```typescript
stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
```

## References

- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [OWASP: Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling)
