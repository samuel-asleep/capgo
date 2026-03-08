# Security Advisories

## Overview (AI generated)

This directory contains documented security vulnerabilities found during an automated security audit of the Capgo codebase. Each vulnerability was **tested and verified** against a local Supabase instance before being documented.

## Test Results Summary (AI generated)

| # | Vulnerability | Severity | Test Result | File |
|---|---------------|----------|-------------|------|
| 1 | [CORS Wildcard Origin](./CORS_WILDCARD_ORIGIN.md) | Medium | 🔴 Confirmed | `utils/hono.ts:104` |
| 2 | [Admin Impersonation No Rate Limit](./ADMIN_IMPERSONATION_NO_RATE_LIMIT.md) | Medium | 🔴 Confirmed | `private/log_as.ts:15` |
| 3 | [Insufficient Auth Rate Limiting](./INSUFFICIENT_AUTH_RATE_LIMITING.md) | Low | 🔴 Confirmed | `utils/rate_limit.ts:11` |
| 4 | [Webhook Data Exposure](./WEBHOOK_DATA_EXPOSURE.md) | Medium | 🔴 Confirmed | `utils/webhook.ts:105` |
| 5 | [Stack Trace in Production Logs](./STACK_TRACE_IN_PRODUCTION_LOGS.md) | Low | 🔴 Confirmed | `utils/logging.ts:19` |
| 6 | [localStorage JWT Storage](./LOCALSTORAGE_JWT_STORAGE.md) | Low | 🔴 Confirmed | `src/services/supabase.ts:92` |

## Verified as Safe (AI generated)

The following areas were tested and found to be properly secured:

| Area | Test | Result |
|------|------|--------|
| Open Redirect (confirm-signup) | Checked `isAllowedConfirmationUrl()` validation | ✅ Safe — allowedHost validation in place |
| Error Information Disclosure | Sent malformed requests to API endpoints | ✅ Safe — no stack traces in responses |
| Unauthenticated Endpoint Access | Called `/app` without auth headers | ✅ Safe — returns HTTP 401 |
| Non-Admin Privilege Escalation | Called `log_as` with non-admin JWT | ✅ Safe — returns HTTP 400 |
| SQL Injection | Code uses Drizzle ORM with parameterized queries | ✅ Safe |
| SSRF in Webhooks | Webhook URL validation blocks localhost/IP/non-HTTPS | ✅ Safe |
| Stripe Webhook Verification | Signature verification present | ✅ Safe |
| Timing-Safe API Secret Comparison | Uses `timingSafeEqual` from hono | ✅ Safe |

## How Tests Were Performed (AI generated)

All vulnerabilities were verified against a running local Supabase instance:

1. Started local Supabase with `bun run supabase:start`
2. Seeded database with `bun run supabase:db:reset`
3. Started backend functions with `bun backend`
4. Executed HTTP-based tests against `http://127.0.0.1:56071/functions/v1`
5. Code review was performed for issues that cannot be tested via HTTP

Test accounts used:
- `test@capgo.app` (regular user)
- `admin@capgo.app` (admin user)

## Disclosure (AI generated)

These findings follow the [Capgo Bug Bounty](https://capgo.app/bug-bounty/) program guidelines. Each advisory includes exact file paths, line numbers, and reproducible proof of concept.
