# Security Advisory: Webhook Payload Data Exposure

## Summary (AI generated)

Webhook payloads include raw `old_record` and `new_record` database objects without any field-level filtering, potentially exposing sensitive data fields to external webhook consumers.

## Severity

**Medium** — CVSS 4.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)

## Affected Component

- **File:** `supabase/functions/_backend/utils/webhook.ts`
- **Lines:** 17–18, 30–31, 105–106
- **Code:**
  ```typescript
  // From WebhookPayload interface (lines 17-18)
  export interface WebhookPayload {
    // ...
    data: {
      table: string
      operation: string
      record_id: string
      old_record: any | null
      new_record: any | null
      changed_fields: string[] | null
    }
  }

  // From payload assembly (lines 105-106)
  old_record: auditLogData.old_record,
  new_record: auditLogData.new_record,
  ```

## Description

When webhook events are triggered (e.g., on app update, bundle creation, channel change), the system sends the complete database records (`old_record` and `new_record`) to the configured webhook URL without any field-level filtering or sanitization.

A code review of `webhook.ts` confirmed:
- No `filter`, `sanitize`, `redact`, or `exclude` logic exists anywhere in the webhook delivery pipeline
- The `old_record` and `new_record` fields are typed as `any` with no schema enforcement
- Whatever fields exist in the database row are passed through verbatim

## Proof of Concept

### Code Review Evidence

```bash
$ grep -n "filter\|sanitize\|redact\|exclude.*field\|sensitive" webhook.ts
# (no results)

$ grep -n "old_record\|new_record" webhook.ts
17:    old_record: any | null
18:    new_record: any | null
30:  old_record: any | null
31:  new_record: any | null
105:      old_record: auditLogData.old_record,
106:      new_record: auditLogData.new_record,
467:      old_record: null,
468:      new_record: {
```

No filtering or redaction logic exists. Records are passed directly from the database audit log to the webhook payload.

## Impact

- If webhook URLs are configured to third-party services, those services receive full database records
- Records may contain internal identifiers, configuration settings, or metadata not intended for external consumers
- If a webhook endpoint is compromised, all data from triggered events is exposed
- Webhook data is sent over HTTPS but to potentially untrusted endpoints

## Recommended Fix

1. Implement a field allowlist per table that specifies which fields can be included in webhook payloads
2. Add a `sanitizeRecord()` function that strips internal/sensitive fields before building the payload
3. Allow webhook creators to configure which fields they want to receive
4. Example:
   ```typescript
   function sanitizeWebhookRecord(table: string, record: any): any {
     const allowedFields = WEBHOOK_FIELD_ALLOWLIST[table]
     if (!allowedFields) return {}
     return Object.fromEntries(
       Object.entries(record).filter(([key]) => allowedFields.includes(key))
     )
   }
   ```

## References

- [OWASP: Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
