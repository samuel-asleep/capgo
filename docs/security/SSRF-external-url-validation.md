# Security Vulnerability Report: SSRF via Unvalidated External Bundle URL

**Severity**: High (latent) / Medium (current state without server-side fetch)
**Type**: Server-Side Request Forgery (SSRF) + Defense-in-Depth Gap
**Component**: `supabase/functions/_backend/public/bundle/create.ts`
**Secondary**: `supabase/functions/_backend/public/bundle/update_metadata.ts` (missing authorization check)
**Status**: Fixed

---

## Summary

The `validateUrlFormat` function in the bundle creation endpoint only verified that
user-supplied external URLs began with `https://`. It did **not** validate that the URL
hostname resolves to a public, routable address. This allowed any authenticated user
with upload access to register a bundle whose download URL pointed at an internal
network resource (private RFC 1918 range, loopback, cloud instance-metadata endpoint,
etc.).

A second, related finding is that `update_metadata.ts` lacked an explicit
application-level RBAC check (`checkPermission`), relying solely on Supabase RLS for
authorization.

---

## Vulnerability 1 – SSRF via Unvalidated `external_url`

### Affected Code (before fix)

```typescript
// supabase/functions/_backend/public/bundle/create.ts

function validateUrlFormat(url: string) {
  if (!url.startsWith('https://')) {
    throw simpleError('invalid_protocol', 'External URL must use HTTPS protocol', { external_url: url })
  }
  // ← No hostname or IP validation
}
```

### Exploit Scenario

1. Attacker authenticates with a valid upload API key for any app they legitimately own.
2. Attacker calls `POST /bundle` with:
   ```json
   {
     "app_id": "com.attacker.app",
     "version": "1.0.0-exploit",
     "checksum": "<valid-checksum>",
     "external_url": "https://169.254.169.254/latest/meta-data/"
   }
   ```
3. The malicious URL passes the `https://` prefix check and is stored in `app_versions.external_url`.
4. **Current impact (without server-side fetch)**: The internal URL is stored in the database
   and delivered to devices as their update download target. Devices attempting to download
   the bundle will try to reach the internal address; on corporate/enterprise networks where
   mobile devices have access to internal ranges, this could succeed and expose internal data.
5. **Elevated impact when `verifyUrlAccessibility` is re-enabled**: The commented-out code
   in `create.ts` calls `verifyUrlAccessibility(body.external_url)`, which performs a
   server-side HEAD request to the URL. Re-enabling this function without hostname
   validation would instantly enable full server-side SSRF against any address reachable
   from the Cloudflare Workers / Supabase Edge runtime, including:
   - AWS EC2 instance metadata service: `http://169.254.169.254/latest/meta-data/`
   - GCP metadata server: `http://metadata.google.internal/computeMetadata/v1/`
   - Azure IMDS: `http://169.254.169.254/metadata/instance`
   - Any private service on `10.x.x.x`, `172.16.x.x–172.31.x.x`, `192.168.x.x`

### Root Cause

`validateUrlFormat` performed only a string prefix check (`url.startsWith('https://')`).
It did not parse the URL, extract the hostname, or validate it against known-safe address
spaces.

### Impact

| Scenario | Severity |
|----------|----------|
| Server-side fetch enabled (verifyUrlAccessibility uncommented) | **Critical** – full SSRF, potential credential/secrets exfiltration from cloud metadata |
| Server-side fetch disabled (current state) | **Medium** – malicious URL stored and served to devices; enterprise devices may reach internal hosts |
| URL with embedded credentials stored/logged | **Medium** – credential leakage in logs, DB, and device telemetry |

---

## Vulnerability 2 – Missing `checkPermission` in `update_metadata.ts`

### Affected Code (before fix)

```typescript
// supabase/functions/_backend/public/bundle/update_metadata.ts
app.post('/', middlewareKey(['all', 'write']), async (c) => {
  // ← No checkPermission call; relied solely on Supabase RLS
  const { data: version, error: versionError } = await supabaseApikey(c, apikey.key)
    .from('app_versions')
    .select('*')
    .eq('app_id', body.app_id)
    .eq('id', body.version_id)
    .single()
  // ...
})
```

### Description

Every other mutation endpoint in the `bundle/` family calls `checkPermission(c, ...)` as
an explicit, application-level gate before touching the database. The `update_metadata`
endpoint was the sole exception. While Supabase RLS (using `get_identity_org_appid`)
provides a database-level control, omitting the application-level check breaks
defense-in-depth and means:

- Any future change to the RLS policy (migration, bug, drift) immediately makes this
  endpoint vulnerable.
- There is no centrally-auditable log of *application-level* authorization decisions for
  this operation.

---

## Fix

### Vulnerability 1 – `validateUrlFormat` hardening

Added IP and hostname validation to `validateUrlFormat`:

1. **Reject embedded credentials** (`user:pass@host`).
2. **Reject `localhost`** and known internal hostnames
   (`metadata.google.internal`, `instance-data`, `169.254.169.254`, `169.254.170.2`).
3. **Reject private/reserved IPv4 ranges**:
   - `127.0.0.0/8` (loopback)
   - `169.254.0.0/16` (link-local; covers all cloud metadata endpoints)
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918)
   - `100.64.0.0/10` (CGNAT/shared address space)
   - `0.0.0.0/8` (unspecified)
4. **Reject private/reserved IPv6 addresses**:
   - `::1` (loopback)
   - `::` (unspecified)
   - `fc00::/7` (unique local)
   - `fe80::/10` (link-local)
   - IPv4-mapped IPv6 (`::ffff:192.168.x.x`)

### Vulnerability 2 – Add `checkPermission` to `update_metadata.ts`

Added an explicit `checkPermission(c, 'app.upload_bundle', { appId: body.app_id })`
call before any database access, consistent with all other bundle mutation endpoints.

---

## Tests Added

New tests in `tests/bundle-create.test.ts`:

- `should reject AWS metadata endpoint (169.254.169.254) – SSRF protection`
- `should reject localhost – SSRF protection`
- `should reject loopback IPv4 (127.0.0.1) – SSRF protection`
- `should reject RFC 1918 private IPv4 10.x – SSRF protection`
- `should reject RFC 1918 private IPv4 192.168.x – SSRF protection`
- `should reject RFC 1918 private IPv4 172.16.x – SSRF protection`
- `should reject GCP metadata endpoint (metadata.google.internal) – SSRF protection`
- `should reject URL with embedded credentials – SSRF protection`
- `should reject IPv6 loopback [::1] – SSRF protection`

All tests assert HTTP 400 with `error: 'invalid_hostname'` (or `'invalid_url_credentials'`
for the credentials case).

---

## Backward Compatibility

No breaking change for legitimate callers. All valid public HTTPS URLs (e.g., GitHub
Releases, CDN hostnames) continue to be accepted. Only URLs pointing to private/internal
addresses or containing embedded credentials are newly rejected.

---

## References

- OWASP SSRF Prevention Cheat Sheet: <https://cheatsheats.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- AWS IMDSv1 SSRF: <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html>
- RFC 1918: <https://datatracker.ietf.org/doc/html/rfc1918>
