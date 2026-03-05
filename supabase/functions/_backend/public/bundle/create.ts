import type { Context } from 'hono'
import type { MiddlewareKeyVariables } from '../../utils/hono.ts'
import type { Database } from '../../utils/supabase.types.ts'
import { simpleError } from '../../utils/hono.ts'
import { checkPermission } from '../../utils/rbac.ts'
import { supabaseAdmin, supabaseApikey } from '../../utils/supabase.ts'
import { isValidAppId, isValidSemver } from '../../utils/utils.ts'

interface CreateBundleBody {
  app_id: string
  version: string
  external_url: string
  checksum: string
  session_key?: string
  key_id?: string
}

function isPrivateIPv4(hostname: string): boolean {
  const parts = hostname.split('.')
  if (parts.length !== 4)
    return false
  const nums = parts.map(Number)
  if (nums.some(n => !Number.isInteger(n) || n < 0 || n > 255))
    return false
  const [a, b] = nums
  return (
    a === 127 // 127.0.0.0/8 loopback
    || (a === 169 && b === 254) // 169.254.0.0/16 link-local (cloud metadata)
    || a === 10 // 10.0.0.0/8 RFC 1918
    || (a === 172 && b >= 16 && b <= 31) // 172.16.0.0/12 RFC 1918
    || (a === 192 && b === 168) // 192.168.0.0/16 RFC 1918
    || a === 0 // 0.0.0.0/8 unspecified
    || (a === 100 && b >= 64 && b <= 127) // 100.64.0.0/10 shared address (CGNAT)
  )
}

function isPrivateIPv6(hostname: string): boolean {
  // Strip brackets: [::1] -> ::1
  const ip = (hostname.startsWith('[') && hostname.endsWith(']')) ? hostname.slice(1, -1) : hostname
  const lower = ip.toLowerCase()
  if (lower === '::1' || lower === '::')
    return true // loopback / unspecified
  // fc00::/7 unique local (fc and fd prefixes)
  if (/^f[cd][0-9a-f]{0,2}:/i.test(lower))
    return true
  // fe80::/10 link-local (fe80 to febf)
  const m = /^fe([0-9a-f]{2})/i.exec(lower)
  if (m) {
    const octet = Number.parseInt(m[1], 16)
    if (octet >= 0x80 && octet <= 0xBF)
      return true
  }
  // IPv4-mapped IPv6: ::ffff:192.168.x.x
  if (lower.startsWith('::ffff:')) {
    const ipv4Part = lower.slice(7)
    if (isPrivateIPv4(ipv4Part))
      return true
  }
  return false
}

function validateUrlFormat(url: string) {
  if (!url.startsWith('https://')) {
    throw simpleError('invalid_protocol', 'External URL must use HTTPS protocol', { external_url: url })
  }

  let parsed: URL
  try {
    parsed = new URL(url)
  }
  catch {
    throw simpleError('invalid_url', 'External URL is not a valid URL', { external_url: url })
  }

  // Reject embedded credentials (user:pass@host)
  if (parsed.username !== '' || parsed.password !== '') {
    throw simpleError('invalid_url_credentials', 'External URL must not contain embedded credentials', { external_url: url })
  }

  const hostname = parsed.hostname.toLowerCase()

  // Reject localhost and known internal/metadata hostnames
  const blockedHostnames = [
    'localhost',
    'metadata.google.internal', // GCP
    'metadata.azure.com', // Azure
    'instance-data', // GCP metadata alternative
    '169.254.169.254', // AWS/GCP/Azure metadata (also caught by isPrivateIPv4)
    '169.254.170.2', // ECS container metadata
    '169.254.169.253', // ECS task metadata v3
  ]
  if (blockedHostnames.includes(hostname)) {
    throw simpleError('invalid_hostname', 'External URL must not point to a private or internal address', { external_url: url })
  }

  // Reject private IPv4 addresses
  if (isPrivateIPv4(hostname)) {
    throw simpleError('invalid_hostname', 'External URL must not point to a private or internal address', { external_url: url })
  }

  // Reject private/reserved IPv6 addresses
  // An IPv6 address always contains at least two colons or is wrapped in brackets
  if (hostname.startsWith('[') || hostname.includes(':')) {
    if (isPrivateIPv6(hostname)) {
      throw simpleError('invalid_hostname', 'External URL must not point to a private or internal address', { external_url: url })
    }
  }
}

// async function followRedirectsHead(url: string, maxRedirects = 5): Promise<Response> {
//   let currentUrl = url
//   let redirectCount = 0

//   while (redirectCount <= maxRedirects) {
//     const response = await ky.head(currentUrl, {
//       headers: {
//         'User-Agent': 'Capgo-Bundle-Validator/1.0',
//       },
//       timeout: 10000,
//       retry: 2,
//       throwHttpErrors: false, // Don't throw on 3xx status codes
//     })

//     // Check if it's a redirect status
//     if (response.status >= 300 && response.status < 400) {
//       const location = response.headers.get('location')
//       if (!location) {
//         throw simpleError('url_fetch_error', 'Redirect response without location header', {
//           external_url: currentUrl,
//           status: response.status,
//         })
//       }

//       // Handle relative URLs
//       currentUrl = new URL(location, currentUrl).href
//       redirectCount++

//       if (redirectCount > maxRedirects) {
//         throw simpleError('url_fetch_error', 'Too many redirects', {
//           external_url: url,
//           finalUrl: currentUrl,
//           redirectCount,
//         })
//       }
//       continue
//     }

//     // Not a redirect, return the response
//     return response
//   }

//   throw simpleError('url_fetch_error', 'Unexpected error in redirect handling', {
//     external_url: url,
//   })
// }

// async function verifyUrlAccessibility(url: string): Promise<void> {
//   try {
//     const response = await followRedirectsHead(url)

//     if (!response.ok) {
//       throw simpleError('url_not_accessible', 'External URL is not accessible', {
//         external_url: url,
//         status: response.status,
//         statusText: response.statusText,
//         finalUrl: response.url,
//       })
//     }

//     const contentType = response.headers.get('content-type') || ''
//     const contentLength = response.headers.get('content-length')

//     // Check if it's likely a file (not HTML page)
//     if (contentType.includes('text/html')) {
//       throw simpleError('url_not_file', 'External URL appears to be a webpage, not a file', {
//         external_url: url,
//         contentType,
//       })
//     }

//     // Check if it's a zip file
//     const isZipContentType = contentType.includes('application/zip')
//       || contentType.includes('application/x-zip-compressed')
//       || contentType.includes('application/octet-stream')
//     const isZipExtension = url.toLowerCase().endsWith('.zip')

//     // Check Content-Disposition header for filename
//     const contentDisposition = response.headers.get('content-disposition') || ''
//     const filenameMatch = contentDisposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/)
//     const filename = filenameMatch ? filenameMatch[1].replace(/['"]/g, '') : ''
//     const isZipFilename = filename.toLowerCase().endsWith('.zip')

//     if (!isZipContentType && !isZipExtension && !isZipFilename) {
//       throw simpleError('url_not_zip', 'External URL must point to a ZIP file', {
//         external_url: url,
//         contentType,
//         contentDisposition,
//         detectedFilename: filename,
//       })
//     }

//     // Check if file has content
//     if (contentLength === '0') {
//       throw simpleError('url_empty_file', 'External URL points to an empty file', {
//         external_url: url,
//       })
//     }
//   }
//   catch (error) {
//     if (error instanceof Error && (error.message.includes('url_not_accessible') || error.message.includes('url_not_file') || error.message.includes('url_empty_file'))) {
//       throw error
//     }
//     throw simpleError('url_fetch_error', 'Failed to verify external URL accessibility', {
//       external_url: url,
//       error: error instanceof Error ? error.message : 'Unknown error',
//     })
//   }
// }

interface AppWithOrg {
  owner_org: string
  orgs: {
    enforce_encrypted_bundles: boolean
    required_encryption_key: string | null
  }
}

async function getAppOrganization(c: Context, appId: string): Promise<AppWithOrg> {
  // Use supabaseAdmin to access org security settings (RLS bypass needed for enforcement check)
  const { data: app, error: appError } = await supabaseAdmin(c)
    .from('apps')
    .select('owner_org, orgs!inner(enforce_encrypted_bundles, required_encryption_key)')
    .eq('app_id', appId)
    .single()

  if (appError || !app) {
    throw simpleError('cannot_find_app', 'Cannot find app', { supabaseError: appError })
  }

  return app as unknown as AppWithOrg
}

async function checkVersionExists(c: Context, appId: string, apikey: Database['public']['Tables']['apikeys']['Row'], version: string): Promise<void> {
  const { data: existingVersion } = await supabaseApikey(c, apikey.key)
    .from('app_versions')
    .select('id')
    .eq('app_id', appId)
    .eq('name', version)
    .eq('deleted', false)
    .single()

  if (existingVersion) {
    throw simpleError('version_already_exists', 'Version already exists', { version })
  }
}

function checkEncryptedBundleEnforcement(appWithOrg: AppWithOrg, sessionKey: string | undefined, keyId: string | undefined): void {
  // If org doesn't enforce encrypted bundles, allow
  if (!appWithOrg.orgs.enforce_encrypted_bundles) {
    return
  }

  // Check if bundle is encrypted (has a non-empty session_key)
  if (!sessionKey || sessionKey === '') {
    throw simpleError('encryption_required', 'This organization requires all bundles to be encrypted. Please upload an encrypted bundle with a session_key.', {
      enforce_encrypted_bundles: true,
    })
  }

  // If org requires a specific encryption key, check it matches
  const requiredKey = appWithOrg.orgs.required_encryption_key
  if (requiredKey && requiredKey !== '') {
    // Bundle must have a key_id
    if (!keyId || keyId === '') {
      throw simpleError('encryption_key_required', 'This organization requires bundles to be encrypted with a specific key. The uploaded bundle does not have a key_id.', {
        enforce_encrypted_bundles: true,
        required_encryption_key: true,
      })
    }

    // Check if the key_id matches the required key (compare first N characters)
    // key_id is 20 chars, required_encryption_key is up to 21 chars
    const matches = keyId === requiredKey.substring(0, 20) || keyId.substring(0, requiredKey.length) === requiredKey
    if (!matches) {
      throw simpleError('encryption_key_mismatch', 'This organization requires bundles to be encrypted with a specific key. The uploaded bundle was encrypted with a different key.', {
        enforce_encrypted_bundles: true,
        required_encryption_key: true,
        expected_key_prefix: `${requiredKey.substring(0, 4)}...`,
      })
    }
  }
}

async function insertBundle(c: Context, body: CreateBundleBody, ownerOrg: string, apikey: Database['public']['Tables']['apikeys']['Row']): Promise<any> {
  const { data: newBundle, error: createError } = await supabaseApikey(c, apikey.key)
    .from('app_versions')
    .insert({
      app_id: body.app_id,
      checksum: body.checksum,
      name: body.version,
      ...(body.session_key && { session_key: body.session_key }),
      ...(body.key_id && { key_id: body.key_id }),
      external_url: body.external_url,
      storage_provider: 'external',
      owner_org: ownerOrg,
      user_id: apikey.user_id,
    })
    .select()
    .single()

  if (createError) {
    throw simpleError('cannot_create_bundle', 'Cannot create bundle', { supabaseError: createError })
  }

  return newBundle
}

export async function createBundle(c: Context<MiddlewareKeyVariables>, body: CreateBundleBody, apikey: Database['public']['Tables']['apikeys']['Row']): Promise<Response> {
  if (!body.app_id) {
    throw simpleError('missing_app_id', 'Missing required fields: app_id', { app_id: body.app_id })
  }
  if (!isValidAppId(body.app_id)) {
    throw simpleError('invalid_app_id', 'App ID must be a reverse domain string', { app_id: body.app_id })
  }
  if (!body.version) {
    throw simpleError('missing_version', 'Missing required fields: version', { version: body.version })
  }
  if (!body.external_url) {
    throw simpleError('missing_external_url', 'Missing required fields: external_url', { external_url: body.external_url })
  }
  if (!body.checksum) {
    throw simpleError('missing_checksum', 'Missing required fields: checksum', { checksum: body.checksum })
  }
  if (!isValidSemver(body.version)) {
    throw simpleError('invalid_version_format', 'Version must be valid semver format (e.g., 1.0.0, 1.0.0-alpha.1)', { version: body.version })
  }
  // Auth context is already set by middlewareKey
  if (!(await checkPermission(c, 'app.upload_bundle', { appId: body.app_id }))) {
    throw simpleError('cannot_create_bundle', 'You can\'t access this app', { app_id: body.app_id })
  }

  validateUrlFormat(body.external_url)
  // await verifyUrlAccessibility(body.external_url)

  const appWithOrg = await getAppOrganization(c, body.app_id)

  // Check encrypted bundle enforcement
  checkEncryptedBundleEnforcement(appWithOrg, body.session_key, body.key_id)

  await checkVersionExists(c, body.app_id, apikey, body.version)

  const newBundle = await insertBundle(c, body, appWithOrg.owner_org, apikey)

  return c.json({
    status: 'success',
    bundle: newBundle,
  })
}
