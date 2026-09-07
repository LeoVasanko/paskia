// Utility functions

export function formatDate(dateString) {
  if (!dateString) return 'Never'

  const date = new Date(dateString)
  const now = new Date()
  const diffMs = date - now  // Changed to date - now for future/past
  const isFuture = diffMs > 0
  const absDiffMs = Math.abs(diffMs)
  const diffMinutes = Math.round(absDiffMs / (1000 * 60))
  const diffHours = Math.round(absDiffMs / (1000 * 60 * 60))
  const diffDays = Math.round(absDiffMs / (1000 * 60 * 60 * 24))

  if (absDiffMs < 1000 * 60) return 'Now'
  if (diffMinutes <= 60) return isFuture ? `In ${diffMinutes} minute${diffMinutes === 1 ? '' : 's'}` : diffMinutes === 1 ? 'a minute ago' : `${diffMinutes} minutes ago`
  if (diffHours <= 24) return isFuture ? `In ${diffHours} hour${diffHours === 1 ? '' : 's'}` : diffHours === 1 ? 'an hour ago' : `${diffHours} hours ago`
  if (diffDays <= 14) return isFuture ? `In ${diffDays} day${diffDays === 1 ? '' : 's'}` : diffDays === 1 ? 'a day ago' : `${diffDays} days ago`
  return date.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' })
}

export function getCookie(name) {
  const value = `; ${document.cookie}`
  const parts = value.split(`; ${name}=`)
  if (parts.length === 2) return parts.pop().split(';').shift()
}

export const goBack = () => history.back() || window.close()

// IPv4 unchanged, IPv6 returns /64 network prefix in compact form
export const hostIP = ip => {
  try {
    if (!ip || !ip.includes(':')) return ip
    const strip = s => s.replace(/^\[|\]$/g, '')
    const norm = strip(new URL(`http://[${ip}]/`).hostname)
    const [l, r] = norm.split('::').map(s => s ? s.split(':') : [])
    const full = r ? [...l, ...Array(8 - l.length - r.length).fill('0'), ...r] : l
    return strip(new URL(`http://[${full.slice(0, 4).join(':')}::]/`).hostname).replace(/::$/, '')
  } catch (e) {
    console.error('hostIP processing failed for:', ip, e)
    return ip
  }
}

// Display-time ordering of a domain's configured origins (the stored
// object is unordered): the auth host first (flagged), then in-domain
// entries (exact rp-id, then hierarchical), then related origins — hosts
// outside the rp-id domain — hierarchically. An empty origins object
// allows nothing and shows as an empty list.

// Hierarchical origin comparison: split off scheme/port, compare hostnames
// label by label from the TLD down, parents before their subdomains and a
// wildcard label ('**' any depth, '*' one level — in that order) after all
// concrete labels at the same level. Entries on the same host tie-break by
// scheme (https first) and numeric port.
function originParts(key) {
  let s = key.toLowerCase().replace(/\/+$/, '')
  let scheme = ''
  const sm = s.match(/^([a-z][a-z0-9+.-]*):\/\//)
  if (sm) { scheme = sm[1]; s = s.slice(sm[0].length) }
  let port = ''
  const pm = s.match(/:(\d+)$/)
  if (pm) { port = pm[1]; s = s.slice(0, -pm[0].length) }
  const labels = s.split('.').reverse()
  return { labels, scheme, port }
}

export function compareOrigins(a, b) {
  const A = originParts(a), B = originParts(b)
  for (let i = 0; i < Math.max(A.labels.length, B.labels.length); i++) {
    const la = A.labels[i], lb = B.labels[i]
    if (la === undefined) return -1
    if (lb === undefined) return 1
    if (la === lb) continue
    const wa = la === '*' || la === '**'
    const wb = lb === '*' || lb === '**'
    if (wa && wb) return la === '**' ? -1 : 1
    if (wa) return 1
    if (wb) return -1
    const c = la.localeCompare(lb)
    if (c) return c
  }
  if (A.scheme !== B.scheme) {
    if (A.scheme === 'https') return -1
    if (B.scheme === 'https') return 1
    return A.scheme.localeCompare(B.scheme)
  }
  if (A.port && B.port) return Number(A.port) - Number(B.port)
  return A.port.localeCompare(B.port)
}

// An origins-table entry outside the rp-id domain is a related origin
// (WebAuthn ROR). Wildcards ('*.' or '**.') are never related — they are
// only valid under the rp-id.
function isRelatedKey(rpId, key) {
  if (key.startsWith('*.') || key.startsWith('**.')) return false
  try {
    const hostname = new URL(key.includes('://') ? key : 'https://' + key).hostname
    return !!hostname && hostname !== rpId && !hostname.endsWith('.' + rpId)
  } catch {
    return false
  }
}

export function originDisplayEntries(domain) {
  const origins = domain.origins || {}
  const keys = Object.keys(origins)
  const authKey = keys.find(k => origins[k] !== true && origins[k]?.auth_host)
  const inDomain = []
  const related = []
  for (const k of keys) {
    if (k === authKey) continue
    const bucket = isRelatedKey(domain.rp_id, k) ? related : inDomain
    bucket.push(k)
  }
  inDomain.sort((a, b) => {
    if (a === domain.rp_id) return -1
    if (b === domain.rp_id) return 1
    return compareOrigins(a, b)
  })
  related.sort(compareOrigins)
  const rows = []
  if (authKey) rows.push({ key: authKey, auth: true })
  for (const k of inDomain) rows.push({ key: k, auth: false })
  for (const k of related) rows.push({ key: k, auth: false, related: true })
  return rows
}
