<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import AdminDialog from './AdminDialog.vue'
import { useAuthStore } from '@/stores/auth'
import { compareOrigins } from '@/utils/helpers'

const props = defineProps({
  dialog: { type: Object, required: true }
})

defineEmits(['submit', 'close'])

const title = computed(() =>
  props.dialog.data?.isNew ? 'Add Domain' : `Edit Domain: ${props.dialog.data?.rp_id}`
)

// The rp-id of the domain being edited (lowercased: classification
// compares against it, and hosts are case-insensitive)
const dialogRpId = computed(() => (props.dialog.data?.rp_id || '').trim().toLowerCase())

// Block submit on hard errors: malformed entries, an over-cap related
// list (the server rejects the save), a save that would lock the admin
// out of the domain they are using, or validation still in flight.
// Connectivity and rp-id mismatch results are warnings only (entries may
// be hosted elsewhere, or a new domain whose DNS is not routed to this
// instance yet).
const isValidationInvalid = computed(() => {
  const d = props.dialog.data
  const bad = v => v === 'invalid' || v === 'validating'
  if (d.originValidation?.some(bad)) return true
  if (relatedEntries.value.length > 5) return true
  if (d.isNew && !isWellFormedDomain(d.rp_id || '')) return true
  if (lockoutWarning.value) return true
  return false
})

// A single origins list holds two kinds of entries: sites on the rp-id
// domain form the in-domain sign-in allow-list; entries on other domain
// names are related origins (WebAuthn ROR). Classification is automatic
// from the hostname. A bare '*' or '**' is invalid (wildcards must sit
// under the rp-id) and never a related origin.
function isRelatedEntry(origin) {
  if (isWildcardEntry(origin)) return false // wildcards are never related
  const h = originHostname(origin)
  return !!(h && dialogRpId.value && !isWithinDomain(origin, dialogRpId.value))
}
const relatedEntries = computed(() => {
  const d = props.dialog.data
  if (!d?.origins) return []
  return d.origins.filter(isRelatedEntry)
})

// Well-known document browsers fetch from the rp-id domain to verify the
// related-origin list (never from the auth host).
const wellKnownUrl = computed(() => {
  const host = (props.dialog.data?.rp_id || '').replace(/^https:\/\//, '').replace(/\/+$/, '')
  return host ? `https://${host}/.well-known/webauthn` : ''
})

// ROR origins must be absolute https URLs in the well-known document.
function asHttpsOrigin(origin) {
  const o = origin.trim().replace(/\/+$/, '')
  return o.startsWith('http') ? o : `https://${o}`
}
const wellKnownJson = computed(() =>
  JSON.stringify({ origins: relatedEntries.value.map(asHttpsOrigin) })
)

// Copy-to-clipboard helper
const authStore = useAuthStore()
function copyText(value, label) {
  navigator.clipboard.writeText(value).then(() => {
    authStore.showMessage(`${label} copied to clipboard`, 'success', 1500)
  })
}

// --- Lockout prevention (editing the domain in use) ---

// When the admin edits the domain they are currently signed in on and no
// auth host is marked (with one, ceremonies move there and saving is
// always allowed), their current page origin must stay allowed to run
// passkey ceremonies — otherwise saving locks them out. Mirrors the
// backend check (Passkey.validate_origin): an in-domain origin matches a
// row exactly (scheme+host+port) or a wildcard row — '**.base' covers
// the apex and subdomains at any depth, '*.base' exactly one subdomain
// level — over https, except under localhost (any scheme and port);
// a related row matches only on exact equality (https://host).
const lockoutWarning = computed(() => {
  const d = props.dialog.data
  if (d?.isNew || d?.auth_host) return null
  const rpId = dialogRpId.value
  if (!rpId || rpId !== authStore.settings?.rp_id) return null
  return pageOriginAllowed(d.origins || [], rpId) ? null : window.location.host
})

// Whether any origin diagnostic is present
const hasOriginDiagnostics = computed(() => {
  const d = props.dialog.data
  if (!d) return false
  if (d.originValidation?.some(v => v === 'invalid' || v === 'unreachable' || v === 'mismatch')) return true
  return relatedEntries.value.length > 5 || !!lockoutWarning.value
})

// Any runtime diagnostic to show in the dialog's attached feedback panel
const hasDiagnostics = computed(
  () => hasOriginDiagnostics.value || !!props.dialog.data?.wellKnownCheck
)

function pageOriginAllowed(rows, rpId) {
  const toUrl = key => (isWildcardEntry(key) || key.includes('://')) ? key : 'https://' + key
  const inDomain = []
  const related = []
  for (const row of rows) {
    if (!originHostname(row)) continue
    const key = entryKey(row).toLowerCase()
    if (!key) continue
    const bucket = isRelatedEntry(row) ? related : inDomain
    bucket.push(toUrl(key))
  }
  const probe = origin => {
    let hostname
    try { hostname = new URL(origin).hostname } catch { return false }
    if (hostname === rpId || hostname.endsWith('.' + rpId)) {
      if (inDomain.includes(origin)) return true
      return inDomain.some(e => {
        const base = wildcardBase(e)
        if (!base) return false
        const matched = e.startsWith('**.')
          ? hostname === base || hostname.endsWith('.' + base)
          : hostname.endsWith('.' + base) && !hostname.slice(0, -base.length - 1).includes('.')
        if (!matched) return false
        // Under localhost a wildcard matches any scheme and port
        return base === 'localhost' || base.endsWith('.localhost') || origin.startsWith('https://')
      })
    }
    return related.includes(origin)
  }
  // The page scheme may be http (e.g. on localhost) — probe both
  return probe(`https://${window.location.host}`) || probe(`http://${window.location.host}`)
}

const originInputs = ref([])

async function addOrigin() {
  const d = props.dialog.data
  if (!d) return
  d.origins.push('')
  d.originValidation.push(null)
  await nextTick()
  originInputs.value[originInputs.value.length - 1]?.focus()
}

// Row validation runs after a short typing pause and immediately on
// blur, so no error indication appears mid-edit. Empty rows are ignored.
const originValidateTimers = new Map()

function scheduleValidateOrigin(i) {
  clearTimeout(originValidateTimers.get(i))
  originValidateTimers.set(i, setTimeout(() => {
    originValidateTimers.delete(i)
    validateOrigin(i)
  }, 600))
}

function onOriginBlur(i) {
  clearTimeout(originValidateTimers.get(i))
  originValidateTimers.delete(i)
  validateOrigin(i)
}

function removeOrigin(i) {
  const d = props.dialog.data
  if (d) {
    // Row indices shift on removal — drop all pending validations
    for (const t of originValidateTimers.values()) clearTimeout(t)
    originValidateTimers.clear()
    d.origins.splice(i, 1)
    d.originValidation.splice(i, 1)
  }
}

function isWellFormedDomain(value) {
  if (!value.trim()) return false
  try {
    const url = value.startsWith('http') ? new URL(value) : new URL('https://' + value)
    // Any DNS label sequence (matching backend validate_rp_id): labels of
    // 1-63 alnum/hyphen chars, no leading/trailing hyphen, dot-separated
    return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(url.hostname)
  } catch {
    return false
  }
}

// Wildcard entries follow the shell-glob convention: '*.base' covers
// exactly one subdomain level, '**.base' the apex and any depth.
const isWildcardEntry = value => {
  const v = value.trim()
  return v.startsWith('*.') || v.startsWith('**.')
}

// Base domain of a wildcard entry (lowercased); null when the value is
// not a wildcard pattern or has no base.
function wildcardBase(value) {
  const v = value.trim()
  if (v.startsWith('**.')) return v.slice(3).replace(/\.+$/, '').toLowerCase() || null
  if (v.startsWith('*.')) return v.slice(2).replace(/\.+$/, '').toLowerCase() || null
  return null
}

function originHostname(origin) {
  const v = origin.trim()
  if (!v || v === '*' || v === '**') return null // a bare '*' or '**' is not a valid entry
  if (isWildcardEntry(v)) {
    const base = wildcardBase(v)
    return base && isWellFormedDomain(base) ? base : null
  }
  try {
    const url = v.startsWith('http') ? new URL(v) : new URL('https://' + v)
    // The URL parser keeps malformed hostnames like '.localhost' or
    // 'a..b.com' — reject anything that is not clean dot-separated labels
    return url.hostname && isWellFormedDomain(url.hostname) ? url.hostname : null
  } catch {
    return null
  }
}

function isWithinDomain(origin, rpId) {
  const hostname = originHostname(origin)
  if (!hostname) return false
  return hostname === rpId || hostname.endsWith('.' + rpId)
}

async function validateOriginConnectivity(i) {
  const d = props.dialog.data
  if (!d) return
  const value = d.origins[i]

  d.originValidation[i] = 'validating'
  try {
    const cleanValue = value.replace(/\/+$/, '')
    const testUrl = cleanValue.startsWith('http') ? cleanValue : 'https://' + cleanValue
    const response = await fetch(testUrl + '/auth/api/settings', {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    })
    if (d.origins[i] !== value) return // entry changed while validating
    if (response.ok) {
      const data = await response.json()
      // Valid when the entry is served by this instance for the edited domain
      d.originValidation[i] = (data.rp_id && data.rp_id === dialogRpId.value) ? 'valid' : 'mismatch'
    } else {
      d.originValidation[i] = 'unreachable'
    }
  } catch (e) {
    if (d.origins[i] === value) {
      d.originValidation[i] = 'unreachable'
    }
  }
}

// A '*' typed into an empty field expands to '**.<rp-id>' with the second
// asterisk selected: typing on (e.g. '.') replaces the selection —
// yielding '*.<rp-id>' — while the rp-id stays at the end; Backspace
// deletes the second asterisk; doing nothing keeps the any-depth form.
// Only typed input into an empty field triggers this — never pasting or
// deleting (e.g. backspacing '**' down to '*' must not re-expand).
function onOriginInput(i, e) {
  const d = props.dialog.data
  if (!d) return
  const el = e.target
  const oldKey = entryKey(d.origins[i])
  let value = el.value
  if (value === '*' && dialogRpId.value && (e.inputType === 'insertText' || e.inputType === 'insertCompositionText')) {
    value = '**.' + dialogRpId.value
    el.value = value
    el.setSelectionRange(1, 2)
  }
  d.origins[i] = value
  // Keep the auth-host mark on a renamed entry, unless it no longer
  // qualifies (wildcards and related origins cannot be the auth host)
  if (d.auth_host && oldKey === d.auth_host) {
    const key = entryKey(value)
    d.auth_host = key && !key.startsWith('*') && !isRelatedEntry(value) ? key : ''
  }
  d.originValidation[i] = null
  scheduleValidateOrigin(i)
}

function validateOrigin(i) {
  const d = props.dialog.data
  if (!d) return
  const value = d.origins[i]
  // Empty rows are ignored — never errors, and skipped on save
  if (!value || !value.trim()) {
    d.originValidation[i] = null
    return
  }
  if (!originHostname(value)) {
    d.originValidation[i] = 'invalid'
    return
  }
  if (isWildcardEntry(value)) {
    // Wildcards have no concrete site to probe, and are only allowed
    // within the domain (related origins are individual hosts)
    d.originValidation[i] = isWithinDomain(value, dialogRpId.value) ? null : 'invalid'
    return
  }
  validateOriginConnectivity(i)
}

// Fetch the well-known document and check it lists every related origin.
// Runs automatically whenever the related set changes; result is a
// warning only, never a submit blocker (the rp-id site may be hosted
// elsewhere, and cross-origin fetches can fail for unrelated reasons).
async function testWellKnown() {
  const d = props.dialog.data
  if (!d) return
  const related = relatedEntries.value.map(asHttpsOrigin)
  if (!related.length) {
    d.wellKnownCheck = null
    return
  }
  const key = related.join('|')
  d.wellKnownCheck = 'validating'
  try {
    const response = await fetch(wellKnownUrl.value, { headers: { 'Accept': 'application/json' } })
    if (!response.ok) throw new Error('not ok')
    const doc = await response.json()
    if (related.join('|') !== key) return // list changed while fetching
    const listed = new Set((doc.origins || []).map(o => String(o).replace(/\/+$/, '')))
    const missing = related.filter(o => !listed.has(o))
    d.wellKnownCheck = missing.length ? 'missing' : 'valid'
    d.wellKnownMissing = missing
  } catch {
    if (related.join('|') === key) d.wellKnownCheck = 'unreachable'
  }
}
watch(() => relatedEntries.value.map(asHttpsOrigin).join('|'), testWellKnown, { immediate: true })

// Prefill a new domain's list with the real '**.<rp-id>' row once its
// rp-id is known ('**.x' = the domain apex and all its subdomains over
// https, any scheme and port under localhost). The row follows rp-id
// edits while it is still the untouched prefilled row; once the admin
// edits it, it is left alone. Seeding waits for a complete-looking rp-id
// (letters after the final dot) so mid-typing states like 'something.'
// don't prefill a broken '**.something'.
function looksCompleteDomain(value) {
  const host = (value || '').trim().replace(/\.$/, '')
  return host === 'localhost' || /\.[a-z]{2,}$/i.test(host)
}
// Tracks the prefilled row so rp-id edits can keep updating it.
let seededOrigin = null
watch(dialogRpId, rp => {
  const d = props.dialog.data
  if (!d?.isNew) return
  if (!looksCompleteDomain(rp) || !isWellFormedDomain(rp)) return
  const seed = '**.' + rp.trim().replace(/\.$/, '')
  if (!d.origins.length) {
    d.origins.push(seed)
    d.originValidation.push(null)
    seededOrigin = seed
  } else if (d.origins.length === 1 && d.origins[0] === seededOrigin && seed !== seededOrigin) {
    d.origins[0] = seed
    seededOrigin = seed
  }
})

// --- Row menu: auth host assignment and entry removal ---

const openMenu = ref(null)

// Close the popup on any click outside it (the toggle button stops
// propagation, so it never reaches this listener).
function onDocumentClick(e) {
  if (openMenu.value !== null && !e.target.closest('.row-menu')) openMenu.value = null
}
onMounted(() => document.addEventListener('click', onDocumentClick))
onBeforeUnmount(() => {
  document.removeEventListener('click', onDocumentClick)
  for (const t of originValidateTimers.values()) clearTimeout(t)
  originValidateTimers.clear()
})

// Origins-dict key form of an entry (https:// omitted), also used for the
// auth_host value.
function entryKey(value) {
  return value?.trim().replace(/^https:\/\//, '').replace(/\/+$/, '') || ''
}

function isAuthHostEntry(origin) {
  const d = props.dialog.data
  const key = entryKey(origin)
  return !!(key && d?.auth_host && key === d.auth_host)
}

function setAuthHost(i) {
  const d = props.dialog.data
  if (!d) return
  let key = entryKey(d.origins[i])
  let added = false
  const wbase = wildcardBase(key)
  if (wbase) {
    // A wildcard cannot be the auth host — create a concrete auth.<base> entry
    key = 'auth.' + wbase
    if (!d.origins.some(o => entryKey(o) === key)) {
      d.origins.push(key)
      d.originValidation.push(null)
      added = true
    }
  }
  d.auth_host = key
  openMenu.value = null
  resortOrigins()
  if (added) validateOrigin(d.origins.findIndex(o => entryKey(o) === key))
}

function clearAuthHost() {
  const d = props.dialog.data
  if (d) d.auth_host = ''
  openMenu.value = null
  resortOrigins()
}

// Display order, applied after row-menu actions (never while typing in an
// input, to avoid focus loss): auth host first, then the rp-id, then
// in-domain entries hierarchically, then related origins.
function resortOrigins() {
  const d = props.dialog.data
  if (!d) return
  const rank = o => isAuthHostEntry(o) ? 0 : o === dialogRpId.value ? 1 : isRelatedEntry(o) ? 3 : 2
  const pairs = d.origins.map((o, i) => [o, d.originValidation[i]])
  pairs.sort((a, b) => rank(a[0]) - rank(b[0]) || compareOrigins(a[0], b[0]))
  d.origins = pairs.map(p => p[0])
  d.originValidation = pairs.map(p => p[1])
}

function onRemoveOrigin(i) {
  const d = props.dialog.data
  if (!d) return
  if (isAuthHostEntry(d.origins[i])) d.auth_host = ''
  removeOrigin(i)
  openMenu.value = null
  resortOrigins()
}
</script>

<template>
  <AdminDialog
    :title="title"
    :busy="dialog.busy"
    :error="dialog.error"
    :submit-disabled="isValidationInvalid"
    @submit="$emit('submit')"
    @close="$emit('close')"
  >
    <template #attached>
      <div v-if="relatedEntries.length || hasDiagnostics" class="attach-panel" @click.stop>
        <template v-if="relatedEntries.length">
          <p class="small muted">
            Related origins are verified by browsers against
            <a :href="wellKnownUrl" target="_blank" rel="noopener noreferrer">{{ wellKnownUrl }}</a>
            — served automatically when this instance hosts {{ dialog.data.rp_id }}; otherwise publish this document there:
          </p>
          <pre class="wellknown-doc" title="Click to copy" tabindex="0" @click="copyText(wellKnownJson, 'Well-known document')" @keydown.enter.prevent="copyText(wellKnownJson, 'Well-known document')">{{ wellKnownJson }}</pre>
        </template>
        <ul v-if="hasDiagnostics" class="diag-list">
          <li v-if="dialog.data.originValidation.some(v => v === 'invalid')" class="small error">Some entries are invalid — check for typos in the hostname; a bare '*' or '**' is not allowed, and wildcards only within the domain.</li>
          <li v-if="dialog.data.originValidation.some(v => v === 'unreachable')" class="small">Some sites are unreachable — make sure they are routed to this instance.</li>
          <li v-else-if="dialog.data.originValidation.some(v => v === 'mismatch')" class="small">Some sites are reachable but do not serve this domain.</li>
          <li v-if="relatedEntries.length > 5" class="small error">At most 5 related origins are allowed ({{ relatedEntries.length }} listed) — the save is rejected.</li>
          <li v-if="lockoutWarning" class="small error">Saving would lock you out: {{ lockoutWarning }} could no longer run sign-in ceremonies for this domain. Keep it listed, or mark an auth host.</li>
          <li v-if="dialog.data.wellKnownCheck === 'validating'" class="small">Checking the published document…</li>
          <li v-else-if="dialog.data.wellKnownCheck === 'valid'" class="small">✓ The published document lists all related origins.</li>
          <li v-else-if="dialog.data.wellKnownCheck === 'missing'" class="small error">The published document does not list: {{ (dialog.data.wellKnownMissing || []).join(', ') }}</li>
          <li v-else-if="dialog.data.wellKnownCheck === 'unreachable'" class="small">Could not fetch the published document to verify it.</li>
        </ul>
      </div>
    </template>
    <template v-if="dialog.data.isNew">
      <label>Domain (rp-id)
        <input v-model="dialog.data.rp_id" placeholder="example.com" data-form-type="other" required />
      </label>
      <p class="small muted">The domain name passkeys belong to — they work on this domain and its subdomains, and related domains. Cannot be changed later.</p>
    </template>
    <label>Display Name (rp-name)
      <input v-model="dialog.data.rp_name" :placeholder="dialog.data.rp_id" />
    </label>

    <div class="origin-label">
      Allowed Origins
      <button type="button" class="icon-btn origin-add-btn" @click="addOrigin()" aria-label="Add origin" title="Add origin">➕</button>
    </div>
    <div v-if="dialog.data.origins.length" class="origin-list">
      <div v-for="(_, i) in dialog.data.origins" :key="i" class="origin-row">
        <input
          ref="originInputs"
          :value="dialog.data.origins[i]"
          @input="e => onOriginInput(i, e)"
          @blur="onOriginBlur(i)"
          class="origin-input"
          :class="{ 'input-error': dialog.data.originValidation[i] === 'invalid' }"
        />
        <span v-if="isAuthHostEntry(dialog.data.origins[i])" class="key-badge" title="Authentication site — the account and admin interface live here">🔑</span>
        <span v-else-if="isRelatedEntry(dialog.data.origins[i])" class="key-badge" title="Related origin (WebAuthn ROR) — shares this domain's passkeys">🔗</span>
        <div class="row-menu">
          <button type="button" class="icon-btn" @click.stop="openMenu = openMenu === i ? null : i" aria-label="Origin actions" title="Actions">⋮</button>
          <div v-if="openMenu === i" class="row-menu-popup">
            <button v-if="isAuthHostEntry(dialog.data.origins[i])" type="button" @click="clearAuthHost()"><span class="menu-icon">🔑</span>Remove auth host</button>
            <button v-else-if="!isRelatedEntry(dialog.data.origins[i]) && originHostname(dialog.data.origins[i])" type="button" @click="setAuthHost(i)"><span class="menu-icon">🔑</span>Set as auth host</button>
            <button type="button" @click="onRemoveOrigin(i)"><span class="menu-icon delete-menu-icon">❌</span>Delete</button>
          </div>
        </div>
      </div>
    </div>
    <p class="small muted">
      Only the listed sites may sign in with {{ dialog.data.rp_id }} passkeys. Wildcards may be used: <strong>**.{{ dialog.data.rp_id }}</strong> allows the whole domain, <strong>*.{{ dialog.data.rp_id }}</strong> only a single subdomain level.<template v-if="relatedEntries.length"> 🔗 means related host requiring WebAuthn ROR setup.</template><template v-if="dialog.data.auth_host"> 🔑 is the dedicated Paskia host for all account management.</template>
    </p>
  </AdminDialog>
</template>

<style scoped>
/* Domain origins */
.origin-label { font-weight: 600; font-size: 0.95rem; margin-top: var(--space-sm); display: flex; align-items: center; gap: var(--space-sm); }
.origin-list { display: flex; flex-direction: column; gap: 0.4rem; }
.origin-row { display: flex; align-items: center; gap: var(--space-xs); }
.origin-input { flex: 1; min-width: 8rem; font-family: var(--font-mono, monospace); }
.origin-add-btn { font-size: 1.2rem; }
.key-badge { flex-shrink: 0; }
.row-menu { position: relative; flex-shrink: 0; }
.row-menu-popup { position: absolute; right: 0; top: 100%; z-index: 10; display: flex; flex-direction: column; min-width: 9rem; background: var(--color-bg, #fff); border: 1px solid var(--color-border, #ccc); border-radius: 4px; box-shadow: 0 2px 8px rgba(0,0,0,0.15); }
.row-menu-popup button { display: flex; align-items: center; justify-content: flex-start; gap: 0.45em; text-align: left; padding: var(--space-xs) var(--space-sm); background: none; border: none; cursor: pointer; white-space: nowrap; }
.row-menu-popup button:hover:not(:disabled) { background: var(--color-bg-soft, rgba(127,127,127,0.12)); }
.row-menu-popup button:disabled { opacity: 0.5; cursor: default; }
.row-menu-popup .menu-icon { flex-shrink: 0; width: 1.1em; text-align: center; }
.row-menu-popup .delete-menu-icon { filter: saturate(1.4); }

.wellknown-doc { margin: 0; padding: var(--space-xs) var(--space-sm); font-size: 0.8rem; background: var(--color-bg-soft, rgba(127,127,127,0.08)); border-radius: 4px; white-space: pre; overflow: hidden; text-overflow: ellipsis; cursor: pointer; }

.input-error {
  border-color: var(--color-error);
  background: var(--color-error-bg, rgba(239, 68, 68, 0.05));
}
</style>
