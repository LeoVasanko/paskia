<script setup>
// Satellites panel: both link roles of this instance.
//
// Upstream role ("Satellites" table): other paskia instances registered to
// serve this instance's domains. Registration is online: mint a link URL
// (RAM-only, single-use, 10 minutes), the satellite pastes it in its own
// Satellites panel or runs `paskia satellite <url>`. A link's scope (the
// domains it serves) is adjustable at any time — the new set is pushed
// over the live link, no new registration. Revoking a link drops the
// satellite's connection and its copy of the domains.
//
// Satellite role ("Uplinks" table): this instance serving other
// instances' domains. The only local configuration is the link itself —
// domains, origins and auth host arrive from the upstream and are
// read-only here.
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import AdminDialog from './dialogs/AdminDialog.vue'
import { useAuthStore } from '@/stores/auth'
import { formatDate } from '@/utils/helpers'
import { apiJson } from 'paskia'

const props = defineProps({
  domains: { type: Array, default: () => [] },
})
const emit = defineEmits(['domains-changed'])

const authStore = useAuthStore()
const links = ref([])
const uplinks = ref([])

async function load() {
  try {
    ;[links.value, uplinks.value] = await Promise.all([
      apiJson('/auth/api/admin/satellites/', { method: 'GET' }),
      apiJson('/auth/api/admin/uplinks/', { method: 'GET' }),
    ])
  } catch {
    // Master admin only section; leave lists empty on failure
  }
}

// While an uplink is not connected, poll gently so status goes live
// without a manual refresh (registration and reconnects included); after
// minting a link URL, poll for a minute to catch the satellite appearing.
let pollTimer = null
let mintWatchUntil = 0
function schedulePoll() {
  clearTimeout(pollTimer)
  const watching =
    uplinks.value.some(u => !u.connected) ||
    Date.now() < mintWatchUntil  // a minted link's satellite may appear
  if (watching) {
    pollTimer = setTimeout(async () => {
      await load()
      schedulePoll()
    }, 3000)
  }
}
onMounted(async () => {
  await load()
  schedulePoll()
})
onBeforeUnmount(() => clearTimeout(pollTimer))

async function refresh() {
  await load()
  schedulePoll()
}

// Domains eligible for a link's scope: locally served, with an auth host
// (satellite users' account pages live there).
const eligibleDomains = computed(() =>
  props.domains.filter(d => !d.remote && d.auth_host)
)

function copyText(value, label) {
  navigator.clipboard.writeText(value).then(() => {
    authStore.showMessage(`${label} copied to clipboard`, 'success', 1500)
  })
}

// --- Link dialog (create an offer / adjust scope) ---
const linkDialog = ref(null) // {id|null, selected:Set, minted:{url,expires_in}|null, busy, error}

function openLinkDialog(link) {
  linkDialog.value = {
    id: link?.id || null,
    selected: new Set(link?.rp_ids || []),
    minted: null,
    busy: false,
    error: '',
  }
}

function toggleScope(rpId) {
  // Replace the Set (in-place mutation is invisible to reactivity)
  const s = new Set(linkDialog.value.selected)
  if (s.has(rpId)) s.delete(rpId)
  else s.add(rpId)
  linkDialog.value.selected = s
}

async function submitLinkDialog() {
  const d = linkDialog.value
  if (!d || d.busy) return
  if (d.minted) {
    // The URL is shown — Done dismisses
    linkDialog.value = null
    return
  }
  d.busy = true
  d.error = ''
  try {
    const rp_ids = [...d.selected]
    if (d.id) {
      await apiJson(`/auth/api/admin/satellites/${d.id}`, { method: 'PATCH', body: { rp_ids } })
      authStore.showMessage('Link scope updated — pushed to the satellite.', 'success', 2500)
      linkDialog.value = null
    } else {
      d.minted = await apiJson('/auth/api/admin/satellites/', { method: 'POST', body: { rp_ids } })
      mintWatchUntil = Date.now() + 60_000  // watch for the satellite registering
    }
    await refresh()
  } catch (e) {
    d.error = e.message || 'Failed'
  } finally {
    d.busy = false
  }
}

// --- Uplink dialog (register from a pasted link URL) ---
const uplinkDialog = ref(null) // {url, busy, error}

async function submitUplinkDialog() {
  const d = uplinkDialog.value
  if (!d || d.busy) return
  d.busy = true
  d.error = ''
  try {
    const result = await apiJson('/auth/api/admin/uplinks/', { method: 'POST', body: { url: d.url } })
    uplinkDialog.value = null
    const served = result.domains?.length ? result.domains.join(', ') : 'no domains yet'
    authStore.showMessage(`Linked to ${result.url} — serving ${served}.`, 'success', 4000)
    const rejected = Object.entries(result.rejected || {})
    if (rejected.length) {
      authStore.showMessage(
        `Rejected by configuration: ${rejected.map(([r, why]) => `${r} (${why})`).join(', ')}`,
        'error'
      )
    }
    await refresh()
    emit('domains-changed')
  } catch (e) {
    d.error = e.message || 'Registration failed'
  } finally {
    d.busy = false
  }
}

// --- Confirm dialog (revoke / unlink) ---
const confirmDialog = ref(null) // {title, message, submitLabel, action, busy}

function askConfirm(title, message, submitLabel, action) {
  confirmDialog.value = { title, message, submitLabel, action, busy: false }
}

async function submitConfirm() {
  const d = confirmDialog.value
  if (!d || d.busy) return
  d.busy = true
  try {
    await d.action()
    confirmDialog.value = null
    await refresh()
    emit('domains-changed')
  } catch (e) {
    authStore.showMessage(e.message || 'Failed', 'error')
    confirmDialog.value = null
  }
}

function revokeLink(link) {
  askConfirm(
    'Revoke satellite link',
    `Revoke the link for ${link.label || link.id}? The satellite disconnects immediately and its copy of ${(link.rp_ids || []).join(', ') || 'the domains'} is dropped.`,
    'Revoke',
    async () => {
      await apiJson(`/auth/api/admin/satellites/${link.id}`, { method: 'DELETE' })
      authStore.showMessage('Satellite link revoked.', 'success', 2500)
    }
  )
}

function unlinkUplink(uplink) {
  askConfirm(
    'Unlink uplink',
    `Unlink ${uplink.url}? This instance stops serving ${(uplink.domains || []).join(', ') || 'its domains'} — the domains and their local replica are removed.`,
    'Unlink',
    async () => {
      await apiJson(`/auth/api/admin/uplinks/${uplink.id}`, { method: 'DELETE' })
      authStore.showMessage('Uplink removed.', 'success', 2500)
    }
  )
}

function uplinkStatus(u) {
  if (u.connected) return { icon: '●', text: 'connected', cls: 'status-ok' }
  if (u.available) return { icon: '◐', text: 'offline — answering from cache', cls: 'status-warn' }
  return { icon: '○', text: 'offline', cls: 'status-bad' }
}
</script>

<template>
  <div class="satellites-section">
    <div class="section-header">
      <h2>Satellites</h2>
      <p class="section-description">
        A satellite is another paskia instance serving this instance's domains next to the apps that need
        them — session checks answer locally in a millisecond from a RAM replica kept in sync over a live
        link. Registration is online: mint a link URL, then paste it in the satellite's own Satellites
        panel or run <code>paskia satellite &lt;url&gt;</code> on the satellite host.
      </p>
    </div>

    <table v-if="links.length" class="org-table">
      <thead>
        <tr>
          <th>Satellite</th>
          <th>Serves domains</th>
          <th class="center">Status</th>
          <th class="center"></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="link in links" :key="link.id">
          <td class="perm-name-cell">
            <div class="perm-title">{{ link.label || 'satellite' }}</div>
            <div class="perm-id-info"><span class="id-text">{{ link.id }}</span><span class="muted">·</span><span>{{ formatDate(link.created) }}</span></div>
          </td>
          <td>
            <span v-if="link.rp_ids.length">{{ link.rp_ids.join(', ') }}</span>
            <span v-else class="muted">—</span>
            <div v-if="Object.keys(link.rejected || {}).length" class="small error">
              rejected there: {{ Object.entries(link.rejected).map(([r, why]) => `${r} (${why})`).join(', ') }}
            </div>
          </td>
          <td class="center">
            <span v-if="link.connected" class="status-ok" title="The satellite is connected now">●</span>
            <span v-else class="muted" title="Not connected">○</span>
          </td>
          <td class="center">
            <button type="button" class="icon-btn" @click="openLinkDialog(link)" aria-label="Adjust scope" title="Adjust which domains it serves">✏️</button>
            <button type="button" class="icon-btn delete-icon" @click="revokeLink(link)" aria-label="Revoke link" title="Revoke — the satellite disconnects and unlinks">❌</button>
          </td>
        </tr>
      </tbody>
    </table>
    <p v-else class="small muted">No satellites registered.</p>
    <div class="actions">
      <button type="button" :disabled="!eligibleDomains.length" @click="openLinkDialog(null)">+ New satellite link</button>
      <span v-if="!eligibleDomains.length" class="small muted">A domain with an auth host is required first.</span>
    </div>

    <h3 class="uplinks-title">Uplinks <span class="muted uplinks-hint">— this instance as the satellite</span></h3>
    <table v-if="uplinks.length" class="org-table">
      <thead>
        <tr>
          <th>Upstream</th>
          <th>Serving domains</th>
          <th class="center">Status</th>
          <th class="center"></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="uplink in uplinks" :key="uplink.id">
          <td class="perm-name-cell">
            <div class="perm-title">{{ uplink.url }}</div>
            <div class="perm-id-info"><span class="id-text">{{ uplink.id }}</span><span class="muted">·</span><span>{{ formatDate(uplink.created) }}</span></div>
          </td>
          <td>
            <span v-if="uplink.domains.length">{{ uplink.domains.join(', ') }}</span>
            <span v-else class="muted">—</span>
          </td>
          <td class="center">
            <span :class="uplinkStatus(uplink).cls" :title="uplinkStatus(uplink).text">{{ uplinkStatus(uplink).icon }}</span>
          </td>
          <td class="center">
            <button type="button" class="icon-btn delete-icon" @click="unlinkUplink(uplink)" aria-label="Unlink" title="Unlink — stop serving its domains">❌</button>
          </td>
        </tr>
      </tbody>
    </table>
    <div class="actions">
      <button type="button" @click="uplinkDialog = { url: '', busy: false, error: '' }">+ Add uplink</button>
    </div>

    <AdminDialog
      v-if="linkDialog"
      :title="linkDialog.id ? 'Satellite link scope' : 'New satellite link'"
      :busy="linkDialog.busy"
      :error="linkDialog.error"
      :submit-label="linkDialog.minted ? 'Done' : linkDialog.id ? 'Save' : 'Generate link URL'"
      @submit="submitLinkDialog"
      @close="linkDialog = null"
    >
      <template v-if="!linkDialog.minted">
        <p class="small muted">
          Domains this satellite serves. Adjustable later — the new set is pushed over the live link,
          no new registration.
        </p>
        <div class="scope-list">
          <label v-for="d in eligibleDomains" :key="d.rp_id" class="scope-row">
            <input type="checkbox" :checked="linkDialog.selected.has(d.rp_id)" @change="toggleScope(d.rp_id)" />
            <span>{{ d.rp_id }}</span>
          </label>
        </div>
      </template>
      <template v-else>
        <p class="small muted">
          The link URL — hand it to the satellite (its Satellites panel, or
          <code>paskia satellite &lt;url&gt;</code>). Valid for {{ Math.round(linkDialog.minted.expires_in / 60) }} minutes,
          single-use, shown once:
        </p>
        <pre class="wellknown-doc" title="Click to copy" tabindex="0" @click="copyText(linkDialog.minted.url, 'Link URL')" @keydown.enter.prevent="copyText(linkDialog.minted.url, 'Link URL')">{{ linkDialog.minted.url }}</pre>
      </template>
    </AdminDialog>

    <AdminDialog
      v-if="uplinkDialog"
      title="Add uplink"
      :busy="uplinkDialog.busy"
      :error="uplinkDialog.error"
      submit-label="Register"
      :submit-disabled="!uplinkDialog.url.trim()"
      @submit="submitUplinkDialog"
      @close="uplinkDialog = null"
    >
      <label>Link URL
        <input
          v-model="uplinkDialog.url"
          placeholder="wss://auth.example.com#hurt.siege.right.burden.permit"
          autocomplete="off"
          data-lpignore="true"
          data-1p-ignore="true"
          data-form-type="other"
          spellcheck="false"
        />
      </label>
      <p class="small muted">
        Minted on the upstream (its Satellites panel → New satellite link). Registration runs now:
        the domains it covers appear here and in the domains list, managed by the upstream.
      </p>
    </AdminDialog>

    <AdminDialog
      v-if="confirmDialog"
      :title="confirmDialog.title"
      :busy="confirmDialog.busy"
      :submit-label="confirmDialog.submitLabel"
      @submit="submitConfirm"
      @close="confirmDialog = null"
    >
      <p class="small">{{ confirmDialog.message }}</p>
    </AdminDialog>
  </div>
</template>

<style scoped>
.satellites-section { margin-top: var(--space-2xl); display: flex; flex-direction: column; gap: var(--space-sm); }
.satellites-section .section-header { display: flex; flex-direction: column; gap: 0.4rem; margin-bottom: var(--space-xs); }
.satellites-section .actions { display: flex; align-items: center; gap: var(--space-sm); }
.uplinks-title { margin: var(--space-lg) 0 var(--space-xs); font-size: 1.05rem; }
.uplinks-hint { font-weight: 400; font-size: 0.85rem; }
.perm-name-cell { display: flex; flex-direction: column; gap: 0.3rem; }
.perm-title { font-weight: 600; color: var(--color-heading); }
.perm-id-info { font-size: 0.8rem; color: var(--color-text-muted); }
.id-text { font-family: var(--font-mono, monospace); }
.org-table .center { width: 4rem; min-width: 4rem; text-align: center; }
.status-ok { color: var(--color-success, #16a34a); }
.status-warn { color: var(--color-warning, #d97706); }
.status-bad { color: var(--color-text-muted); }
.scope-list { display: flex; flex-direction: column; gap: 0.3rem; }
.scope-row { display: flex; flex-direction: row; align-items: center; gap: var(--space-xs); }
.scope-row input { width: auto; }
.wellknown-doc { margin: 0; padding: var(--space-xs) var(--space-sm); font-size: 0.8rem; background: var(--color-bg-soft, rgba(127,127,127,0.08)); border-radius: 4px; white-space: pre-wrap; word-break: break-all; cursor: pointer; }
.error { color: var(--color-error); }
</style>
