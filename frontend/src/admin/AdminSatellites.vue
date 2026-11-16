<script setup>
// Links panel: domains served by this instance's satellites and domains this
// instance serves for another master share one table and one add-link dialog.
// Link scope is adjustable at any time and pushed over the live connection.
// Revoking or unlinking drops the connection and the satellite's domains.
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

const allLinks = computed(() => [
  ...links.value.map(link => ({ ...link, kind: 'master', servedDomains: link.rp_ids })),
  ...uplinks.value.map(link => ({ ...link, kind: 'satellite', servedDomains: link.domains })),
])

function managementUrl(value) {
  const url = new URL(value)
  if (url.protocol === 'ws:') url.protocol = 'http:'
  if (url.protocol === 'wss:') url.protocol = 'https:'
  url.hash = ''
  url.search = ''
  return url.toString()
}

async function copyText(value, label) {
  await navigator.clipboard.writeText(value)
  authStore.showMessage(`${label} copied to clipboard`, 'success', 1500)
}

// --- Link dialog (share / register / adjust scope) ---
const linkDialog = ref(null) // {id|null, url, selected:Set, busy, errors}

function openLinkDialog(link) {
  linkDialog.value = {
    id: link?.id || null,
    url: '',
    selected: new Set(link?.rp_ids || eligibleDomains.value.map(d => d.rp_id)),
    busy: false,
    error: '',
    masterError: '',
    satelliteError: '',
  }
}

function toggleScope(rpId) {
  // Replace the Set (in-place mutation is invisible to reactivity)
  const s = new Set(linkDialog.value.selected)
  if (s.has(rpId)) s.delete(rpId)
  else s.add(rpId)
  linkDialog.value.selected = s
}

async function shareDomains() {
  const d = linkDialog.value
  if (!d || d.busy || !eligibleDomains.value.length) return
  d.busy = true
  d.masterError = ''
  try {
    const result = await apiJson('/auth/api/admin/satellites/', {
      method: 'POST', body: { rp_ids: [...d.selected] },
    })
    mintWatchUntil = Date.now() + 60_000
    await refresh()
    linkDialog.value = null
    await copyText(result.url, 'Link URL')
  } catch (e) {
    d.masterError = e.message || 'Could not create the link'
  } finally {
    d.busy = false
  }
}

async function registerUplink() {
  const d = linkDialog.value
  if (!d || d.busy || !d.url.trim()) return
  d.busy = true
  d.satelliteError = ''
  try {
    const result = await apiJson('/auth/api/admin/uplinks/', { method: 'POST', body: { url: d.url } })
    linkDialog.value = null
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
    d.satelliteError = e.message || 'Registration failed'
  } finally {
    d.busy = false
  }
}

async function submitLinkDialog() {
  const d = linkDialog.value
  if (!d?.id || d.busy) return
  d.busy = true
  d.error = ''
  try {
    await apiJson(`/auth/api/admin/satellites/${d.id}`, {
      method: 'PATCH', body: { rp_ids: [...d.selected] },
    })
    authStore.showMessage('Link scope updated — pushed to the satellite.', 'success', 2500)
    linkDialog.value = null
    await refresh()
  } catch (e) {
    d.error = e.message || 'Failed'
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

function linkStatus(link) {
  if (link.connected) return { icon: '●', text: 'connected', cls: 'status-ok' }
  if (link.available) return { icon: '◐', text: 'offline — answering from cache', cls: 'status-warn' }
  return { icon: '○', text: 'offline', cls: 'status-bad' }
}
</script>

<template>
  <div class="satellites-section">
    <div class="section-header">
      <h2>Satellites</h2>
      <p class="section-description">
        Links let one paskia instance serve another's domains next to the apps that need them — session
        checks answer locally in a millisecond from a RAM replica kept in sync over a live connection.
        Create a link URL here, or paste a URL from the authoritative instance.
      </p>
    </div>

    <div class="actions">
      <button type="button" @click="openLinkDialog(null)">+ Add link</button>
    </div>
    <table v-if="allLinks.length" class="org-table">
      <thead>
        <tr>
          <th>Authoritative side</th>
          <th>Serves domains</th>
          <th class="center">Status</th>
          <th class="center"></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="link in allLinks" :key="`${link.kind}:${link.id}`">
          <td class="perm-name-cell">
            <div v-if="link.kind === 'master'" class="perm-title">This instance (master)</div>
            <a
              v-else
              class="perm-title"
              :href="managementUrl(link.url)"
              target="_blank"
              rel="noopener noreferrer"
            >{{ managementUrl(link.url) }}</a>
            <div class="perm-id-info">
              <template v-if="link.kind === 'master'">
                <span>{{ link.label || 'satellite' }}</span><span class="muted">·</span>
              </template>
              <span class="id-text">{{ link.id }}</span><span class="muted">·</span><span>{{ formatDate(link.created) }}</span>
            </div>
          </td>
          <td>
            <span v-if="link.servedDomains.length">{{ link.servedDomains.join(', ') }}</span>
            <span v-else class="muted">—</span>
            <div v-if="Object.keys(link.rejected || {}).length" class="small error">
              rejected there: {{ Object.entries(link.rejected).map(([r, why]) => `${r} (${why})`).join(', ') }}
            </div>
          </td>
          <td class="center">
            <span :class="linkStatus(link).cls" :title="linkStatus(link).text">{{ linkStatus(link).icon }}</span>
          </td>
          <td class="center row-actions">
            <template v-if="link.kind === 'master'">
              <button type="button" class="icon-btn" @click="openLinkDialog(link)" aria-label="Adjust scope" title="Adjust which domains it serves">✏️</button>
              <button type="button" class="icon-btn delete-icon" @click="revokeLink(link)" aria-label="Revoke link" title="Revoke — the satellite disconnects and unlinks">❌</button>
            </template>
            <button v-else type="button" class="icon-btn delete-icon" @click="unlinkUplink(link)" aria-label="Unlink" title="Unlink — stop serving its domains">❌</button>
          </td>
        </tr>
      </tbody>
    </table>
    <p v-else class="small muted">No links registered.</p>

    <AdminDialog
      v-if="linkDialog && !linkDialog.id"
      title="Add link"
      panel-class="link-dialog-panel"
      :busy="linkDialog.busy"
      bare
      @close="linkDialog = null"
    >
      <div class="link-roles">
        <section class="link-role">
          <h4>Master</h4>
          <template v-if="eligibleDomains.length">
            <p class="small muted">Create a link on this authoritative instance and paste it on a satellite.</p>
            <div class="scope-list">
              <label v-for="d in eligibleDomains" :key="d.rp_id" class="scope-row">
                <input
                  type="checkbox"
                  :checked="linkDialog.selected.has(d.rp_id)"
                  :disabled="linkDialog.busy"
                  @change="toggleScope(d.rp_id)"
                />
                <span>{{ d.rp_id }}</span>
              </label>
            </div>
            <button
              type="button"
              class="btn-primary link-role-action"
              :disabled="linkDialog.busy"
              @click="shareDomains"
            >Share these domains</button>
          </template>
          <p v-else class="small muted">
            Sharing requires a local domain with a designated auth host. On localhost, add the exact
            development origin including its port in Domains and mark it as the auth host.
          </p>
          <p v-if="linkDialog.masterError" class="small error">{{ linkDialog.masterError }}</p>
        </section>

        <section class="link-role">
          <h4>Satellite</h4>
          <p class="small muted">Register this instance with a link created by its master.</p>
          <label>Link URL
            <input
              v-model="linkDialog.url"
              placeholder="wss://auth.example.com#hurt.siege.right.burden.permit"
              autocomplete="off"
              data-lpignore="true"
              data-1p-ignore="true"
              data-form-type="other"
              spellcheck="false"
              :disabled="linkDialog.busy"
            />
          </label>
          <p v-if="linkDialog.satelliteError" class="small error">{{ linkDialog.satelliteError }}</p>
          <button
            type="button"
            class="btn-primary link-role-action"
            :disabled="linkDialog.busy || !linkDialog.url.trim()"
            @click="registerUplink"
          >Connect to master</button>
        </section>
      </div>
    </AdminDialog>

    <AdminDialog
      v-if="linkDialog && linkDialog.id"
      title="Satellite link scope"
      :busy="linkDialog.busy"
      :error="linkDialog.error"
      submit-label="Save"
      @submit="submitLinkDialog"
      @close="linkDialog = null"
    >
      <p class="small muted">
        Domains this satellite serves. Adjusting the selection pushes it over the live link.
      </p>
      <div class="scope-list">
        <label v-for="d in eligibleDomains" :key="d.rp_id" class="scope-row">
          <input type="checkbox" :checked="linkDialog.selected.has(d.rp_id)" @change="toggleScope(d.rp_id)" />
          <span>{{ d.rp_id }}</span>
        </label>
      </div>
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
.perm-name-cell { display: flex; flex-direction: column; gap: 0.3rem; }
.perm-title { font-weight: 600; color: var(--color-heading); }
.perm-id-info { font-size: 0.8rem; color: var(--color-text-muted); }
.id-text { font-family: var(--font-mono, monospace); }
.org-table .center { width: 4rem; min-width: 4rem; text-align: center; }
.org-table .row-actions { width: 5rem; min-width: 5rem; white-space: nowrap; }
.row-actions .icon-btn { display: inline-flex; vertical-align: middle; }
.row-actions .icon-btn + .icon-btn { margin-left: 0.25rem; }
.status-ok { color: var(--color-success, #16a34a); }
.status-warn { color: var(--color-warning, #d97706); }
.status-bad { color: var(--color-text-muted); }
:deep(.link-dialog-panel) { width: min(900px, 92vw); max-width: 900px; }
.link-roles { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-md); align-items: stretch; }
.link-role { min-width: 0; display: flex; flex-direction: column; gap: var(--space-sm); padding: var(--space-md); border: 1px solid var(--color-border); border-radius: var(--radius-md); background: var(--color-surface-subtle); }
.link-role h4 { margin: 0; color: var(--color-heading); }
.link-role-action { align-self: flex-start; margin-top: auto; }
.scope-list { display: flex; flex-direction: column; gap: 0.3rem; max-height: 14rem; overflow-y: auto; }
.scope-list label.scope-row { display: flex; flex-direction: row; flex-wrap: nowrap; align-items: center; gap: var(--space-xs); font-weight: 400; }
.scope-list label.scope-row input[type="checkbox"] { width: auto; flex: 0 0 auto; margin: 0; }
.scope-list label.scope-row span { min-width: 0; overflow-wrap: anywhere; }
.error { color: var(--color-error); }
@media (max-width: 700px) {
  .link-roles { grid-template-columns: minmax(0, 1fr); }
}
</style>
