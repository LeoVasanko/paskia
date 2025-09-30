<script setup>
import { ref, onMounted, onBeforeUnmount, computed, watch } from 'vue'
import Breadcrumbs from '@/components/Breadcrumbs.vue'
import CredentialList from '@/components/CredentialList.vue'
import UserBasicInfo from '@/components/UserBasicInfo.vue'
import RegistrationLinkModal from '@/components/RegistrationLinkModal.vue'
import StatusMessage from '@/components/StatusMessage.vue'
import { useAuthStore } from '@/stores/auth'

const info = ref(null)
const loading = ref(true)
const error = ref(null)
const orgs = ref([])
const permissions = ref([])
const currentOrgId = ref(null) // UUID of selected org for detail view
const currentUserId = ref(null) // UUID for user detail view
const userDetail = ref(null) // cached user detail object
const userLink = ref(null) // latest generated registration link
const userLinkExpires = ref(null)
const authStore = useAuthStore()
const addingOrgForPermission = ref(null)
const PERMISSION_ID_PATTERN = '^[A-Za-z0-9:._~-]+$'
const editingPermId = ref(null)
const renameIdValue = ref('')
const editingPermDisplay = ref(null)
const renameDisplayValue = ref('')
const dialog = ref({ type: null, data: null, busy: false, error: '' })
const safeIdRegex = /[^A-Za-z0-9:._~-]/g

function sanitizeRenameId() { if (renameIdValue.value) renameIdValue.value = renameIdValue.value.replace(safeIdRegex, '') }

function handleGlobalClick(e) {
  if (!addingOrgForPermission.value) return
  const menu = e.target.closest('.org-add-menu')
  const trigger = e.target.closest('.add-org-btn')
  if (!menu && !trigger) {
    addingOrgForPermission.value = null
  }
}

onMounted(() => {
  document.addEventListener('click', handleGlobalClick)
})
onBeforeUnmount(() => {
  document.removeEventListener('click', handleGlobalClick)
})

// Build a summary: for each permission id -> { orgs: Set(org_display_name), userCount }
const permissionSummary = computed(() => {
  const summary = {}
  for (const o of orgs.value) {
    const orgBase = { uuid: o.uuid, display_name: o.display_name }
    // Org-level permissions (direct)
    for (const pid of o.permissions || []) {
      if (!summary[pid]) summary[pid] = { orgs: [], orgSet: new Set(), userCount: 0 }
      if (!summary[pid].orgSet.has(o.uuid)) {
        summary[pid].orgs.push(orgBase)
        summary[pid].orgSet.add(o.uuid)
      }
    }
    // Role-based permissions (inheritance)
    for (const r of o.roles) {
      for (const pid of r.permissions) {
        if (!summary[pid]) summary[pid] = { orgs: [], orgSet: new Set(), userCount: 0 }
        if (!summary[pid].orgSet.has(o.uuid)) {
          summary[pid].orgs.push(orgBase)
          summary[pid].orgSet.add(o.uuid)
        }
        summary[pid].userCount += r.users.length
      }
    }
  }
  const display = {}
  for (const [pid, v] of Object.entries(summary)) {
    display[pid] = { orgs: v.orgs.sort((a,b)=>a.display_name.localeCompare(b.display_name)), userCount: v.userCount }
  }
  return display
})

function renamePermissionDisplay(p) { openDialog('perm-display', { permission: p, id: p.id, display_name: p.display_name }) }

async function refreshPermissionsContext() {
  // Reload both lists so All Permissions table shows new associations promptly.
  await Promise.all([loadPermissions(), loadOrgs()])
}

async function attachPermissionToOrg(pid, orgUuid) {
  if (!orgUuid) return
  try {
    const params = new URLSearchParams({ permission_id: pid })
    const res = await fetch(`/auth/admin/orgs/${orgUuid}/permission?${params.toString()}`, { method: 'POST' })
    const data = await res.json()
    if (data.detail) throw new Error(data.detail)
    await loadOrgs()
  } catch (e) {
  authStore.showMessage(e.message || 'Failed to add permission to org')
  }
}

async function detachPermissionFromOrg(pid, orgUuid) {
  openDialog('confirm', { message: 'Remove permission from this org?', action: async () => {
    try {
      const params = new URLSearchParams({ permission_id: pid })
      const res = await fetch(`/auth/admin/orgs/${orgUuid}/permission?${params.toString()}`, { method: 'DELETE' })
      const data = await res.json()
      if (data.detail) throw new Error(data.detail)
      await loadOrgs()
    } catch (e) {
      authStore.showMessage(e.message || 'Failed to remove permission from org')
    }
  } })
}

function parseHash() {
  const h = window.location.hash || ''
  currentOrgId.value = null
  currentUserId.value = null
  if (h.startsWith('#org/')) {
    currentOrgId.value = h.slice(5)
  } else if (h.startsWith('#user/')) {
    currentUserId.value = h.slice(6)
  }
}

async function loadOrgs() {
  const res = await fetch('/auth/admin/orgs')
  const data = await res.json()
  if (data.detail) throw new Error(data.detail)
  // Restructure to attach users to roles instead of flat user list at org level
  orgs.value = data.map(o => {
    const roles = o.roles.map(r => ({ ...r, org_uuid: o.uuid, users: [] }))
    const roleMap = Object.fromEntries(roles.map(r => [r.display_name, r]))
    for (const u of o.users || []) {
      if (roleMap[u.role]) roleMap[u.role].users.push(u)
    }
    return { ...o, roles }
  })
}

async function loadPermissions() {
  const res = await fetch('/auth/admin/permissions')
  const data = await res.json()
  if (data.detail) throw new Error(data.detail)
  permissions.value = data
}

async function load() {
  loading.value = true
  error.value = null
  try {
  const res = await fetch('/auth/api/user-info', { method: 'POST' })
    const data = await res.json()
    if (data.detail) throw new Error(data.detail)
    info.value = data
    if (data.authenticated && (data.is_global_admin || data.is_org_admin)) {
      await Promise.all([loadOrgs(), loadPermissions()])
    }
    // After loading orgs decide view if not global admin
    if (!data.is_global_admin && data.is_org_admin && orgs.value.length === 1) {
      if (!window.location.hash || window.location.hash === '#overview') {
        currentOrgId.value = orgs.value[0].uuid
        window.location.hash = `#org/${currentOrgId.value}`
      } else {
        parseHash()
      }
    } else parseHash()
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

// Org actions
function createOrg() { openDialog('org-create', {}) }

function updateOrg(org) { openDialog('org-update', { org }) }

function deleteOrg(org) {
  if (!info.value?.is_global_admin) { authStore.showMessage('Global admin only'); return }
  openDialog('confirm', { message: `Delete organization ${org.display_name}?`, action: async () => {
    const res = await fetch(`/auth/admin/orgs/${org.uuid}`, { method: 'DELETE' })
    const data = await res.json(); if (data.detail) throw new Error(data.detail)
    await loadOrgs()
  } })
}

function createUserInRole(org, role) { openDialog('user-create', { org, role }) }

async function moveUserToRole(org, user, targetRoleDisplayName) {
  if (user.role === targetRoleDisplayName) return
  const res = await fetch(`/auth/admin/orgs/${org.uuid}/users/${user.uuid}/role`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ role: targetRoleDisplayName })
  })
  const data = await res.json()
  if (data.detail) { authStore.showMessage(data.detail); return }
  await loadOrgs()
}

function onUserDragStart(e, user, org_uuid) {
  e.dataTransfer.effectAllowed = 'move'
  e.dataTransfer.setData('text/plain', JSON.stringify({ user_uuid: user.uuid, org_uuid }))
}

function onRoleDragOver(e) {
  e.preventDefault()
  e.dataTransfer.dropEffect = 'move'
}

function onRoleDrop(e, org, role) {
  e.preventDefault()
  try {
    const data = JSON.parse(e.dataTransfer.getData('text/plain'))
    if (data.org_uuid !== org.uuid) return // only within same org
    const user = org.roles.flatMap(r => r.users).find(u => u.uuid === data.user_uuid)
    if (user) moveUserToRole(org, user, role.display_name)
  } catch (_) { /* ignore */ }
}

// (legacy function retained but unused in UI)
async function addOrgPermission() { /* obsolete */ }

async function removeOrgPermission() { /* obsolete */ }

// Role actions
function createRole(org) { openDialog('role-create', { org }) }

function updateRole(role) { openDialog('role-update', { role }) }

function deleteRole(role) {
  openDialog('confirm', { message: `Delete role ${role.display_name}?`, action: async () => {
    const res = await fetch(`/auth/admin/orgs/${role.org_uuid}/roles/${role.uuid}`, { method: 'DELETE' })
    const data = await res.json(); if (data.detail) throw new Error(data.detail)
    await loadOrgs()
  } })
}

// Permission actions
function updatePermission(p) { openDialog('perm-display', { permission: p }) }

function deletePermission(p) {
  openDialog('confirm', { message: `Delete permission ${p.id}?`, action: async () => {
    const params = new URLSearchParams({ permission_id: p.id })
    const res = await fetch(`/auth/admin/permission?${params.toString()}`, { method: 'DELETE' })
    const data = await res.json(); if (data.detail) throw new Error(data.detail)
    await loadPermissions()
  } })
}

onMounted(async () => {
  window.addEventListener('hashchange', parseHash)
  await authStore.loadSettings()
  if (authStore.settings?.rp_name) {
    document.title = authStore.settings.rp_name + ' Admin'
  }
  load()
})

const selectedOrg = computed(() => orgs.value.find(o => o.uuid === currentOrgId.value) || null)

function openOrg(o) {
  window.location.hash = `#org/${o.uuid}`
}

function goOverview() {
  window.location.hash = '#overview'
}

function openUser(u) {
  window.location.hash = `#user/${u.uuid}`
}

const selectedUser = computed(() => {
  if (!currentUserId.value) return null
  for (const o of orgs.value) {
    for (const r of o.roles) {
      const u = r.users.find(x => x.uuid === currentUserId.value)
      if (u) return { ...u, org_uuid: o.uuid, role_display_name: r.display_name }
    }
  }
  return null
})

const pageHeading = computed(() => {
  if (selectedUser.value) return 'Organization Admin'
  if (selectedOrg.value) return 'Organization Admin'
  return (authStore.settings?.rp_name || 'Passkey') + ' Admin'
})

// Breadcrumb entries for admin app.
const breadcrumbEntries = computed(() => {
  const entries = [
    { label: 'Auth', href: '/auth/' },
    { label: 'Admin', href: '/auth/admin/' }
  ]
  // Determine organization for user view if selectedOrg not explicitly chosen.
  let orgForUser = null
  if (selectedUser.value) {
    orgForUser = orgs.value.find(o => o.uuid === selectedUser.value.org_uuid) || null
  }
  const orgToShow = selectedOrg.value || orgForUser
  if (orgToShow) {
    entries.push({ label: orgToShow.display_name, href: `#org/${orgToShow.uuid}` })
  }
  if (selectedUser.value) {
    entries.push({ label: selectedUser.value.display_name || 'User', href: `#user/${selectedUser.value.uuid}` })
  }
  return entries
})

watch(selectedUser, async (u) => {
  if (!u) { userDetail.value = null; return }
  try {
  const res = await fetch(`/auth/admin/orgs/${u.org_uuid}/users/${u.uuid}`)
    const data = await res.json()
    if (data.detail) throw new Error(data.detail)
    userDetail.value = data
  } catch (e) {
    userDetail.value = { error: e.message }
  }
})

const showRegModal = ref(false)
function generateUserRegistrationLink(u) {
  showRegModal.value = true
}

function onLinkCopied() {
  authStore.showMessage('Link copied to clipboard!')
}

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text)
    .catch(()=>{})
}

function permissionDisplayName(id) {
  return permissions.value.find(p => p.id === id)?.display_name || id
}

async function toggleOrgPermission(org, permId, checked) {
  // Build next permission list
  const has = org.permissions.includes(permId)
  if (checked && has) return
  if (!checked && !has) return
  const next = checked ? [...org.permissions, permId] : org.permissions.filter(p => p !== permId)
  // Optimistic update
  const prev = [...org.permissions]
  org.permissions = next
  try {
    const params = new URLSearchParams({ permission_id: permId })
    const res = await fetch(`/auth/admin/orgs/${org.uuid}/permission?${params.toString()}`, { method: checked ? 'POST' : 'DELETE' })
    const data = await res.json()
    if (data.detail) throw new Error(data.detail)
    await loadOrgs()
  } catch (e) {
    authStore.showMessage(e.message || 'Failed to update organization permission')
    org.permissions = prev // revert
  }
}

function openDialog(type, data) { dialog.value = { type, data, busy: false, error: '' } }
function closeDialog() { dialog.value = { type: null, data: null, busy: false, error: '' } }

async function onUserNameSaved() {
  await loadOrgs()
  if (selectedUser.value) {
    try {
  const r = await fetch(`/auth/admin/orgs/${selectedUser.value.org_uuid}/users/${selectedUser.value.uuid}`)
      const jd = await r.json()
      if (!r.ok || jd.detail) throw new Error(jd.detail || 'Reload failed')
      userDetail.value = jd
    } catch (e) { authStore.showMessage(e.message || 'Failed to reload user', 'error') }
  }
  authStore.showMessage('User renamed', 'success', 1500)
}

async function submitDialog() {
  if (!dialog.value.type || dialog.value.busy) return
  dialog.value.busy = true; dialog.value.error = ''
  try {
    const t = dialog.value.type
    if (t === 'org-create') {
      const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const res = await fetch('/auth/admin/orgs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, permissions: [] }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await Promise.all([loadOrgs(), loadPermissions()])
    } else if (t === 'org-update') {
      const { org } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const res = await fetch(`/auth/admin/orgs/${org.uuid}`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, permissions: org.permissions }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await loadOrgs()
    } else if (t === 'role-create') {
      const { org } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const res = await fetch(`/auth/admin/orgs/${org.uuid}/roles`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, permissions: [] }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await loadOrgs()
    } else if (t === 'role-update') {
      const { role } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const permsCsv = dialog.value.data.perms || ''
      const perms = permsCsv.split(',').map(s=>s.trim()).filter(Boolean)
  const res = await fetch(`/auth/admin/orgs/${role.org_uuid}/roles/${role.uuid}`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, permissions: perms }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await loadOrgs()
    } else if (t === 'user-create') {
      const { org, role } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const res = await fetch(`/auth/admin/orgs/${org.uuid}/users`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, role: role.display_name }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await loadOrgs()
    } else if (t === 'perm-display') {
      const { permission } = dialog.value.data
      const newId = dialog.value.data.id?.trim()
      const newDisplay = dialog.value.data.display_name?.trim()
      if (!newDisplay) throw new Error('Display name required')
      if (!newId) throw new Error('ID required')
      
      if (newId !== permission.id) {
        // ID changed, use rename endpoint
        const body = { old_id: permission.id, new_id: newId, display_name: newDisplay }
        const res = await fetch('/auth/admin/permission/rename', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
        let data; try { data = await res.json() } catch(_) { data = {} }
        if (!res.ok || data.detail) throw new Error(data.detail || data.error || `Failed (${res.status})`)
      } else if (newDisplay !== permission.display_name) {
        // Only display name changed
        const params = new URLSearchParams({ permission_id: permission.id, display_name: newDisplay })
        const res = await fetch(`/auth/admin/permission?${params.toString()}`, { method: 'PUT' })
        const d = await res.json(); if (d.detail) throw new Error(d.detail)
      }
      await loadPermissions()
    } else if (t === 'perm-create') {
      const id = dialog.value.data.id?.trim(); if (!id) throw new Error('ID required')
      const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Display name required')
      const res = await fetch('/auth/admin/permissions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id, display_name: name }) })
      const data = await res.json(); if (data.detail) throw new Error(data.detail)
      await loadPermissions(); dialog.value.data.id = ''; dialog.value.data.name = ''
    } else if (t === 'confirm') {
      const action = dialog.value.data.action; if (action) await action()
    }
    closeDialog()
  } catch (e) {
    dialog.value.error = e.message || 'Error'
  } finally { dialog.value.busy = false }
}
</script>

<template>
  <div class="app-shell admin-shell">
    <StatusMessage />
    <main class="app-main">
      <section class="view-root view-admin">
        <div class="view-content view-content--wide">
          <header class="view-header">
            <h1>{{ pageHeading }}</h1>
            <Breadcrumbs :entries="breadcrumbEntries" />
            <p class="view-lede" v-if="info?.authenticated">
              Manage organizations, roles, permissions, and passkeys for your relying party.
            </p>
          </header>

          <section class="section-block admin-section">
            <div class="section-body admin-section-body">
              <div v-if="loading" class="surface surface--tight">Loading…</div>
              <div v-else-if="error" class="surface surface--tight error">{{ error }}</div>
              <template v-else>
                <div v-if="!info?.authenticated" class="surface surface--tight">
                  <p>You must be authenticated.</p>
                </div>
                <div v-else-if="!(info?.is_global_admin || info?.is_org_admin)" class="surface surface--tight">
                  <p>Insufficient permissions.</p>
                </div>
                <div v-else class="admin-panels">
                  <div v-if="!selectedUser && !selectedOrg && (info.is_global_admin || info.is_org_admin)" class="permissions-section">
                    <h2>Organizations</h2>
                    <div class="actions">
                      <button v-if="info.is_global_admin" @click="createOrg">+ Create Org</button>
                    </div>
                    <table class="org-table">
                      <thead>
                        <tr>
                          <th>Name</th>
                          <th>Roles</th>
                          <th>Members</th>
                          <th v-if="info.is_global_admin">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr v-for="o in orgs" :key="o.uuid">
                          <td>
                            <a href="#org/{{o.uuid}}" @click.prevent="openOrg(o)">{{ o.display_name }}</a>
                            <button v-if="info.is_global_admin" @click="updateOrg(o)" class="icon-btn edit-org-btn" aria-label="Rename organization" title="Rename organization">✏️</button>
                          </td>
                          <td>{{ o.roles.length }}</td>
                          <td>{{ o.roles.reduce((acc,r)=>acc + r.users.length,0) }}</td>
                          <td v-if="info.is_global_admin">
                            <button @click="deleteOrg(o)" class="icon-btn delete-icon" aria-label="Delete organization" title="Delete organization">❌</button>
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>

                  <div v-if="selectedUser" class="card surface user-detail">
                    <UserBasicInfo
                      v-if="userDetail && !userDetail.error"
                      :name="userDetail.display_name || selectedUser.display_name"
                      :visits="userDetail.visits"
                      :created-at="userDetail.created_at"
                      :last-seen="userDetail.last_seen"
                      :loading="loading"
                      :org-display-name="userDetail.org.display_name"
                      :role-name="userDetail.role"
                      :update-endpoint="`/auth/admin/orgs/${selectedUser.org_uuid}/users/${selectedUser.uuid}/display-name`"
                      @saved="onUserNameSaved"
                    />
                    <div v-else-if="userDetail?.error" class="error small">{{ userDetail.error }}</div>
                    <template v-if="userDetail && !userDetail.error">
                      <h3 class="cred-title">Registered Passkeys</h3>
                      <CredentialList :credentials="userDetail.credentials" :aaguid-info="userDetail.aaguid_info" />
                    </template>
                    <div class="actions">
                      <button @click="generateUserRegistrationLink(selectedUser)">Generate Registration Token</button>
                      <button @click="goOverview" v-if="info.is_global_admin" class="icon-btn" title="Overview">🏠</button>
                      <button @click="openOrg(selectedOrg)" v-if="selectedOrg" class="icon-btn" title="Back to Org">↩️</button>
                    </div>
                    <p class="matrix-hint muted">Use the token dialog to register a new credential for the member.</p>
                    <RegistrationLinkModal
                      v-if="showRegModal"
                      :endpoint="`/auth/admin/orgs/${selectedUser.org_uuid}/users/${selectedUser.uuid}/create-link`"
                      :auto-copy="false"
                      @close="showRegModal = false"
                      @copied="onLinkCopied"
                    />
                  </div>
                  <div v-else-if="selectedOrg" class="card surface">
                    <h2 class="org-title" :title="selectedOrg.uuid">
                      <span class="org-name">{{ selectedOrg.display_name }}</span>
                      <button @click="updateOrg(selectedOrg)" class="icon-btn" aria-label="Rename organization" title="Rename organization">✏️</button>
                    </h2>
                    <div class="org-actions"></div>

                    <div class="matrix-wrapper">
                      <div class="matrix-scroll">
                        <div
                          class="perm-matrix-grid"
                          :style="{ gridTemplateColumns: 'minmax(180px, 1fr) ' + selectedOrg.roles.map(()=> '2.2rem').join(' ') + ' 2.2rem' }"
                        >
                          <div class="grid-head perm-head">Permission</div>
                          <div
                            v-for="r in selectedOrg.roles"
                            :key="'head-' + r.uuid"
                            class="grid-head role-head"
                            :title="r.display_name"
                          >
                            <span>{{ r.display_name }}</span>
                          </div>
                          <div class="grid-head role-head add-role-head" title="Add role" @click="createRole(selectedOrg)" role="button">➕</div>

                          <template v-for="pid in selectedOrg.permissions" :key="pid">
                            <div class="perm-name" :title="pid">{{ permissionDisplayName(pid) }}</div>
                            <div
                              v-for="r in selectedOrg.roles"
                              :key="r.uuid + '-' + pid"
                              class="matrix-cell"
                            >
                              <input
                                type="checkbox"
                                :checked="r.permissions.includes(pid)"
                                @change="e => toggleRolePermission(r, pid, e.target.checked)"
                              />
                            </div>
                            <div class="matrix-cell add-role-cell" />
                          </template>
                        </div>
                      </div>
                      <p class="matrix-hint muted">Toggle which permissions each role grants.</p>
                    </div>
                    <div class="roles-grid">
                      <div
                        v-for="r in selectedOrg.roles"
                        :key="r.uuid"
                        class="role-column"
                        @dragover="onRoleDragOver"
                        @drop="e => onRoleDrop(e, selectedOrg, r)"
                      >
                        <div class="role-header">
                          <strong class="role-name" :title="r.uuid">
                            <span>{{ r.display_name }}</span>
                            <button @click="updateRole(r)" class="icon-btn" aria-label="Edit role" title="Edit role">✏️</button>
                          </strong>
                          <div class="role-actions">
                            <button @click="createUserInRole(selectedOrg, r)" class="plus-btn" aria-label="Add user" title="Add user">➕</button>
                          </div>
                        </div>
                        <template v-if="r.users.length > 0">
                          <ul class="user-list">
                            <li
                              v-for="u in r.users"
                              :key="u.uuid"
                              class="user-chip"
                              draggable="true"
                              @dragstart="e => onUserDragStart(e, u, selectedOrg.uuid)"
                              @click="openUser(u)"
                              :title="u.uuid"
                            >
                              <span class="name">{{ u.display_name }}</span>
                              <span class="meta">{{ u.last_seen ? new Date(u.last_seen).toLocaleDateString() : '—' }}</span>
                            </li>
                          </ul>
                        </template>
                        <div v-else class="empty-role">
                          <p class="empty-text muted">No members</p>
                          <button @click="deleteRole(r)" class="icon-btn delete-icon" aria-label="Delete empty role" title="Delete role">❌</button>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div v-if="!selectedUser && !selectedOrg && (info.is_global_admin || info.is_org_admin)" class="permissions-section">
                    <h2>Permissions</h2>
                    <div class="matrix-wrapper">
                      <div class="matrix-scroll">
                        <div
                          class="perm-matrix-grid"
                          :style="{ gridTemplateColumns: 'minmax(180px, 1fr) ' + orgs.map(()=> '2.2rem').join(' ') }"
                        >
                          <div class="grid-head perm-head">Permission</div>
                          <div
                            v-for="o in [...orgs].sort((a,b)=> a.display_name.localeCompare(b.display_name))"
                            :key="'head-' + o.uuid"
                            class="grid-head org-head"
                            :title="o.display_name"
                          >
                            <span>{{ o.display_name }}</span>
                          </div>

                          <template v-for="p in [...permissions].sort((a,b)=> a.id.localeCompare(b.id))" :key="p.id">
                            <div class="perm-name" :title="p.id">
                              <span class="display-text">{{ p.display_name }}</span>
                            </div>
                            <div
                              v-for="o in [...orgs].sort((a,b)=> a.display_name.localeCompare(b.display_name))"
                              :key="o.uuid + '-' + p.id"
                              class="matrix-cell"
                            >
                              <input
                                type="checkbox"
                                :checked="o.permissions.includes(p.id)"
                                @change="e => toggleOrgPermission(o, p.id, e.target.checked)"
                              />
                            </div>
                          </template>
                        </div>
                      </div>
                      <p class="matrix-hint muted">Toggle which permissions each organization can grant to its members.</p>
                    </div>
                    <div class="actions">
                      <button v-if="info.is_global_admin" @click="openDialog('perm-create', {})">+ Create Permission</button>
                    </div>
                    <table class="org-table">
                        <thead>
                          <tr>
                            <th scope="col">Permission</th>
                            <th scope="col" class="center">Members</th>
                            <th scope="col" class="center">Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr v-for="p in [...permissions].sort((a,b)=> a.id.localeCompare(b.id))" :key="p.id">
                            <td class="perm-name-cell">
                              <div class="perm-title">
                                <span class="display-text">{{ p.display_name }}</span>
                                <button @click="renamePermissionDisplay(p)" class="icon-btn edit-display-btn" aria-label="Edit display name" title="Edit display name">✏️</button>
                              </div>
                              <div class="perm-id-info">
                                <span class="id-text">{{ p.id }}</span>
                                <button @click="renamePermissionDisplay(p)" class="icon-btn edit-id-btn" aria-label="Edit id" title="Edit id">🆔</button>
                              </div>
                            </td>
                            <td class="perm-members center">{{ permissionSummary[p.id]?.userCount || 0 }}</td>
                            <td class="perm-actions center">
                              <button @click="deletePermission(p)" class="icon-btn delete-icon" aria-label="Delete permission" title="Delete permission">❌</button>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                  </div>
                </div>
              </template>
            </div>
          </section>
        </div>
      </section>
    </main>
    <div v-if="dialog.type" class="modal-overlay" @keydown.esc.prevent.stop="closeDialog" tabindex="-1">
      <div class="modal" role="dialog" aria-modal="true">
        <h3 class="modal-title">
          <template v-if="dialog.type==='org-create'">Create Organization</template>
          <template v-else-if="dialog.type==='org-update'">Rename Organization</template>
          <template v-else-if="dialog.type==='role-create'">Create Role</template>
          <template v-else-if="dialog.type==='role-update'">Edit Role</template>
          <template v-else-if="dialog.type==='user-create'">Add User To Role</template>
          <template v-else-if="dialog.type==='perm-create'">Create Permission</template>
          <template v-else-if="dialog.type==='perm-display'">Edit Permission Display</template>
          <template v-else-if="dialog.type==='confirm'">Confirm</template>
        </h3>
        <form @submit.prevent="submitDialog" class="modal-form">
          <template v-if="dialog.type==='org-create' || dialog.type==='org-update'">
            <label>Name
              <input v-model="dialog.data.name" :placeholder="dialog.type==='org-update'? dialog.data.org.display_name : 'Organization name'" required />
            </label>
          </template>
          <template v-else-if="dialog.type==='role-create'">
            <label>Role Name
              <input v-model="dialog.data.name" placeholder="Role name" required />
            </label>
          </template>
          <template v-else-if="dialog.type==='role-update'">
            <label>Role Name
              <input v-model="dialog.data.name" :placeholder="dialog.data.role.display_name" required />
            </label>
            <label>Permissions (comma separated)
              <textarea v-model="dialog.data.perms" rows="2" placeholder="perm:a, perm:b"></textarea>
            </label>
          </template>
          <template v-else-if="dialog.type==='user-create'">
            <p class="small muted">Role: {{ dialog.data.role.display_name }}</p>
            <label>Display Name
              <input v-model="dialog.data.name" placeholder="User display name" required />
            </label>
          </template>
          <template v-else-if="dialog.type==='perm-create'">
            <label>Permission ID
              <input v-model="dialog.data.id" placeholder="permission id" required :pattern="PERMISSION_ID_PATTERN" title="Allowed: A-Za-z0-9:._~-" />
            </label>
            <label>Display Name
              <input v-model="dialog.data.name" placeholder="display name" required />
            </label>
          </template>
          <template v-else-if="dialog.type==='perm-display'">
            <label>Permission ID
              <input v-model="dialog.data.id" :placeholder="dialog.data.permission.id" required :pattern="PERMISSION_ID_PATTERN" title="Allowed: A-Za-z0-9:._~-" />
            </label>
            <label>Display Name
              <input v-model="dialog.data.display_name" :placeholder="dialog.data.permission.display_name" required />
            </label>
          </template>
          <template v-else-if="dialog.type==='confirm'">
            <p>{{ dialog.data.message }}</p>
          </template>
          <div v-if="dialog.error" class="error small">{{ dialog.error }}</div>
          <div class="modal-actions">
            <button type="submit" :disabled="dialog.busy">{{ dialog.type==='confirm' ? 'OK' : 'Save' }}</button>
            <button type="button" @click="closeDialog" :disabled="dialog.busy">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<style scoped>
.view-admin { padding-bottom: var(--space-3xl); }
.view-header { display: flex; flex-direction: column; gap: var(--space-sm); }
.admin-section { margin-top: var(--space-xl); }
.admin-section-body { display: flex; flex-direction: column; gap: var(--space-xl); }
.admin-panels { display: flex; flex-direction: column; gap: var(--space-xl); }
.permissions-section { margin-bottom: var(--space-xl); }
.permissions-section h2 { margin-bottom: var(--space-md); }
.actions { display: flex; flex-wrap: wrap; gap: var(--space-sm); align-items: center; }
.actions button { width: auto; }
.org-table a { text-decoration: none; color: var(--color-link); }
.org-table a:hover { text-decoration: underline; }
.perm-name-cell { display: flex; flex-direction: column; gap: 0.3rem; }
.perm-title { font-weight: 600; color: var(--color-heading); }
.perm-id-info { font-size: 0.8rem; color: var(--color-text-muted); }
.plus-btn { background: var(--color-accent-soft); color: var(--color-accent); border: none; border-radius: var(--radius-sm); padding: 0.25rem 0.45rem; font-size: 1.1rem; cursor: pointer; }
.plus-btn:hover { background: rgba(37, 99, 235, 0.18); }
.user-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: var(--space-xs); }
.user-chip { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: 0.45rem 0.6rem; display: flex; justify-content: space-between; gap: var(--space-sm); cursor: grab; }
.user-chip .meta { font-size: 0.7rem; color: var(--color-text-muted); }
.empty-role { border: 1px dashed var(--color-border-strong); border-radius: var(--radius-md); padding: var(--space-sm); display: flex; flex-direction: column; gap: var(--space-xs); align-items: flex-start; }
.icon-btn { background: none; border: none; color: var(--color-text-muted); padding: 0.2rem; border-radius: var(--radius-sm); cursor: pointer; transition: background 0.2s ease, color 0.2s ease; }
.icon-btn:hover { color: var(--color-heading); background: var(--color-surface-muted); }
.delete-icon { color: var(--color-danger); }
.delete-icon:hover { background: var(--color-danger-bg); color: var(--color-danger-text); }
.matrix-wrapper { margin: var(--space-md) 0; padding: var(--space-lg); }
.matrix-scroll { overflow-x: auto; }
.matrix-hint { font-size: 0.8rem; color: var(--color-text-muted); }
.perm-matrix-grid { display: inline-grid; gap: 0.25rem; align-items: stretch; }
.perm-matrix-grid > * { padding: 0.35rem 0.45rem; font-size: 0.75rem; }
.perm-matrix-grid .grid-head { color: var(--color-text-muted); text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em; }
.perm-matrix-grid .perm-head { display: flex; align-items: flex-end; justify-content: flex-start; padding: 0.35rem 0.45rem; font-size: 0.75rem; }
.perm-matrix-grid .role-head { display: flex; align-items: flex-end; justify-content: center; }
.perm-matrix-grid .role-head span { writing-mode: vertical-rl; transform: rotate(180deg); font-size: 0.65rem; }
.perm-matrix-grid .org-head { display: flex; align-items: flex-end; justify-content: center; }
.perm-matrix-grid .org-head span { writing-mode: vertical-rl; transform: rotate(180deg); font-size: 0.65rem; }
.perm-matrix-grid .add-role-head,
.perm-matrix-grid .add-permission-head { cursor: pointer; }
.perm-name { font-weight: 600; color: var(--color-heading); padding: 0.35rem 0.45rem; font-size: 0.75rem; }
.perm-orgs { gap: 0.5rem; }
.perm-orgs-list { display: flex; flex-wrap: wrap; gap: 0.4rem; }
.org-pill { display: inline-flex; align-items: center; gap: 0.3rem; padding: 0.2rem 0.55rem; border-radius: 999px; background: var(--color-surface-muted); border: 1px solid var(--color-border); font-size: 0.75rem; }
.pill-x { background: none; border: none; color: var(--color-danger); cursor: pointer; }
.pill-x:hover { color: var(--color-danger-text); }
.org-add-wrapper { display: inline-flex; align-items: center; gap: var(--space-xs); position: relative; }
.add-org-btn { background: var(--color-accent-soft); color: var(--color-accent); border: none; border-radius: var(--radius-sm); padding: 0.2rem 0.4rem; cursor: pointer; }
.add-org-btn:hover { background: rgba(37, 99, 235, 0.18); }
.org-add-menu { position: absolute; top: calc(100% + var(--space-xs)); right: 0; background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-md); box-shadow: var(--shadow-lg); padding: var(--space-xs); min-width: 220px; z-index: 20; }
.org-add-list { display: flex; flex-direction: column; gap: var(--space-xs); max-height: 240px; overflow-y: auto; }
.org-add-item { background: none; border: 1px solid transparent; border-radius: var(--radius-sm); padding: 0.45rem 0.6rem; text-align: left; cursor: pointer; }
.org-add-item:hover { background: var(--color-surface-muted); border-color: var(--color-border-strong); }
.org-add-footer { display: flex; justify-content: flex-end; margin-top: var(--space-xs); }
.org-add-cancel { background: none; border: none; color: var(--color-text-muted); cursor: pointer; }
.display-text { margin-right: var(--space-xs); }
.edit-display-btn { padding: 0.1rem 0.2rem; font-size: 0.8rem; }
.edit-org-btn { padding: 0.1rem 0.2rem; font-size: 0.8rem; margin-left: var(--space-xs); }
.perm-actions { text-align: center; }
.small { font-size: 0.9rem; }
.muted { color: var(--color-text-muted); }
.error { color: var(--color-danger-text); }

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(.1rem);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-xl);
  padding: var(--space-lg);
  max-width: 500px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-title {
  margin: 0 0 var(--space-md) 0;
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--color-heading);
}

.modal-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
}

.modal-form label {
  display: flex;
  flex-direction: column;
  gap: var(--space-xs);
  font-weight: 500;
}

.modal-form input,
.modal-form textarea {
  padding: var(--space-sm);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  background: var(--color-surface);
  color: var(--color-text);
}

.modal-form input:focus,
.modal-form textarea:focus {
  outline: none;
  border-color: var(--color-accent);
  box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.1);
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-sm);
  margin-top: var(--space-lg);
}

@media (max-width: 720px) {
  .card.surface { padding: var(--space-md); }
  .actions { flex-direction: column; align-items: flex-start; }
  .roles-grid { flex-direction: column; }
  .org-add-menu { left: 0; right: auto; }
}
</style>
