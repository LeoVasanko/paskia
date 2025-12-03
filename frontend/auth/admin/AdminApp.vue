<script setup>
import { ref, onMounted, onBeforeUnmount, onUnmounted, computed, watch } from 'vue'
import Breadcrumbs from '@/components/Breadcrumbs.vue'
import CredentialList from '@/components/CredentialList.vue'
import UserBasicInfo from '@/components/UserBasicInfo.vue'
import RegistrationLinkModal from '@/components/RegistrationLinkModal.vue'
import StatusMessage from '@/components/StatusMessage.vue'
import LoadingView from '@/components/LoadingView.vue'
import AuthRequiredMessage from '@/components/AccessDenied.vue'
import AdminOverview from '@/admin/AdminOverview.vue'
import AdminOrgDetail from '@/admin/AdminOrgDetail.vue'
import AdminUserDetail from '@/admin/AdminUserDetail.vue'
import AdminDialogs from '@/admin/AdminDialogs.vue'
import { useAuthStore } from '@/stores/auth'
import { getSettings, adminUiPath, makeUiHref } from '@/utils/settings'

const info = ref(null)
const loading = ref(true)
const loadingMessage = ref('Loading...')
const authenticated = ref(false)
const showBackMessage = ref(false)
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
let authIframe = null

watch(() => authStore.authRequired, (required) => {
  if (required) {
    authenticated.value = false
    loading.value = true
    showAuthIframe()
    authStore.clearAuthRequired()
  }
})

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
    const orgPerms = new Set(o.permissions || [])

    // Org-level permissions (direct) - only count if org can grant them
    for (const pid of o.permissions || []) {
      if (!summary[pid]) summary[pid] = { orgs: [], orgSet: new Set(), userCount: 0 }
      if (!summary[pid].orgSet.has(o.uuid)) {
        summary[pid].orgs.push(orgBase)
        summary[pid].orgSet.add(o.uuid)
      }
    }

    // Role-based permissions (inheritance) - only count if org can grant them
    for (const r of o.roles) {
      for (const pid of r.permissions) {
        // Only count if the org can grant this permission
        if (!orgPerms.has(pid)) continue

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
    const res = await fetch(`/auth/api/admin/orgs/${orgUuid}/permission?${params.toString()}`, { method: 'POST' })
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
      const res = await fetch(`/auth/api/admin/orgs/${orgUuid}/permission?${params.toString()}`, { method: 'DELETE' })
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
  const res = await fetch('/auth/api/admin/orgs')
  if (res.status === 401) {
    authStore.authRequired = true
    throw new Error('Authentication required')
  }
  const data = await res.json()
  if (data.detail) throw new Error(data.detail)
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
  const res = await fetch('/auth/api/admin/permissions')
  if (res.status === 401) {
    authStore.authRequired = true
    throw new Error('Authentication required')
  }
  const data = await res.json()
  if (data.detail) throw new Error(data.detail)
  permissions.value = data
}

async function load() {
  loading.value = true
  loadingMessage.value = 'Loading...'
  error.value = null
  try {
    const res = await fetch('/auth/api/user-info', { method: 'POST' })
    if (res.status === 401) {
      authStore.authRequired = true
      loading.value = true
      return
    }
    const data = await res.json()
    if (data.detail) throw new Error(data.detail)
    info.value = data
    authenticated.value = true

    // Check if user has required permissions
    if (data.authenticated && !(data.is_global_admin || data.is_org_admin)) {
      // User is authenticated but lacks required permissions - show auth iframe
      authStore.authRequired = true
      loading.value = true
      return
    }

    if (data.authenticated && (data.is_global_admin || data.is_org_admin)) {
      await Promise.all([loadOrgs(), loadPermissions()])
    }
    if (!data.is_global_admin && data.is_org_admin && orgs.value.length === 1) {
      if (!window.location.hash || window.location.hash === '#overview') {
        currentOrgId.value = orgs.value[0].uuid
        window.location.hash = `#org/${currentOrgId.value}`
        authStore.showMessage(`Navigating to ${orgs.value[0].display_name} Administration`, 'info', 3000)
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

function updateOrg(org) { openDialog('org-update', { org, name: org.display_name }) }

function editUserName(user) { openDialog('user-update-name', { user, name: user.display_name }) }

function deleteOrg(org) {
  if (!info.value?.is_global_admin) { authStore.showMessage('Global admin only'); return }
  openDialog('confirm', { message: `Delete organization ${org.display_name}?`, action: async () => {
    const res = await fetch(`/auth/api/admin/orgs/${org.uuid}`, { method: 'DELETE' })
    const data = await res.json(); if (data.detail) throw new Error(data.detail)
    await Promise.all([loadOrgs(), loadPermissions()])
  } })
}

function createUserInRole(org, role) { openDialog('user-create', { org, role }) }

async function moveUserToRole(org, user, targetRoleDisplayName) {
  if (user.role === targetRoleDisplayName) return
  const res = await fetch(`/auth/api/admin/orgs/${org.uuid}/users/${user.uuid}/role`, {
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

function updateRole(role) { openDialog('role-update', { role, name: role.display_name }) }

function deleteRole(role) {
  openDialog('confirm', { message: `Delete role ${role.display_name}?`, action: async () => {
    const res = await fetch(`/auth/api/admin/orgs/${role.org_uuid}/roles/${role.uuid}`, { method: 'DELETE' })
    const data = await res.json(); if (data.detail) throw new Error(data.detail)
    await loadOrgs()
  } })
}

async function toggleRolePermission(role, pid, checked) {
  // Calculate new permissions array
  const newPermissions = checked
    ? [...role.permissions, pid]
    : role.permissions.filter(p => p !== pid)

  // Optimistic update
  const prevPermissions = [...role.permissions]
  role.permissions = newPermissions

  try {
    const res = await fetch(`/auth/api/admin/orgs/${role.org_uuid}/roles/${role.uuid}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ display_name: role.display_name, permissions: newPermissions })
    })
    const data = await res.json()
    if (data.detail) throw new Error(data.detail)
    await loadOrgs()
  } catch (e) {
    authStore.showMessage(e.message || 'Failed to update role permission')
    role.permissions = prevPermissions // revert
  }
}

// Permission actions
function updatePermission(p) { openDialog('perm-display', { permission: p }) }

function deletePermission(p) {
  openDialog('confirm', { message: `Delete permission ${p.id}?`, action: async () => {
    const params = new URLSearchParams({ permission_id: p.id })
    const res = await fetch(`/auth/api/admin/permission?${params.toString()}`, { method: 'DELETE' })
    const data = await res.json(); if (data.detail) throw new Error(data.detail)
    await loadPermissions()
  } })
}

function showAuthIframe() {
  hideAuthIframe()
  authIframe = document.createElement('iframe')
  authIframe.id = 'auth-iframe'
  authIframe.title = 'Authentication'
  authIframe.src = '/auth/restricted/?mode=login'
  document.body.appendChild(authIframe)
  loadingMessage.value = 'Authentication required...'
}

function hideAuthIframe() {
  if (authIframe) {
    authIframe.remove()
    authIframe = null
  }
}

function reloadPage() {
  window.location.reload()
}

function handleAuthMessage(event) {
  const data = event.data
  if (!data?.type) return

  switch (data.type) {
    case 'auth-success':
      hideAuthIframe()
      loading.value = true
      loadingMessage.value = 'Loading admin panel...'
      authStore.clearAuthRequired()
      load()
      break

    case 'auth-error':
      if (!data.cancelled) {
        authStore.showMessage(data.message || 'Authentication failed', 'error', 5000)
      }
      break

    case 'auth-back':
      hideAuthIframe()
      loading.value = false
      showBackMessage.value = true
      authStore.showMessage('Authentication cancelled', 'info', 3000)
      break

    case 'auth-close-request':
      hideAuthIframe()
      break
  }
}

onMounted(async () => {
  window.addEventListener('message', handleAuthMessage)
  window.addEventListener('hashchange', parseHash)
  const settings = await getSettings()
  if (settings?.rp_name) document.title = settings.rp_name + ' Admin'
  await load()
  if (authStore.authRequired) {
    showAuthIframe()
  }
})

onUnmounted(() => {
  window.removeEventListener('message', handleAuthMessage)
  hideAuthIframe()
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
  if (selectedUser.value) return 'Admin: User'
  if (selectedOrg.value) return 'Admin: Org'
  return ((authStore.settings?.rp_name) || 'Master') + ' Admin'
})

// Breadcrumb entries for admin app.
const breadcrumbEntries = computed(() => {
  const entries = [
    { label: 'Auth', href: makeUiHref() },
    { label: 'Admin', href: adminUiPath() }
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
  const res = await fetch(`/auth/api/admin/orgs/${u.org_uuid}/users/${u.uuid}`)
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
    const res = await fetch(`/auth/api/admin/orgs/${org.uuid}/permission?${params.toString()}`, { method: checked ? 'POST' : 'DELETE' })
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
  const r = await fetch(`/auth/api/admin/orgs/${selectedUser.value.org_uuid}/users/${selectedUser.value.uuid}`)
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
      const res = await fetch('/auth/api/admin/orgs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, permissions: [] }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await Promise.all([loadOrgs(), loadPermissions()])
    } else if (t === 'org-update') {
      const { org } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const res = await fetch(`/auth/api/admin/orgs/${org.uuid}`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, permissions: org.permissions }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await loadOrgs()
    } else if (t === 'role-create') {
      const { org } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const res = await fetch(`/auth/api/admin/orgs/${org.uuid}/roles`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, permissions: [] }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await loadOrgs()
    } else if (t === 'role-update') {
      const { role } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const res = await fetch(`/auth/api/admin/orgs/${role.org_uuid}/roles/${role.uuid}`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, permissions: role.permissions }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await loadOrgs()
    } else if (t === 'user-create') {
      const { org, role } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const res = await fetch(`/auth/api/admin/orgs/${org.uuid}/users`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name, role: role.display_name }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await loadOrgs()
    } else if (t === 'user-update-name') {
      const { user } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')
      const res = await fetch(`/auth/api/admin/orgs/${user.org_uuid}/users/${user.uuid}/display-name`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ display_name: name }) })
      const d = await res.json(); if (d.detail) throw new Error(d.detail); await onUserNameSaved()
    } else if (t === 'perm-display') {
      const { permission } = dialog.value.data
      const newId = dialog.value.data.id?.trim()
      const newDisplay = dialog.value.data.display_name?.trim()
      if (!newDisplay) throw new Error('Display name required')
      if (!newId) throw new Error('ID required')

      if (newId !== permission.id) {
        // ID changed, use rename endpoint
        const body = { old_id: permission.id, new_id: newId, display_name: newDisplay }
        const res = await fetch('/auth/api/admin/permission/rename', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
        let data; try { data = await res.json() } catch(_) { data = {} }
        if (!res.ok || data.detail) throw new Error(data.detail || data.error || `Failed (${res.status})`)
      } else if (newDisplay !== permission.display_name) {
        // Only display name changed
        const params = new URLSearchParams({ permission_id: permission.id, display_name: newDisplay })
        const res = await fetch(`/auth/api/admin/permission?${params.toString()}`, { method: 'PUT' })
        const d = await res.json(); if (d.detail) throw new Error(d.detail)
      }
      await loadPermissions()
    } else if (t === 'perm-create') {
      const id = dialog.value.data.id?.trim(); if (!id) throw new Error('ID required')
      const display_name = dialog.value.data.display_name?.trim(); if (!display_name) throw new Error('Display name required')
      const res = await fetch('/auth/api/admin/permissions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id, display_name }) })
      const data = await res.json(); if (data.detail) throw new Error(data.detail)
      await loadPermissions(); dialog.value.data.display_name = ''; dialog.value.data.id = ''
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
      <LoadingView v-if="loading" :message="loadingMessage" />
      <AuthRequiredMessage
        v-else-if="showBackMessage"
        @reload="reloadPage"
      />
      <section v-else-if="authenticated && (info?.is_global_admin || info?.is_org_admin)" class="view-root view-root--wide view-admin">
        <header class="view-header">
          <h1>{{ pageHeading }}</h1>
          <Breadcrumbs :entries="breadcrumbEntries" />
        </header>

        <section class="section-block admin-section">
          <div class="section-body admin-section-body">
            <div v-if="error" class="surface surface--tight error">{{ error }}</div>
            <div v-else class="admin-panels">
                                  <AdminOverview
                  v-if="!selectedUser && !selectedOrg && (info.is_global_admin || info.is_org_admin)"
                  :info="info"
                  :orgs="orgs"
                  :permissions="permissions"
                  :permission-summary="permissionSummary"
                  @create-org="createOrg"
                  @open-org="openOrg"
                  @update-org="updateOrg"
                  @delete-org="deleteOrg"
                  @toggle-org-permission="toggleOrgPermission"
                  @open-dialog="openDialog"
                  @delete-permission="deletePermission"
                  @rename-permission-display="renamePermissionDisplay"
                />

                <AdminUserDetail
                  v-else-if="selectedUser"
                  :selected-user="selectedUser"
                  :user-detail="userDetail"
                  :selected-org="selectedOrg"
                  :loading="loading"
                  :show-reg-modal="showRegModal"
                  @generate-user-registration-link="generateUserRegistrationLink"
                  @go-overview="goOverview"
                  @open-org="openOrg"
                  @on-user-name-saved="onUserNameSaved"
                  @edit-user-name="editUserName"
                  @close-reg-modal="showRegModal = false"
                />
                <AdminOrgDetail
                  v-else-if="selectedOrg"
                  :selected-org="selectedOrg"
                  :permissions="permissions"
                  @update-org="updateOrg"
                  @create-role="createRole"
                  @update-role="updateRole"
                  @delete-role="deleteRole"
                  @create-user-in-role="createUserInRole"
                  @open-user="openUser"
                  @toggle-role-permission="toggleRolePermission"
                  @on-role-drag-over="onRoleDragOver"
                  @on-role-drop="onRoleDrop"
                  @on-user-drag-start="onUserDragStart"
                />

              </div>
          </div>
        </section>
      </section>
    </main>
    <AdminDialogs
      :dialog="dialog"
      :permission-id-pattern="PERMISSION_ID_PATTERN"
      @submit-dialog="submitDialog"
      @close-dialog="closeDialog"
    />
  </div>
</template>

<style scoped>
.view-admin { padding-bottom: var(--space-3xl); }
.view-header { display: flex; flex-direction: column; gap: var(--space-sm); }
.admin-section { margin-top: var(--space-xl); }
.admin-section-body { display: flex; flex-direction: column; gap: var(--space-xl); }
.admin-panels { display: flex; flex-direction: column; gap: var(--space-xl); }
</style>
