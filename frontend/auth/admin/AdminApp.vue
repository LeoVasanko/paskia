<script setup>
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import Breadcrumbs from '@/components/Breadcrumbs.vue'
import CredentialList from '@/components/CredentialList.vue'
import UserBasicInfo from '@/components/UserBasicInfo.vue'
import StatusMessage from '@/components/StatusMessage.vue'
import LoadingView from '@/components/LoadingView.vue'
import AccessDenied from '@/components/AccessDenied.vue'
import AdminOverview from '@/admin/AdminOverview.vue'
import AdminOrgDetail from '@/admin/AdminOrgDetail.vue'
import AdminUserDetail from '@/admin/AdminUserDetail.vue'
import AdminOidcDetail from '@/admin/AdminOidcDetail.vue'
import AdminDialogs from '@/admin/AdminDialogs.vue'
import { useAuthStore } from '@/stores/auth'
import { adminUiPath, makeUiHref } from '@/utils/settings'
import { apiJson, SessionValidator } from 'paskia'
import { uuidv7 } from 'uuidv7'
import { getDirection } from '@/utils/keynav'
import { goBack } from '@/utils/helpers'

const info = ref(null)
const loading = ref(true)
const loadingMessage = ref('Loading...')
const authenticated = ref(false)
const showBackMessage = ref(false)
const error = ref(null)
const orgs = ref([])
const permissions = ref([])
const oidcClients = ref([])
const currentOrgId = ref(null) // UUID of selected org for detail view
const currentUserId = ref(null) // UUID for user detail view
const currentOidcId = ref(null) // UUID for OIDC client detail view
const userDetail = ref(null) // cached user detail object
const editingOidcClient = ref(null) // OIDC client being edited (with local changes)
const authStore = useAuthStore()
const addingOrgForPermission = ref(null)
const PERMISSION_ID_PATTERN = '^[A-Za-z0-9:._~-]+$'
const editingPermId = ref(null)
const renameIdValue = ref('')
const editingPermDisplay = ref(null)
const renameDisplayValue = ref('')
const dialog = ref({ type: null, data: null, busy: false, error: '' })
const dialogPreviousFocus = ref(null)  // Track element that had focus before dialog opened
const safeIdRegex = /[^A-Za-z0-9:._~-]/g

// Template refs for navigation
const breadcrumbsRef = ref(null)
const adminOverviewRef = ref(null)
const adminOrgDetailRef = ref(null)
const adminUserDetailRef = ref(null)
const adminOidcDetailRef = ref(null)

// Check if any modal/dialog is open (blocks arrow key navigation)
const hasActiveModal = computed(() => dialog.value.type !== null || showRegModal.value)

// Derive admin status from permissions
const isMasterAdmin = computed(() => info.value?.ctx.permissions.includes('auth:admin'))
const isOrgAdmin = computed(() => info.value?.ctx.permissions.includes('auth:org:admin'))

function sanitizeRenameId() { if (renameIdValue.value) renameIdValue.value = renameIdValue.value.replace(safeIdRegex, '') }

function handleGlobalClick(e) {
  if (!addingOrgForPermission.value) return
  const menu = e.target.closest('.org-add-menu')
  const trigger = e.target.closest('.add-org-btn')
  if (!menu && !trigger) {
    addingOrgForPermission.value = null
  }
}

onMounted(async () => {
  document.addEventListener('click', handleGlobalClick)
  window.addEventListener('hashchange', parseHash)
  await authStore.loadSettings()
  if (authStore.settings?.rp_name) document.title = authStore.settings.rp_name + ' Admin'
  await load()
})

onUnmounted(() => {
  document.removeEventListener('click', handleGlobalClick)
  window.removeEventListener('hashchange', parseHash)
})

// Build a summary: for each permission id -> { orgs: Set(org_display_name), userCount }
const permissionSummary = computed(() => {
  const summary = {}
  for (const o of orgs.value) {
    const orgBase = { uuid: o.uuid, display_name: o.org.display_name }
    // o.permissions is a dict[UUID, Permission]
    const orgPermUuids = new Set(Object.keys(o.permissions || {}))

    // Org-level permissions (direct) - only count if org can grant them
    for (const pid of Object.keys(o.permissions || {})) {
      if (!summary[pid]) summary[pid] = { orgs: [], orgSet: new Set(), userCount: 0 }
      if (!summary[pid].orgSet.has(o.uuid)) {
        summary[pid].orgs.push(orgBase)
        summary[pid].orgSet.add(o.uuid)
      }
    }

    // Role-based permissions (inheritance) - only count if org can grant them
    for (const [roleUuid, r] of Object.entries(o.roles || {})) {
      // r.permissions is dict[UUID, bool]
      for (const pid of Object.keys(r.permissions || {})) {
        // Only count if the org can grant this permission
        if (!orgPermUuids.has(pid)) continue

        if (!summary[pid]) summary[pid] = { orgs: [], orgSet: new Set(), userCount: 0 }
        if (!summary[pid].orgSet.has(o.uuid)) {
          summary[pid].orgs.push(orgBase)
          summary[pid].orgSet.add(o.uuid)
        }
        summary[pid].userCount += roleUserCount(o, roleUuid)
      }
    }
  }
  const display = {}
  for (const [pid, v] of Object.entries(summary)) {
    display[pid] = { orgs: v.orgs.sort((a,b)=>a.display_name.localeCompare(b.display_name)), userCount: v.userCount }
  }
  return display
})

function renamePermissionDisplay(p) { openDialog('perm-display', { permission: p, scope: p.scope, display_name: p.display_name, domain: p.domain || '' }) }


function parseHash() {
  const h = window.location.hash || ''
  currentOrgId.value = null
  currentUserId.value = null
  currentOidcId.value = null
  editingOidcClient.value = null
  if (h.startsWith('#org/')) {
    currentOrgId.value = h.slice(5)
  } else if (h.startsWith('#user/')) {
    currentUserId.value = h.slice(6)
  } else if (h.startsWith('#oidc:')) {
    const oidcUuid = h.slice(6)
    currentOidcId.value = oidcUuid
    // Initialize editing client data
    if (oidcUuid === 'new') {
      // Generate client_id and secret for new client
      const bytes = new Uint8Array(32)
      crypto.getRandomValues(bytes)
      const client_secret = btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
      editingOidcClient.value = {
        client_id: uuidv7(),
        client_secret,
        isNew: true,
        name: '',
        redirect_uris: []
      }
    } else {
      const client = oidcClients.value.find(c => c.uuid === oidcUuid)
      if (client) {
        editingOidcClient.value = {
          ...client,
          client_id: client.uuid,
          client_secret: null,
          isNew: false
        }
      }
    }
  }
}

async function loadAdminData() {
  const data = await apiJson('/auth/api/admin/info')
  // Convert dicts to arrays with uuid added
  orgs.value = Object.entries(data.orgs).map(([uuid, o]) => ({ uuid, ...o }))
  permissions.value = Object.entries(data.permissions).map(([uuid, p]) => ({ uuid, ...p }))
  oidcClients.value = Object.entries(data.oidc_clients).map(([uuid, c]) => ({ uuid, ...c }))
}

// Helper to get users for a role as sorted array of [uuid, user]
function roleUsers(org, roleUuid) {
  return Object.entries(org.users)
    .filter(([_, u]) => u.role === roleUuid)
    .sort(([, a], [, b]) => {
      const nameA = a.display_name.toLowerCase()
      const nameB = b.display_name.toLowerCase()
      return nameA.localeCompare(nameB)
    })
}

// Helper to count users in a role
function roleUserCount(org, roleUuid) {
  return Object.values(org.users).filter(u => u.role === roleUuid).length
}

// Helper to count total users in an org
function orgUserCount(org) {
  return Object.keys(org.users).length
}

async function loadUserInfo() {
  const data = await apiJson('/auth/api/validate', { method: 'POST' })
  info.value = data
  authenticated.value = true
}

function clearSensitiveState() {
  info.value = null
  orgs.value = []
  permissions.value = []
  oidcClients.value = []
  userDetail.value = null
  editingOidcClient.value = null
  authenticated.value = false
}

function onSessionLost(e) {
  clearSensitiveState()
  if (e.name === 'AuthCancelledError') {
    showBackMessage.value = true
  } else {
    error.value = e.message
  }
}

const userUuidGetter = () => info.value?.ctx.user.uuid
const sessionValidator = new SessionValidator(userUuidGetter, onSessionLost)

onMounted(() => sessionValidator.start())
onUnmounted(() => sessionValidator.stop())

async function load() {
  loading.value = true
  loadingMessage.value = 'Loading...'
  error.value = null
  try {
    // Load admin data first - apiJson will handle 401/403 with iframe authentication
    await loadAdminData()
    // If we get here, user has admin access - now fetch user info for display
    await loadUserInfo()

    if (!isMasterAdmin.value && isOrgAdmin.value && orgs.value.length === 1) {
      if (!window.location.hash || window.location.hash === '#overview') {
        currentOrgId.value = orgs.value[0].uuid
        window.location.hash = `#org/${currentOrgId.value}`
      } else {
        parseHash()
      }
    } else parseHash()
  } catch (e) {
    onSessionLost(e)
  } finally {
    loading.value = false
  }
}

// Org actions
function createOrg() { openDialog('org-create', {}) }

function updateOrg(org) { openDialog('org-update', { org, name: org.display_name }) }

function editUserName(user) { openDialog('user-update-name', { user, name: user.display_name }) }

async function performOrgDeletion(orgUuid) {
  await apiJson(`/auth/api/admin/orgs/${orgUuid}`, { method: 'DELETE' })
  await Promise.all([loadAdminData()])
}

function deleteOrg(org) {
  const userCount = orgUserCount(org)

  if (userCount === 0) {
    // No users in the organization, safe to delete directly
    performOrgDeletion(org.uuid)
      .then(() => {
        authStore.showMessage(`Organization "${org.org.display_name}" deleted.`, 'success', 2500)
      })
      .catch(e => {
        authStore.showMessage(e.message || 'Failed to delete organization', 'error')
      })
    return
  }

  // Build detailed breakdown of users by role
  const roleParts = Object.entries(org.roles)
    .map(([uuid, r]) => ({ role: r, count: roleUserCount(org, uuid) }))
    .filter(x => x.count > 0)
    .map(x => `${x.count} ${x.role.display_name}`)

  const affects = roleParts.join(', ')

  openDialog('confirm', { message: `Delete organization "${org.org.display_name}", including accounts of ${affects})?`, action: async () => {
    await performOrgDeletion(org.uuid)
  } })
}

function createUserInRole(org, role) { openDialog('user-create', { org, role }) }

function deleteUser(user, userDetail) {
  const credentialCount = userDetail?.credentials ? Object.keys(userDetail.credentials).length : 0
  const userUuid = user.uuid
  const userName = user.display_name
  const orgUuid = user.org  // org UUID is stored in selectedUser

  if (credentialCount === 0) {
    // No credentials, safe to delete directly
    performUserDeletion(userUuid, userName, orgUuid)
    return
  }

  const passkeys = credentialCount === 1 ? '1 passkey' : `${credentialCount} passkeys`
  openDialog('confirm', {
    message: `Delete user "${userName}" with ${passkeys}? This action cannot be undone.`,
    action: async () => {
      await performUserDeletion(userUuid, userName, orgUuid)
    }
  })
}

async function performUserDeletion(userUuid, userName, orgUuid) {
  try {
    await apiJson(`/auth/api/admin/users/${userUuid}`, { method: 'DELETE' })
    authStore.showMessage(`User "${userName}" deleted.`, 'success', 2500)
    await loadAdminData()
    window.location.hash = `#org/${orgUuid}`
  } catch (e) {
    authStore.showMessage(e.message || 'Failed to delete user', 'error')
  }
}

async function moveUserToRole(userUuid, user, targetRoleUuid) {
  if (user.role === targetRoleUuid) return
  try {
    await apiJson(`/auth/api/admin/users/${userUuid}/role`, {
      method: 'PATCH',
      body: { role_uuid: targetRoleUuid }
    })
    await loadAdminData()
  } catch (e) {
    authStore.showMessage(e.message || 'Failed to update user role')
  }
}

function onUserDragStart(e, userUuid, org) {
  e.dataTransfer.effectAllowed = 'move'
  e.dataTransfer.setData('text/plain', JSON.stringify({ user_uuid: userUuid, org }))
}

function onRoleDragOver(e) {
  e.preventDefault()
  e.dataTransfer.dropEffect = 'move'
}

function onRoleDrop(e, org, role) {
  e.preventDefault()
  try {
    const data = JSON.parse(e.dataTransfer.getData('text/plain'))
    if (data.org !== org.uuid) return // only within same org
    const user = org.users[data.user_uuid]
    if (user) moveUserToRole(data.user_uuid, user, role.uuid)
  } catch (_) { /* ignore */ }
}

// Role actions
function createRole(org) { openDialog('role-create', { org }) }

function updateRole(role) { openDialog('role-update', { role, name: role.display_name }) }

function deleteRole(role) {
  // UI only allows deleting empty roles, so no confirmation needed
  apiJson(`/auth/api/admin/roles/${role.uuid}`, { method: 'DELETE' })
    .then(() => {
      authStore.showMessage(`Role "${role.display_name}" deleted.`, 'success', 2500)
      loadAdminData()
    })
    .catch(e => {
      authStore.showMessage(e.message || 'Failed to delete role', 'error')
    })
}

async function toggleRolePermission(role, pid, checked) {
  // Optimistic update - role.permissions is dict[UUID, bool]
  const prevPermissions = { ...role.permissions }
  const newPermissions = { ...role.permissions }
  if (checked) {
    newPermissions[pid] = true
  } else {
    delete newPermissions[pid]
  }
  role.permissions = newPermissions

  try {
    const method = checked ? 'POST' : 'DELETE'
    await apiJson(`/auth/api/admin/roles/${role.uuid}/permissions/${pid}`, {
      method
    })
    await loadAdminData()
  } catch (e) {
    authStore.showMessage(e.message || 'Failed to update role permission')
    role.permissions = prevPermissions // revert
  }
}

// Permission actions
async function performPermissionDeletion(permissionUuid) {
  const params = new URLSearchParams({ permission_uuid: permissionUuid })
  await apiJson(`/auth/api/admin/permission?${params.toString()}`, { method: 'DELETE' })
  await loadAdminData()
}

function deletePermission(p) {
  const userCount = permissionSummary.value[p.uuid]?.userCount || 0

  // Count roles that have this permission
  let roleCount = 0
  for (const org of orgs.value) {
    for (const role of Object.values(org.roles)) {
      if (p.uuid in (role.permissions || {})) {
        roleCount++
      }
    }
  }

  if (roleCount === 0) {
    // No roles have this permission, safe to delete directly
    performPermissionDeletion(p.uuid)
      .then(() => {
        authStore.showMessage(`Permission "${p.display_name}" deleted.`, 'success', 2500)
      })
      .catch(e => {
        authStore.showMessage(e.message || 'Failed to delete permission', 'error')
      })
    return
  }

  const parts = []
  if (roleCount > 0) parts.push(`${roleCount} role${roleCount !== 1 ? 's' : ''}`)
  if (userCount > 0) parts.push(`${userCount} user${userCount !== 1 ? 's' : ''}`)
  const affects = parts.join(', ')

  openDialog('confirm', { message: `Delete permission "${p.display_name}" (${affects})?`, action: async () => {
    await performPermissionDeletion(p.uuid)
  } })
}

// OIDC Client actions
async function sha256Hex(text) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('')
}

function createOidcClient() {
  // Navigate to new OIDC client page
  window.location.hash = '#oidc:new'
}

function openOidcClient(client) {
  // Navigate to OIDC client detail page
  window.location.hash = `#oidc:${client.uuid}`
}

function resetOidcSecret(clientId) {
  // Generate new secret locally; it will be sent to server on Save
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  const client_secret = btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  // Update editingOidcClient if we're on the detail page
  if (editingOidcClient.value?.client_id === clientId) {
    editingOidcClient.value = { ...editingOidcClient.value, client_secret }
  }
  // Also update dialog if open (for backwards compatibility)
  if (dialog.value.type === 'oidc-edit' && dialog.value.data?.client_id === clientId) {
    dialog.value.data.client_secret = client_secret
  }
}

function createPermissionForClient(clientId) {
  openDialog('perm-create', { display_name: '', scope: '', domain: clientId })
}

function deleteOidcClient(client) {
  openDialog('confirm', {
    message: `Delete OIDC client "${client.name}"? This will break any applications using this client.`,
    action: async () => {
      await performOidcClientDeletion(client.uuid, client.name)
      // Navigate back to overview if we were on the detail page
      if (currentOidcId.value === client.uuid) {
        window.location.hash = '#overview'
      }
    }
  })
}

async function performOidcClientDeletion(clientUuid, clientName) {
  await apiJson(`/auth/api/admin/oidc-clients/${clientUuid}`, { method: 'DELETE' })
  authStore.showMessage(`OIDC client "${clientName}" deleted.`, 'success', 2500)
  await loadAdminData()
}

async function handleOidcSave(data) {
  const { client_id, client_secret, name, redirect_uris, isNew } = data

  try {
    if (client_secret) {
      const secret_hash = await sha256Hex(client_secret)
      if (isNew) {
        await apiJson('/auth/api/admin/oidc-clients', { method: 'POST', body: { client_id, secret_hash, name, redirect_uris } })
      } else {
        await apiJson(`/auth/api/admin/oidc-clients/${client_id}`, { method: 'PATCH', body: { name, redirect_uris, secret_hash } })
      }
    } else {
      await apiJson(`/auth/api/admin/oidc-clients/${client_id}`, { method: 'PATCH', body: { name, redirect_uris } })
    }
    authStore.showMessage(`OIDC client "${name}" ${isNew ? 'created' : 'updated'}.`, 'success', 2500)
    await loadAdminData()
    window.location.hash = '#overview'
  } catch (e) {
    authStore.showMessage(e.message || `Failed to ${isNew ? 'create' : 'update'} OIDC client`, 'error')
  }
}

function handleOidcCancel() {
  goOverview()
}

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
    const u = o.users[currentUserId.value]
    if (u) {
      const role = o.roles[u.role]
      return { ...u, uuid: currentUserId.value, org: o.uuid, role_display_name: role?.display_name }
    }
  }
  return null
})

// Breadcrumb entries for admin app.
const breadcrumbEntries = computed(() => {
  const entries = [
    { label: 'My Profile', href: makeUiHref() }
  ]
  // For org admins, combine Admin and their org
  if (isOrgAdmin.value && !isMasterAdmin.value && orgs.value.length > 0) {
    const org = orgs.value[0]
    entries.push({ label: `Admin: ${org.org.display_name}`, href: `#org/${org.uuid}` })
  } else {
    entries.push({ label: 'Admin', href: adminUiPath() })
  }
  // Determine organization for user view if selectedOrg not explicitly chosen.
  let orgForUser = null
  if (selectedUser.value) {
    orgForUser = orgs.value.find(o => o.uuid === selectedUser.value.org) || null
  }
  const orgToShow = selectedOrg.value || orgForUser
  // Add org breadcrumb only if it's not already included in the Admin entry
  const adminOrg = (isOrgAdmin.value && !isMasterAdmin.value && orgs.value.length > 0) ? orgs.value[0] : null
  if (orgToShow && (!adminOrg || orgToShow.uuid !== adminOrg.uuid)) {
    entries.push({ label: orgToShow.org.display_name, href: `#org/${orgToShow.uuid}` })
  }
  if (currentOidcId.value) {
    const label = editingOidcClient.value?.isNew ? 'New Client' : (editingOidcClient.value?.name || 'OIDC Client')
    entries.push({ label, href: `#oidc:${currentOidcId.value}` })
  }
  if (selectedUser.value) {
    entries.push({ label: selectedUser.value.display_name, href: `#user/${selectedUser.value.uuid}` })
  }
  return entries
})

watch(selectedUser, async (u) => {
  if (!u) { userDetail.value = null; return }
  try {
    userDetail.value = await apiJson(`/auth/api/admin/users/${u.uuid}`)
  } catch (e) {
    userDetail.value = { error: e.message }
  }
})

const showRegModal = ref(false)
function generateUserRegistrationLink(u) {
  showRegModal.value = true
}

async function toggleOrgPermission(org, permId, checked) {
  // org.permissions is dict[UUID, Permission]
  const has = permId in org.permissions
  if (checked && has) return
  if (!checked && !has) return
  // Optimistic update
  const prev = { ...org.permissions }
  if (checked) {
    // Need to fetch the permission object to add it
    const perm = permissions.value.find(p => p.uuid === permId)
    if (perm) {
      org.permissions = { ...org.permissions, [permId]: perm }
    }
  } else {
    const next = { ...org.permissions }
    delete next[permId]
    org.permissions = next
  }
  try {
    const params = new URLSearchParams({ permission_uuid: permId })
    await apiJson(`/auth/api/admin/orgs/${org.uuid}/permission?${params.toString()}`, { method: checked ? 'POST' : 'DELETE' })
    await loadAdminData()
  } catch (e) {
    authStore.showMessage(e.message || 'Failed to update organization permission', 'error')
    org.permissions = prev // revert
  }
}

function openDialog(type, data) {
  const focused = document.activeElement
  dialogPreviousFocus.value = focused

  // For delete operations, store sibling info to help restore focus after deletion
  if (type === 'confirm' && focused) {
    const row = focused.closest('tr')
    if (row) {
      const tbody = row.closest('tbody')
      if (tbody) {
        const rows = Array.from(tbody.querySelectorAll('tr'))
        const idx = rows.indexOf(row)
        // Store context to find next/prev row after deletion
        dialog.value.focusContext = {
          tbody,
          index: idx,
          total: rows.length,
          selector: 'button:not([disabled]), a'
        }
      }
    }
  }

  dialog.value = { ...dialog.value, type, data, busy: false, error: '' }
}

function closeDialog() {
  const prev = dialogPreviousFocus.value
  const context = dialog.value.focusContext
  dialog.value = { type: null, data: null, busy: false, error: '' }
  // Restore focus after dialog closes
  restoreFocusAfterDialog(prev, context)
  dialogPreviousFocus.value = null
}

/**
 * Restore focus to the previously focused element, or find a sibling if deleted.
 */
function restoreFocusAfterDialog(prev, context) {
  if (!prev) return

  // Check if the original element still exists in DOM and is focusable
  if (document.body.contains(prev) && !prev.disabled) {
    prev.focus()
    return
  }

  // Element was deleted - try to find a sibling using stored context
  if (context?.tbody && context.selector) {
    const rows = Array.from(context.tbody.querySelectorAll('tr'))
    if (rows.length > 0) {
      // Try the same index (next row moved up) or the last row
      const targetIdx = Math.min(context.index, rows.length - 1)
      const targetRow = rows[targetIdx]
      const focusable = targetRow?.querySelector(context.selector)
      if (focusable) {
        focusable.focus()
        return
      }
    }
  }

  // Fallback: try to find any focusable element in the admin panels
  const container = document.querySelector('.admin-panels')
  if (!container) return

  const focusable = container.querySelector('button:not([disabled]), a, input:not([disabled]), [tabindex="0"]')
  if (focusable) {
    focusable.focus()
  }
}

// Keyboard navigation handlers
function handleBreadcrumbKeydown(event) {
  if (hasActiveModal.value) return

  const direction = getDirection(event)
  if (!direction) return

  // Left/right handled internally by Breadcrumbs component
  if (direction === 'down') {
    event.preventDefault()
    // Move to admin panel content
    if (adminOverviewRef.value) {
      adminOverviewRef.value.focusFirstElement?.()
    } else if (adminOrgDetailRef.value) {
      adminOrgDetailRef.value.focusFirstElement?.()
    } else if (adminUserDetailRef.value) {
      adminUserDetailRef.value.focusFirstElement?.()
    }
  }
}

function handlePanelNavigateOut(direction) {
  if (hasActiveModal.value) return

  if (direction === 'up') {
    // Focus breadcrumbs - focus the current page's crumb
    breadcrumbsRef.value?.focusCurrent?.()
  }
}

async function refreshUserDetail() {
  await loadAdminData()
  if (selectedUser.value) {
    try {
      userDetail.value = await apiJson(`/auth/api/admin/users/${selectedUser.value.uuid}`)
    } catch (e) { authStore.showMessage(e.message || 'Failed to reload user', 'error') }
  }
}

async function onUserNameSaved() {
  await refreshUserDetail()
  authStore.showMessage('User renamed', 'success', 1500)
}

async function submitDialog() {
  if (!dialog.value.type || dialog.value.busy) return
  dialog.value.busy = true; dialog.value.error = ''
  try {
    const t = dialog.value.type
    if (t === 'org-create') {
      const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')

      // Close dialog immediately, then perform async operation
      closeDialog()
      apiJson('/auth/api/admin/orgs', { method: 'POST', body: { display_name: name, permissions: [] } })
        .then(() => {
          authStore.showMessage(`Organization "${name}" created.`, 'success', 2500)
          loadAdminData()
        })
        .catch(e => {
          authStore.showMessage(e.message || 'Failed to create organization', 'error')
        })
      return // Don't call closeDialog() again
    } else if (t === 'org-update') {
      const { org } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')

      // Close dialog immediately, then perform async operation
      closeDialog()
      apiJson(`/auth/api/admin/orgs/${org.uuid}`, { method: 'PATCH', body: { display_name: name } })
        .then(() => {
          authStore.showMessage(`Organization renamed to "${name}".`, 'success', 2500)
          loadAdminData()
        })
        .catch(e => {
          authStore.showMessage(e.message || 'Failed to update organization', 'error')
        })
      return // Don't call closeDialog() again
    } else if (t === 'role-create') {
      const { org } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')

      // Close dialog immediately, then perform async operation
      closeDialog()
      apiJson(`/auth/api/admin/orgs/${org.uuid}/roles`, { method: 'POST', body: { display_name: name, permissions: [] } })
        .then(() => {
          authStore.showMessage(`Role "${name}" created.`, 'success', 2500)
          loadAdminData()
        })
        .catch(e => {
          authStore.showMessage(e.message || 'Failed to create role', 'error')
        })
      return // Don't call closeDialog() again
    } else if (t === 'role-update') {
      const { role } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')

      // Close dialog immediately, then perform async operation
      closeDialog()
      apiJson(`/auth/api/admin/roles/${role.uuid}`, { method: 'PATCH', body: { display_name: name } })
        .then(() => {
          authStore.showMessage(`Role renamed to "${name}".`, 'success', 2500)
          loadOrgs()
        })
        .catch(e => {
          authStore.showMessage(e.message || 'Failed to update role', 'error')
        })
      return // Don't call closeDialog() again
    } else if (t === 'user-create') {
      const { org, role } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')

      // Close dialog immediately, then perform async operation
      closeDialog()
      apiJson(`/auth/api/admin/orgs/${org.uuid}/users`, { method: 'POST', body: { display_name: name, role: role.display_name } })
        .then(() => {
          authStore.showMessage(`User "${name}" added to ${role.display_name} role.`, 'success', 2500)
          loadAdminData()
        })
        .catch(e => {
          authStore.showMessage(e.message || 'Failed to add user', 'error')
        })
      return // Don't call closeDialog() again
    } else if (t === 'user-update-name') {
      const { user } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')

      // Close dialog immediately, then perform async operation
      closeDialog()
      apiJson(`/auth/api/admin/users/${user.uuid}/info`, { method: 'PATCH', body: { display_name: name } })
        .then(() => {
          authStore.showMessage(`User renamed to "${name}".`, 'success', 2500)
          onUserNameSaved()
        })
        .catch(e => {
          authStore.showMessage(e.message || 'Failed to update user name', 'error')
        })
      return // Don't call closeDialog() again
    } else if (t === 'perm-display') {
      const { permission } = dialog.value.data
      const newScope = dialog.value.data.scope?.trim()
      const newDisplay = dialog.value.data.display_name?.trim()
      const newDomain = dialog.value.data.domain?.trim() || ''
      if (!newDisplay) throw new Error('Display name required')
      if (!newScope) throw new Error('Scope required')

      // Close dialog immediately, then perform async operation
      closeDialog()

      const oldDomain = permission.domain || ''
      // Check if anything changed
      if (newScope === permission.scope && newDisplay === permission.display_name && newDomain === oldDomain) {
        return // No changes
      }

      // Always use PATCH with permission_uuid
      const params = new URLSearchParams({ permission_uuid: permission.uuid })
      if (newScope !== permission.scope) params.set('scope', newScope)
      if (newDisplay !== permission.display_name) params.set('display_name', newDisplay)
      if (newDomain !== oldDomain) params.set('domain', newDomain || '')

      apiJson(`/auth/api/admin/permission?${params.toString()}`, { method: 'PATCH' })
        .then(() => {
          authStore.showMessage(`Permission "${newDisplay}" updated.`, 'success', 2500)
          loadAdminData()
        })
        .catch(e => {
          authStore.showMessage(e.message || 'Failed to update permission', 'error')
        })
      return // Don't call closeDialog() again
    } else if (t === 'perm-create') {
      const scope = dialog.value.data.scope?.trim(); if (!scope) throw new Error('Scope required')
      const display_name = dialog.value.data.display_name?.trim(); if (!display_name) throw new Error('Display name required')
      const domain = dialog.value.data.domain?.trim() || ''

      // Close dialog immediately, then perform async operation
      closeDialog()
      apiJson('/auth/api/admin/permissions', { method: 'POST', body: { scope, display_name, domain: domain || undefined } })
        .then(() => {
          authStore.showMessage(`Permission "${display_name}" created.`, 'success', 2500)
          loadAdminData()
        })
        .catch(e => {
          authStore.showMessage(e.message || 'Failed to create permission', 'error')
        })
      return // Don't call closeDialog() again
    } else if (t === 'oidc-edit') {
      const { client_id, client_secret, isNew } = dialog.value.data
      const name = dialog.value.data.name?.trim()
      const uris = dialog.value.data.redirect_uris?.trim()
      if (!name) throw new Error('Client name required')

      const redirect_uris = uris ? uris.split('\n').map(u => u.trim()).filter(u => u) : []

      // Close dialog immediately, then perform async operation
      closeDialog()

      const req = client_secret
        ? sha256Hex(client_secret).then(secret_hash => isNew
            ? apiJson('/auth/api/admin/oidc-clients', { method: 'POST', body: { client_id, secret_hash, name, redirect_uris } })
            : apiJson(`/auth/api/admin/oidc-clients/${client_id}`, { method: 'PATCH', body: { name, redirect_uris, secret_hash } }))
        : apiJson(`/auth/api/admin/oidc-clients/${client_id}`, { method: 'PATCH', body: { name, redirect_uris } })
      req
        .then(() => {
          authStore.showMessage(`OIDC client "${name}" ${isNew ? 'created' : 'updated'}.`, 'success', 2500)
          loadAdminData()
        })
        .catch(e => {
          authStore.showMessage(e.message || `Failed to ${isNew ? 'create' : 'update'} OIDC client`, 'error')
        })
      return // Don't call closeDialog() again
    } else if (t === 'confirm') {
      const action = dialog.value.data.action
      // Close dialog first, then perform action (errors shown via showMessage)
      closeDialog()
      if (action) {
        try {
          await action()
        } catch (e) {
          authStore.showMessage(e.message || 'Action failed', 'error')
        }
      }
      return // Already closed
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
      <AccessDenied v-else-if="showBackMessage" />
      <AccessDenied
        v-else-if="error"
        icon="⚠️"
        title="Error"
        :message="error"
      />
      <AccessDenied
        v-else-if="authenticated && !isMasterAdmin && !isOrgAdmin"
        icon="⛔"
        message="You do not have admin permissions for this application."
      />
      <section v-else-if="authenticated && (isMasterAdmin || isOrgAdmin)" class="view-root view-root--wide view-admin">
        <header class="view-header">
          <Breadcrumbs ref="breadcrumbsRef" :entries="breadcrumbEntries" @keydown="handleBreadcrumbKeydown" />
        </header>

        <section class="section-block admin-section">
          <div class="section-body admin-section-body">
            <div class="admin-panels">
                                  <AdminOverview
                  v-if="!selectedUser && !selectedOrg && !currentOidcId && (isMasterAdmin || isOrgAdmin)"
                  ref="adminOverviewRef"
                  :info="info"
                  :orgs="orgs"
                  :permissions="permissions"
                  :oidc-clients="oidcClients"
                  :navigation-disabled="hasActiveModal"
                  :permission-summary="permissionSummary"
                  @create-org="createOrg"
                  @open-org="openOrg"
                  @update-org="updateOrg"
                  @delete-org="deleteOrg"
                  @toggle-org-permission="toggleOrgPermission"
                  @open-dialog="openDialog"
                  @delete-permission="deletePermission"
                  @rename-permission-display="renamePermissionDisplay"
                  @create-oidc-client="createOidcClient"
                  @open-oidc-client="openOidcClient"
                  @delete-oidc-client="deleteOidcClient"
                  @navigate-out="handlePanelNavigateOut"
                />

                <AdminUserDetail
                  v-else-if="selectedUser"
                  ref="adminUserDetailRef"
                  :selected-user="selectedUser"
                  :user-detail="userDetail"
                  :selected-org="selectedOrg"
                  :loading="loading"
                  :show-reg-modal="showRegModal"
                  :navigation-disabled="hasActiveModal"
                  @generate-user-registration-link="generateUserRegistrationLink"
                  @go-overview="goOverview"
                  @open-org="openOrg"
                  @on-user-name-saved="onUserNameSaved"
                  @refresh-user-detail="refreshUserDetail"
                  @edit-user-name="editUserName"
                  @close-reg-modal="showRegModal = false"
                  @navigate-out="handlePanelNavigateOut"
                  @delete-user="deleteUser(selectedUser, userDetail)"
                />
                <AdminOrgDetail
                  v-else-if="selectedOrg"
                  ref="adminOrgDetailRef"
                  :selected-org="selectedOrg"
                  :permissions="permissions"
                  :navigation-disabled="hasActiveModal"
                  @update-org="updateOrg"
                  @create-role="createRole"
                  @update-role="updateRole"
                  @delete-role="deleteRole"
                  @create-user-in-role="createUserInRole"
                  @open-user="openUser"
                  @toggle-role-permission="toggleRolePermission"
                  @on-role-drag-over="onRoleDragOver"
                  @navigate-out="handlePanelNavigateOut"
                  @on-role-drop="onRoleDrop"
                  @on-user-drag-start="onUserDragStart"
                />

                <AdminOidcDetail
                  v-else-if="currentOidcId && editingOidcClient"
                  ref="adminOidcDetailRef"
                  :client="editingOidcClient"
                  :permissions="permissions"
                  :is-new="editingOidcClient.isNew"
                  :navigation-disabled="hasActiveModal"
                  @save="handleOidcSave"
                  @cancel="handleOidcCancel"
                  @delete="deleteOidcClient"
                  @reset-secret="resetOidcSecret"
                  @create-permission="createPermissionForClient"
                  @navigate-out="handlePanelNavigateOut"
                />

              </div>
          </div>
        </section>
      </section>
    </main>
    <AdminDialogs
      :dialog="dialog"
      :permission-id-pattern="PERMISSION_ID_PATTERN"
      :settings="authStore.settings"
      @submit-dialog="submitDialog"
      @close-dialog="closeDialog"
      @reset-oidc-secret="resetOidcSecret"
      @create-permission-for-client="createPermissionForClient"
    />
  </div>
</template>

<style scoped>
.view-admin { padding-bottom: var(--space-3xl); }
.admin-section-body { display: flex; flex-direction: column; gap: var(--space-xl); }
.admin-panels { display: flex; flex-direction: column; gap: var(--space-xl); }
</style>
