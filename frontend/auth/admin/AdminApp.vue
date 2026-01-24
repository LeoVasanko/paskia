<script setup>
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import Breadcrumbs from '@/components/Breadcrumbs.vue'
import CredentialList from '@/components/CredentialList.vue'
import UserBasicInfo from '@/components/UserBasicInfo.vue'
import StatusMessage from '@/components/StatusMessage.vue'
import LoadingView from '@/components/LoadingView.vue'
import AuthRequiredMessage from '@/components/AccessDenied.vue'
import AdminOverview from '@/admin/AdminOverview.vue'
import AdminOrgDetail from '@/admin/AdminOrgDetail.vue'
import AdminUserDetail from '@/admin/AdminUserDetail.vue'
import AdminDialogs from '@/admin/AdminDialogs.vue'
import { useAuthStore } from '@/stores/auth'
import { adminUiPath, makeUiHref } from '@/utils/settings'
import { apiJson } from '@/utils/api'
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
const currentOrgId = ref(null) // UUID of selected org for detail view
const currentUserId = ref(null) // UUID for user detail view
const userDetail = ref(null) // cached user detail object
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

// Check if any modal/dialog is open (blocks arrow key navigation)
const hasActiveModal = computed(() => dialog.value.type !== null || showRegModal.value)

// Derive admin status from permissions
const isGlobalAdmin = computed(() => info.value?.permissions?.includes('auth:admin') ?? false)
const isOrgAdmin = computed(() => info.value?.permissions?.includes('auth:org:admin') ?? false)

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

function renamePermissionDisplay(p) { openDialog('perm-display', { permission: p, scope: p.scope, display_name: p.display_name, domain: p.domain || '' }) }


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
  const data = await apiJson('/auth/api/admin/orgs')
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
  permissions.value = await apiJson('/auth/api/admin/permissions')
}

async function loadUserInfo() {
  info.value = await apiJson('/auth/api/user-info', { method: 'POST' })
  authenticated.value = true
}

async function load() {
  loading.value = true
  loadingMessage.value = 'Loading...'
  error.value = null
  try {
    // Load admin data first - apiJson will handle 401/403 with iframe authentication
    await Promise.all([loadOrgs(), loadPermissions()])
    // If we get here, user has admin access - now fetch user info for display
    await loadUserInfo()

    if (!isGlobalAdmin.value && isOrgAdmin.value && orgs.value.length === 1) {
      if (!window.location.hash || window.location.hash === '#overview') {
        currentOrgId.value = orgs.value[0].uuid
        window.location.hash = `#org/${currentOrgId.value}`
        authStore.showMessage(`Navigating to ${orgs.value[0].display_name} Administration`, 'info', 3000)
      } else {
        parseHash()
      }
    } else parseHash()
  } catch (e) {
    if (e.name === 'AuthCancelledError') {
      showBackMessage.value = true
    } else {
      error.value = e.message
    }
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
  await Promise.all([loadOrgs(), loadPermissions()])
}

function deleteOrg(org) {
  if (!isGlobalAdmin.value) { authStore.showMessage('Global admin only'); return }

  const userCount = org.roles.reduce((acc, r) => acc + r.users.length, 0)

  if (userCount === 0) {
    // No users in the organization, safe to delete directly
    performOrgDeletion(org.uuid)
      .then(() => {
        authStore.showMessage(`Organization "${org.display_name}" deleted.`, 'success', 2500)
      })
      .catch(e => {
        authStore.showMessage(e.message || 'Failed to delete organization', 'error')
      })
    return
  }

  // Build detailed breakdown of users by role
  const roleParts = org.roles
    .filter(r => r.users.length > 0)
    .map(r => `${r.users.length} ${r.display_name}`)

  const affects = roleParts.join(', ')

  openDialog('confirm', { message: `Delete organization "${org.display_name}", including accounts of ${affects})?`, action: async () => {
    await performOrgDeletion(org.uuid)
  } })
}

function createUserInRole(org, role) { openDialog('user-create', { org, role }) }

async function moveUserToRole(org, user, targetRoleDisplayName) {
  if (user.role === targetRoleDisplayName) return
  try {
    await apiJson(`/auth/api/admin/orgs/${org.uuid}/users/${user.uuid}/role`, {
      method: 'PATCH',
      body: { role: targetRoleDisplayName }
    })
    await loadOrgs()
  } catch (e) {
    authStore.showMessage(e.message || 'Failed to update user role')
  }
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

// Role actions
function createRole(org) { openDialog('role-create', { org }) }

function updateRole(role) { openDialog('role-update', { role, name: role.display_name }) }

function deleteRole(role) {
  // UI only allows deleting empty roles, so no confirmation needed
  apiJson(`/auth/api/admin/orgs/${role.org_uuid}/roles/${role.uuid}`, { method: 'DELETE' })
    .then(() => {
      authStore.showMessage(`Role "${role.display_name}" deleted.`, 'success', 2500)
      loadOrgs()
    })
    .catch(e => {
      authStore.showMessage(e.message || 'Failed to delete role', 'error')
    })
}

async function toggleRolePermission(role, pid, checked) {
  // Optimistic update
  const prevPermissions = [...role.permissions]
  const newPermissions = checked
    ? [...role.permissions, pid]
    : role.permissions.filter(p => p !== pid)
  role.permissions = newPermissions

  try {
    const method = checked ? 'POST' : 'DELETE'
    await apiJson(`/auth/api/admin/orgs/${role.org_uuid}/roles/${role.uuid}/permissions/${pid}`, {
      method
    })
    await loadOrgs()
  } catch (e) {
    authStore.showMessage(e.message || 'Failed to update role permission')
    role.permissions = prevPermissions // revert
  }
}

// Permission actions
async function performPermissionDeletion(permissionScope) {
  const params = new URLSearchParams({ permission_id: permissionScope })
  await apiJson(`/auth/api/admin/permission?${params.toString()}`, { method: 'DELETE' })
  await loadPermissions()
}

function deletePermission(p) {
  const userCount = permissionSummary.value[p.uuid]?.userCount || 0

  // Count roles that have this permission
  let roleCount = 0
  for (const org of orgs.value) {
    for (const role of org.roles) {
      if (role.permissions.includes(p.uuid)) {
        roleCount++
      }
    }
  }

  if (roleCount === 0) {
    // No roles have this permission, safe to delete directly
    performPermissionDeletion(p.scope)
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
    await performPermissionDeletion(p.scope)
  } })
}

function reloadPage() {
  window.location.reload()
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
    userDetail.value = await apiJson(`/auth/api/admin/orgs/${u.org_uuid}/users/${u.uuid}`)
  } catch (e) {
    userDetail.value = { error: e.message }
  }
})

const showRegModal = ref(false)
function generateUserRegistrationLink(u) {
  showRegModal.value = true
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
    await apiJson(`/auth/api/admin/orgs/${org.uuid}/permission?${params.toString()}`, { method: checked ? 'POST' : 'DELETE' })
    await loadOrgs()
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
  await loadOrgs()
  if (selectedUser.value) {
    try {
      userDetail.value = await apiJson(`/auth/api/admin/orgs/${selectedUser.value.org_uuid}/users/${selectedUser.value.uuid}`)
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
          Promise.all([loadOrgs(), loadPermissions()])
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
          loadOrgs()
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
          loadOrgs()
        })
        .catch(e => {
          authStore.showMessage(e.message || 'Failed to create role', 'error')
        })
      return // Don't call closeDialog() again
    } else if (t === 'role-update') {
      const { role } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')

      // Close dialog immediately, then perform async operation
      closeDialog()
      apiJson(`/auth/api/admin/orgs/${role.org_uuid}/roles/${role.uuid}`, { method: 'PATCH', body: { display_name: name } })
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
          loadOrgs()
        })
        .catch(e => {
          authStore.showMessage(e.message || 'Failed to add user', 'error')
        })
      return // Don't call closeDialog() again
    } else if (t === 'user-update-name') {
      const { user } = dialog.value.data; const name = dialog.value.data.name?.trim(); if (!name) throw new Error('Name required')

      // Close dialog immediately, then perform async operation
      closeDialog()
      apiJson(`/auth/api/admin/orgs/${user.org_uuid}/users/${user.uuid}/display-name`, { method: 'PATCH', body: { display_name: name } })
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
      const newId = dialog.value.data.scope?.trim()
      const newDisplay = dialog.value.data.display_name?.trim()
      const newDomain = dialog.value.data.domain?.trim() || ''
      if (!newDisplay) throw new Error('Display name required')
      if (!newId) throw new Error('Scope required')

      // Close dialog immediately, then perform async operation
      closeDialog()

      const oldDomain = permission.domain || ''
      let apiCall;
      if (newId !== permission.scope) {
        // Scope changed, use rename endpoint (also update domain)
        apiCall = apiJson('/auth/api/admin/permission/rename', { method: 'POST', body: { old_scope: permission.scope, new_scope: newId, display_name: newDisplay, domain: newDomain } })
      } else if (newDisplay !== permission.display_name || newDomain !== oldDomain) {
        // Display name or domain changed
        const params = new URLSearchParams({ permission_id: permission.scope, display_name: newDisplay })
        if (newDomain) params.set('domain', newDomain)
        apiCall = apiJson(`/auth/api/admin/permission?${params.toString()}`, { method: 'PATCH' })
      } else {
        // No changes
        return
      }

      apiCall
        .then(() => {
          authStore.showMessage(`Permission "${newDisplay}" updated.`, 'success', 2500)
          loadPermissions()
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
          loadPermissions()
        })
        .catch(e => {
          authStore.showMessage(e.message || 'Failed to create permission', 'error')
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
      <AuthRequiredMessage
        v-else-if="showBackMessage"
        @reload="reloadPage"
      />
      <!-- Access denied: authenticated but not admin, or error occurred -->
      <div v-else-if="error || (authenticated && !isGlobalAdmin && !isOrgAdmin)" class="access-denied-container">
        <div class="access-denied-content">
          <h2>⛔ Access Denied</h2>
          <p v-if="error" class="error-detail">{{ error }}</p>
          <p v-else class="error-detail">You do not have admin permissions for this application.</p>
          <div class="button-row">
            <button class="btn-secondary" @click="goBack">Back</button>
            <button class="btn-primary" @click="reloadPage">Reload Page</button>
          </div>
        </div>
      </div>
      <section v-else-if="authenticated && (isGlobalAdmin || isOrgAdmin)" class="view-root view-root--wide view-admin">
        <header class="view-header">
          <h1>{{ pageHeading }}</h1>
          <Breadcrumbs ref="breadcrumbsRef" :entries="breadcrumbEntries" @keydown="handleBreadcrumbKeydown" />
        </header>

        <section class="section-block admin-section">
          <div class="section-body admin-section-body">
            <div class="admin-panels">
                                  <AdminOverview
                  v-if="!selectedUser && !selectedOrg && (isGlobalAdmin || isOrgAdmin)"
                  ref="adminOverviewRef"
                  :info="info"
                  :orgs="orgs"
                  :permissions="permissions"
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
    />
  </div>
</template>

<style scoped>
.view-admin { padding-bottom: var(--space-3xl); }
.view-header { display: flex; flex-direction: column; gap: var(--space-sm); }
.admin-section { margin-top: var(--space-xl); }
.admin-section-body { display: flex; flex-direction: column; gap: var(--space-xl); }
.admin-panels { display: flex; flex-direction: column; gap: var(--space-xl); }
.access-denied-container { display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 60vh; padding: 2rem; }
.access-denied-content { text-align: center; max-width: 480px; }
.access-denied-content h2 { margin: 0 0 1rem; color: var(--color-heading); font-size: 1.5rem; }
.access-denied-content .error-detail { margin: 0 0 1.5rem; color: var(--color-text-muted); }
.access-denied-content .button-row { display: flex; gap: 0.75rem; justify-content: center; }
</style>
