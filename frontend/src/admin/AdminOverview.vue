<script setup>
import { computed, ref } from 'vue'
import { getDirection, navigateButtonRow, focusPreferred, focusAtIndex } from '@/utils/keynav'

const props = defineProps({
  info: Object,
  orgs: Array,
  permissions: Array,
  permissionSummary: Object,
  navigationDisabled: { type: Boolean, default: false }
})

const emit = defineEmits(['createOrg', 'openOrg', 'updateOrg', 'deleteOrg', 'toggleOrgPermission', 'openDialog', 'deletePermission', 'renamePermissionDisplay', 'navigateOut'])

// Template refs for navigation
const orgSection = ref(null)
const orgActionsRef = ref(null)
const orgTableRef = ref(null)
const permMatrixRef = ref(null)
const permActionsRef = ref(null)
const permTableRef = ref(null)

const sortedOrgs = computed(() => [...props.orgs].sort((a,b)=> {
  const nameCompare = a.org.display_name.localeCompare(b.org.display_name)
  return nameCompare !== 0 ? nameCompare : a.uuid.localeCompare(b.uuid)
}))
const sortedPermissions = computed(() => [...props.permissions].sort((a,b)=> a.scope.localeCompare(b.scope)))

// Derive admin status from permissions (info contains ctx from validate response)
const isMasterAdmin = computed(() => props.info?.ctx.permissions.includes('auth:admin'))
const isOrgAdmin = computed(() => props.info?.ctx.permissions.includes('auth:org:admin'))

function permissionDisplayName(scope) {
  return props.permissions.find(p => p.scope === scope)?.display_name || scope
}

function getRoleNames(org) {
  return Object.values(org.roles)
    .slice()
    .sort((a, b) => a.display_name.localeCompare(b.display_name))
    .map(r => r.display_name)
    .join(', ')
}

function orgUserCount(org) {
  return Object.keys(org.users).length
}

// Table navigation for both org and permissions tables
function handleTableKeydown(event, tableType) {
  if (props.navigationDisabled) return

  const direction = getDirection(event)
  if (!direction) return

  const target = event.target
  const row = target.closest('tr')
  if (!row) return

  const tbody = row.closest('tbody')
  if (!tbody) return

  const rows = Array.from(tbody.querySelectorAll('tr'))
  const currentIndex = rows.indexOf(row)
  if (currentIndex === -1) return

  // Handle left/right navigation within the row
  if (direction === 'left' || direction === 'right') {
    event.preventDefault()
    const focusables = Array.from(row.querySelectorAll('a, button:not([disabled])'))
    const currentFocusIndex = focusables.indexOf(target)
    if (currentFocusIndex === -1) return

    if (direction === 'left' && currentFocusIndex > 0) {
      focusables[currentFocusIndex - 1].focus()
    } else if (direction === 'right' && currentFocusIndex < focusables.length - 1) {
      focusables[currentFocusIndex + 1].focus()
    }
    return
  }

  // Handle up/down navigation between rows
  let newIndex = currentIndex
  if (direction === 'up' && currentIndex > 0) {
    newIndex = currentIndex - 1
  } else if (direction === 'down' && currentIndex < rows.length - 1) {
    newIndex = currentIndex + 1
  } else if (direction === 'up' && currentIndex === 0) {
    // At top of table, navigate to actions above
    event.preventDefault()
    if (tableType === 'org') {
      focusPreferred(orgActionsRef.value, { itemSelector: 'button' })
    } else if (tableType === 'perm') {
      focusPreferred(permActionsRef.value, { itemSelector: 'button' })
    }
    return
  } else if (direction === 'down' && currentIndex === rows.length - 1) {
    // At bottom of org table, navigate to permissions section
    event.preventDefault()
    if (tableType === 'org' && isMasterAdmin.value) {
      // Navigate to permissions matrix or actions
      if (permMatrixRef.value) {
        const firstCheckbox = permMatrixRef.value.querySelector('input[type="checkbox"]')
        if (firstCheckbox) firstCheckbox.focus()
        else focusPreferred(permActionsRef.value, { itemSelector: 'button' })
      }
    }
    return
  }

  if (newIndex !== currentIndex) {
    event.preventDefault()
    const newRow = rows[newIndex]
    const focusable = newRow.querySelector('a, button:not([disabled])')
    if (focusable) focusable.focus()
  }
}

// Handle org actions button keynav
function handleOrgActionsKeydown(event) {
  if (props.navigationDisabled) return

  const direction = getDirection(event)
  if (!direction) return

  event.preventDefault()

  if (direction === 'left' || direction === 'right') {
    navigateButtonRow(orgActionsRef.value, event.target, direction, { itemSelector: 'button' })
  } else if (direction === 'up') {
    emit('navigateOut', 'up')
  } else if (direction === 'down') {
    // Move to org table
    const firstFocusable = orgTableRef.value?.querySelector('tbody tr a, tbody tr button:not([disabled])')
    if (firstFocusable) firstFocusable.focus()
  }
}

// Handle permission matrix grid navigation
function handleMatrixKeydown(event) {
  if (props.navigationDisabled) return

  const direction = getDirection(event)
  if (!direction) return

  const target = event.target
  if (target.tagName !== 'INPUT') return

  event.preventDefault()

  const checkboxes = Array.from(permMatrixRef.value.querySelectorAll('input[type="checkbox"]'))
  const currentIndex = checkboxes.indexOf(target)
  if (currentIndex === -1) return

  // Calculate grid dimensions
  const cols = sortedOrgs.value.length
  const rows = sortedPermissions.value.length

  if (cols === 0 || rows === 0) return

  const currentRow = Math.floor(currentIndex / cols)
  const currentCol = currentIndex % cols

  let newIndex = currentIndex
  if (direction === 'left') {
    if (currentCol > 0) {
      // Move left within the same row
      newIndex = currentIndex - 1
    }
    // At leftmost column, do nothing (no wrap)
  } else if (direction === 'right') {
    if (currentCol < cols - 1) {
      // Move right within the same row
      newIndex = currentIndex + 1
    }
    // At rightmost column, do nothing (no wrap)
  } else if (direction === 'up') {
    if (currentRow > 0) {
      // Move up within the same column
      newIndex = currentIndex - cols
    } else {
      // At top row, navigate up to org table
      const lastRow = orgTableRef.value?.querySelector('tbody tr:last-child')
      const focusable = lastRow?.querySelector('a, button:not([disabled])')
      if (focusable) focusable.focus()
      return
    }
  } else if (direction === 'down') {
    if (currentRow < rows - 1) {
      // Move down within the same column
      newIndex = currentIndex + cols
    } else {
      // At bottom row, navigate down to permission actions
      focusPreferred(permActionsRef.value, { itemSelector: 'button' })
      return
    }
  }

  if (newIndex !== currentIndex && checkboxes[newIndex]) {
    checkboxes[newIndex].focus()
  }
}

// Handle permission actions button keynav
function handlePermActionsKeydown(event) {
  if (props.navigationDisabled) return

  const direction = getDirection(event)
  if (!direction) return

  event.preventDefault()

  if (direction === 'left' || direction === 'right') {
    navigateButtonRow(permActionsRef.value, event.target, direction, { itemSelector: 'button' })
  } else if (direction === 'up') {
    // Move to first column of last row in matrix
    const checkboxes = permMatrixRef.value?.querySelectorAll('input[type="checkbox"]')
    if (checkboxes?.length) {
      const cols = sortedOrgs.value.length
      const rows = sortedPermissions.value.length
      // First checkbox of last row = (rows - 1) * cols
      const lastRowFirstIndex = (rows - 1) * cols
      if (checkboxes[lastRowFirstIndex]) {
        checkboxes[lastRowFirstIndex].focus()
      } else {
        checkboxes[0].focus()
      }
    } else {
      // No matrix, go to org table
      const lastRow = orgTableRef.value?.querySelector('tbody tr:last-child')
      const focusable = lastRow?.querySelector('a, button:not([disabled])')
      if (focusable) focusable.focus()
    }
  } else if (direction === 'down') {
    // Move to permissions table
    const firstFocusable = permTableRef.value?.querySelector('tbody tr button:not([disabled])')
    if (firstFocusable) firstFocusable.focus()
  }
}

// Focus helper for external navigation
function focusFirstElement() {
  if (isMasterAdmin.value) {
    focusPreferred(orgActionsRef.value, { itemSelector: 'button' })
  } else {
    const firstFocusable = orgTableRef.value?.querySelector('tbody tr a, tbody tr button:not([disabled])')
    if (firstFocusable) firstFocusable.focus()
  }
}

defineExpose({ focusFirstElement })
</script>

<template>
  <div class="permissions-section" ref="orgSection">
    <h2>{{ isMasterAdmin ? 'Organizations' : 'Your Organizations' }}</h2>
    <div class="actions" ref="orgActionsRef" @keydown="handleOrgActionsKeydown">
      <button v-if="isMasterAdmin" @click="$emit('createOrg')">+ Create Org</button>
    </div>
    <table class="org-table" ref="orgTableRef" @keydown="e => handleTableKeydown(e, 'org')">
      <thead>
        <tr>
          <th>Name</th>
          <th>Roles</th>
          <th>Members</th>
          <th v-if="isMasterAdmin">Actions</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="o in sortedOrgs" :key="o.uuid">
          <td>
            <a href="#org/{{o.uuid}}" @click.prevent="$emit('openOrg', o)">{{ o.org.display_name }}</a>
            <button v-if="isMasterAdmin || isOrgAdmin" @click="$emit('updateOrg', o)" class="icon-btn edit-org-btn" aria-label="Rename organization" title="Rename organization">✏️</button>
          </td>
          <td class="role-names">{{ getRoleNames(o) }}</td>
          <td class="center">{{ orgUserCount(o) }}</td>
          <td v-if="isMasterAdmin" class="center">
            <button @click="$emit('deleteOrg', o)" class="icon-btn delete-icon" aria-label="Delete organization" title="Delete organization">❌</button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <div v-if="isMasterAdmin" class="permissions-section">
    <h2>Permissions</h2>
    <div class="matrix-wrapper" ref="permMatrixRef" @keydown="handleMatrixKeydown">
      <div class="matrix-scroll">
        <div
          class="perm-matrix-grid"
          :style="{ gridTemplateColumns: 'minmax(180px, 1fr) ' + sortedOrgs.map(()=> '2.2rem').join(' ') }"
        >
          <div class="grid-head perm-head">Permission</div>
          <div
            v-for="o in sortedOrgs"
            :key="'head-' + o.uuid"
            class="grid-head org-head"
            :title="o.org.display_name"
          >
            <span>{{ o.org.display_name }}</span>
          </div>

          <template v-for="p in sortedPermissions" :key="p.uuid">
            <div class="perm-name" :title="p.scope">
              <span class="display-text">{{ p.display_name }}</span>
            </div>
            <div
              v-for="o in sortedOrgs"
              :key="o.uuid + '-' + p.uuid"
              class="matrix-cell"
            >
              <input
                type="checkbox"
                :checked="p.uuid in o.permissions"
                @change="e => $emit('toggleOrgPermission', o, p.uuid, e.target.checked)"
              />
            </div>
          </template>
        </div>
      </div>
      <p class="matrix-hint muted">Toggle which permissions each organization can grant to its members.</p>
    </div>
    <div class="actions" ref="permActionsRef" @keydown="handlePermActionsKeydown">
      <button v-if="isMasterAdmin" @click="$emit('openDialog', 'perm-create', { display_name: '', scope: '', domain: '' })">+ Create Permission</button>
    </div>
    <table class="org-table" ref="permTableRef" @keydown="e => handleTableKeydown(e, 'perm')">
        <thead>
          <tr>
            <th scope="col">Permission</th>
            <th scope="col">Domain</th>
            <th scope="col" class="center">Members</th>
            <th scope="col" class="center">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in sortedPermissions" :key="p.uuid">
            <td class="perm-name-cell">
              <div class="perm-title">
                <span class="display-text">{{ p.display_name }}</span>
                <button @click="$emit('renamePermissionDisplay', p)" class="icon-btn edit-display-btn" aria-label="Edit permission" title="Edit permission">✏️</button>
              </div>
              <div class="perm-id-info">
                <span class="id-text">{{ p.scope }}</span>
              </div>
            </td>
            <td class="perm-domain">{{ p.domain || '—' }}</td>
            <td class="perm-members center">{{ permissionSummary[p.uuid]?.userCount || 0 }}</td>
            <td class="perm-actions center">
              <button @click="$emit('deletePermission', p)" class="icon-btn delete-icon" aria-label="Delete permission" title="Delete permission">❌</button>
            </td>
          </tr>
        </tbody>
      </table>
  </div>
</template>

<style scoped>
.permissions-section { margin-bottom: var(--space-xl); }
.permissions-section h2 { margin-bottom: var(--space-md); }
.org-table a { text-decoration: none; color: var(--color-link); }
.org-table a:hover { text-decoration: underline; }
.org-table .center { width: 6rem; min-width: 6rem; }
.org-table .role-names { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.perm-name-cell { display: flex; flex-direction: column; gap: 0.3rem; }
.perm-title { font-weight: 600; color: var(--color-heading); }
.perm-id-info { font-size: 0.8rem; color: var(--color-text-muted); display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
.perm-domain { color: var(--color-text-muted); font-size: 0.9rem; }
.perm-matrix-grid .org-head { display: flex; align-items: flex-end; justify-content: center; }
.perm-matrix-grid .org-head span { writing-mode: vertical-rl; transform: rotate(180deg); font-size: 0.65rem; }
.display-text { margin-right: var(--space-xs); }
.edit-display-btn { padding: 0.1rem 0.2rem; font-size: 0.8rem; }
.edit-org-btn { padding: 0.1rem 0.2rem; font-size: 0.8rem; margin-left: var(--space-xs); }
.perm-actions { text-align: center; }
</style>
