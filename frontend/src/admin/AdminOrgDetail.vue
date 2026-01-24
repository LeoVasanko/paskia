<script setup>
import { computed, ref } from 'vue'
import { getDirection, navigateButtonRow, focusPreferred } from '@/utils/keynav'

const props = defineProps({
  selectedOrg: Object,
  permissions: Array,
  navigationDisabled: { type: Boolean, default: false }
})

const emit = defineEmits(['updateOrg', 'createRole', 'updateRole', 'deleteRole', 'createUserInRole', 'openUser', 'toggleRolePermission', 'onRoleDragOver', 'onRoleDrop', 'onUserDragStart', 'navigateOut'])

// Template refs for navigation
const orgTitleRef = ref(null)
const permMatrixRef = ref(null)
const rolesGridRef = ref(null)

const sortedRoles = computed(() => {
  return [...props.selectedOrg.roles].sort((a, b) => {
    const nameA = a.display_name.toLowerCase()
    const nameB = b.display_name.toLowerCase()
    if (nameA !== nameB) {
      return nameA.localeCompare(nameB)
    }
    return a.uuid.localeCompare(b.uuid)
  })
})

// Get org's grantable permissions as full permission objects (with UUIDs)
const orgPermissions = computed(() => {
  const uuidSet = new Set(props.selectedOrg.permissions || [])
  return props.permissions.filter(p => uuidSet.has(p.uuid))
})

function permissionDisplayName(scope) {
  return props.permissions.find(p => p.scope === scope)?.display_name || scope
}

function toggleRolePermission(role, pid, checked) {
  emit('toggleRolePermission', role, pid, checked)
}

// Handle org title header keynav
function handleTitleKeydown(event) {
  if (props.navigationDisabled) return

  const direction = getDirection(event)
  if (!direction) return

  event.preventDefault()

  if (direction === 'left' || direction === 'right') {
    navigateButtonRow(orgTitleRef.value, event.target, direction, { itemSelector: 'button' })
  } else if (direction === 'up') {
    emit('navigateOut', 'up')
  } else if (direction === 'down') {
    // Move to permission matrix
    const firstCheckbox = permMatrixRef.value?.querySelector('input[type="checkbox"]')
    if (firstCheckbox) {
      firstCheckbox.focus()
    } else {
      // No matrix, go to roles grid
      focusFirstRoleElement()
    }
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
  const cols = sortedRoles.value.length
  const rows = props.selectedOrg.permissions.length

  const currentRow = Math.floor(currentIndex / cols)
  const currentCol = currentIndex % cols

  let newIndex = currentIndex
  if (direction === 'left' && currentCol > 0) {
    newIndex = currentIndex - 1
  } else if (direction === 'right' && currentCol < cols - 1) {
    newIndex = currentIndex + 1
  } else if (direction === 'up' && currentRow > 0) {
    newIndex = currentIndex - cols
  } else if (direction === 'down' && currentRow < rows - 1) {
    newIndex = currentIndex + cols
  } else if (direction === 'up' && currentRow === 0) {
    // Navigate up to title
    const titleButton = orgTitleRef.value?.querySelector('button')
    if (titleButton) titleButton.focus()
    return
  } else if (direction === 'down' && currentRow === rows - 1) {
    // Navigate down to roles grid
    focusFirstRoleElement()
    return
  }

  if (newIndex !== currentIndex && checkboxes[newIndex]) {
    checkboxes[newIndex].focus()
  }
}

// Handle navigation within user list
function handleUserListKeydown(event) {
  if (props.navigationDisabled) return

  const direction = getDirection(event)
  if (!direction) return

  const target = event.target
  if (!target.classList.contains('user-chip')) return

  const list = target.closest('.user-list')
  if (!list) return

  const items = Array.from(list.querySelectorAll('.user-chip'))
  const currentIndex = items.indexOf(target)
  if (currentIndex === -1) return

  // For vertical navigation within the list
  if (direction === 'up' && currentIndex > 0) {
    event.preventDefault()
    items[currentIndex - 1].focus()
    return
  } else if (direction === 'down' && currentIndex < items.length - 1) {
    event.preventDefault()
    items[currentIndex + 1].focus()
    return
  }

  // Handle boundary navigation
  if (direction === 'up' && currentIndex === 0) {
    event.preventDefault()
    // Go to role header buttons
    const roleColumn = list.closest('.role-column')
    const headerButton = roleColumn?.querySelector('.role-header button')
    if (headerButton) headerButton.focus()
    return
  }

  if (direction === 'down' && currentIndex === items.length - 1) {
    // At bottom - nothing below
    return
  }

  // Handle left/right to navigate between role columns
  if (direction === 'left' || direction === 'right') {
    event.preventDefault()
    const roleColumns = Array.from(rolesGridRef.value?.querySelectorAll('.role-column') || [])
    const currentColumn = list.closest('.role-column')
    const colIndex = roleColumns.indexOf(currentColumn)

    let targetColIndex = direction === 'left' ? colIndex - 1 : colIndex + 1
    if (targetColIndex >= 0 && targetColIndex < roleColumns.length) {
      const targetColumn = roleColumns[targetColIndex]
      const targetUsers = targetColumn.querySelectorAll('.user-chip')
      const targetIndex = Math.min(currentIndex, targetUsers.length - 1)
      if (targetUsers[targetIndex]) {
        targetUsers[targetIndex].focus()
      } else {
        // No users in target column, focus the add user button
        const addBtn = targetColumn.querySelector('.plus-btn')
        if (addBtn) addBtn.focus()
      }
    } else if (direction === 'left' && colIndex === 0) {
      // At leftmost column, go up to matrix
      const lastCheckbox = permMatrixRef.value?.querySelector('input[type="checkbox"]:last-of-type')
      if (lastCheckbox) lastCheckbox.focus()
    }
  }
}

// Handle role header button navigation
function handleRoleHeaderKeydown(event, roleIndex) {
  if (props.navigationDisabled) return

  const direction = getDirection(event)
  if (!direction) return

  const roleColumns = Array.from(rolesGridRef.value?.querySelectorAll('.role-column') || [])

  if (direction === 'left' || direction === 'right') {
    event.preventDefault()
    const buttons = event.currentTarget.querySelectorAll('button:not([disabled])')
    const btnIndex = Array.from(buttons).indexOf(event.target)

    if (direction === 'left' && btnIndex > 0) {
      buttons[btnIndex - 1].focus()
    } else if (direction === 'right' && btnIndex < buttons.length - 1) {
      buttons[btnIndex + 1].focus()
    } else if (direction === 'left' && btnIndex === 0 && roleIndex > 0) {
      // Move to previous column's header
      const prevColumn = roleColumns[roleIndex - 1]
      const prevButtons = prevColumn?.querySelectorAll('.role-header button')
      if (prevButtons?.length) prevButtons[prevButtons.length - 1].focus()
    } else if (direction === 'right' && btnIndex === buttons.length - 1 && roleIndex < roleColumns.length - 1) {
      // Move to next column's header
      const nextColumn = roleColumns[roleIndex + 1]
      const nextButton = nextColumn?.querySelector('.role-header button')
      if (nextButton) nextButton.focus()
    }
  } else if (direction === 'up') {
    event.preventDefault()
    // Go to permission matrix
    const checkboxes = permMatrixRef.value?.querySelectorAll('input[type="checkbox"]')
    if (checkboxes?.length) {
      // Focus the checkbox in the corresponding column
      const cols = sortedRoles.value.length
      const rows = props.selectedOrg.permissions.length
      const targetIndex = (rows - 1) * cols + roleIndex
      if (checkboxes[targetIndex]) checkboxes[targetIndex].focus()
      else checkboxes[checkboxes.length - 1].focus()
    } else {
      const titleButton = orgTitleRef.value?.querySelector('button')
      if (titleButton) titleButton.focus()
    }
  } else if (direction === 'down') {
    event.preventDefault()
    // Go to first user in this column
    const roleColumn = roleColumns[roleIndex]
    const firstUser = roleColumn?.querySelector('.user-chip')
    if (firstUser) {
      firstUser.focus()
    }
  }
}

// Handle empty role section keynav
function handleEmptyRoleKeydown(event, roleIndex) {
  if (props.navigationDisabled) return

  const direction = getDirection(event)
  if (!direction) return

  const roleColumns = Array.from(rolesGridRef.value?.querySelectorAll('.role-column') || [])

  if (direction === 'up') {
    event.preventDefault()
    const roleColumn = roleColumns[roleIndex]
    const headerButton = roleColumn?.querySelector('.role-header button')
    if (headerButton) headerButton.focus()
  } else if (direction === 'left' && roleIndex > 0) {
    event.preventDefault()
    const prevColumn = roleColumns[roleIndex - 1]
    const prevEmpty = prevColumn?.querySelector('.empty-role button')
    const prevUser = prevColumn?.querySelector('.user-chip:last-child')
    if (prevEmpty) prevEmpty.focus()
    else if (prevUser) prevUser.focus()
  } else if (direction === 'right' && roleIndex < roleColumns.length - 1) {
    event.preventDefault()
    const nextColumn = roleColumns[roleIndex + 1]
    const nextEmpty = nextColumn?.querySelector('.empty-role button')
    const nextUser = nextColumn?.querySelector('.user-chip')
    if (nextEmpty) nextEmpty.focus()
    else if (nextUser) nextUser.focus()
  }
}

// Helper to focus first element in roles grid
function focusFirstRoleElement() {
  const firstRoleColumn = rolesGridRef.value?.querySelector('.role-column')
  const firstButton = firstRoleColumn?.querySelector('.role-header button')
  if (firstButton) firstButton.focus()
}

// Focus helper for external navigation
function focusFirstElement() {
  const titleButton = orgTitleRef.value?.querySelector('button')
  if (titleButton) titleButton.focus()
}

defineExpose({ focusFirstElement })
</script>

<template>
  <h2 class="org-title" ref="orgTitleRef" @keydown="handleTitleKeydown" :title="selectedOrg.uuid">
    <span class="org-name">{{ selectedOrg.display_name }}</span>
    <button @click="$emit('updateOrg', selectedOrg)" class="icon-btn" aria-label="Rename organization" title="Rename organization">✏️</button>
  </h2>

    <div class="matrix-wrapper" ref="permMatrixRef" @keydown="handleMatrixKeydown">
      <div class="matrix-scroll">
        <div
          class="perm-matrix-grid"
          :style="{ gridTemplateColumns: 'minmax(180px, 1fr) ' + sortedRoles.map(()=> '2.2rem').join(' ') + ' 2.2rem' }"
        >
          <div class="grid-head perm-head">Permission</div>
          <div
            v-for="r in sortedRoles"
            :key="'head-' + r.uuid"
            class="grid-head role-head"
            :title="r.display_name"
          >
            <span>{{ r.display_name }}</span>
          </div>
          <div class="grid-head role-head add-role-head" title="Add role" @click="$emit('createRole', selectedOrg)" role="button" tabindex="0" @keydown.enter="$emit('createRole', selectedOrg)">➕</div>

          <template v-for="p in orgPermissions" :key="p.uuid">
            <div class="perm-name" :title="p.scope">{{ p.display_name }}</div>
            <div
              v-for="r in sortedRoles"
              :key="r.uuid + '-' + p.uuid"
              class="matrix-cell"
            >
              <input
                type="checkbox"
                :checked="r.permissions.includes(p.uuid)"
                @change="e => toggleRolePermission(r, p.uuid, e.target.checked)"
              />
            </div>
            <div class="matrix-cell add-role-cell" />
          </template>
        </div>
      </div>
      <p class="matrix-hint muted">Toggle which permissions each role grants.</p>
    </div>
    <div class="roles-grid" ref="rolesGridRef">
      <div
        v-for="(r, roleIndex) in sortedRoles"
        :key="r.uuid"
        class="role-column"
        @dragover="$emit('onRoleDragOver', $event)"
        @drop="e => $emit('onRoleDrop', e, selectedOrg, r)"
      >
        <div class="role-header" @keydown="e => handleRoleHeaderKeydown(e, roleIndex)">
          <strong class="role-name" :title="r.uuid">
            <span>{{ r.display_name }}</span>
            <button @click="$emit('updateRole', r)" class="icon-btn" aria-label="Edit role" title="Edit role">✏️</button>
          </strong>
          <div class="role-actions">
            <button @click="$emit('createUserInRole', selectedOrg, r)" class="plus-btn" aria-label="Add user" title="Add user">➕</button>
          </div>
        </div>
        <template v-if="r.users.length > 0">
          <ul class="user-list" @keydown="handleUserListKeydown">
            <li
              v-for="u in r.users.slice().sort((a, b) => {
                const nameA = a.display_name.toLowerCase()
                const nameB = b.display_name.toLowerCase()
                if (nameA !== nameB) {
                  return nameA.localeCompare(nameB)
                }
                return a.uuid.localeCompare(b.uuid)
              })"
              :key="u.uuid"
              class="user-chip"
              tabindex="0"
              draggable="true"
              @dragstart="e => $emit('onUserDragStart', e, u, selectedOrg.uuid)"
              @click="$emit('openUser', u)"
              @keydown.enter="$emit('openUser', u)"
              :title="u.uuid"
            >
              <span class="name">{{ u.display_name }}</span>
              <span class="meta">{{ u.last_seen ? new Date(u.last_seen).toLocaleDateString() : '—' }}</span>
            </li>
          </ul>
        </template>
        <div v-else class="empty-role" @keydown="e => handleEmptyRoleKeydown(e, roleIndex)">
          <p class="empty-text muted">No members</p>
          <button @click="$emit('deleteRole', r)" class="icon-btn delete-icon" aria-label="Delete empty role" title="Delete role">❌</button>
        </div>
      </div>
    </div>
</template>

<style scoped>
.card.surface { padding: var(--space-lg); }
.org-title { display: flex; align-items: center; gap: var(--space-sm); margin-bottom: var(--space-lg); }
.org-name { font-size: 1.5rem; font-weight: 600; color: var(--color-heading); }
.icon-btn { background: none; border: none; color: var(--color-text-muted); padding: 0.2rem; border-radius: var(--radius-sm); cursor: pointer; transition: background 0.2s ease, color 0.2s ease; }
.icon-btn:hover { color: var(--color-heading); background: var(--color-surface-muted); }
.matrix-wrapper { margin: var(--space-md) 0; padding: var(--space-lg); }
.matrix-scroll { overflow-x: auto; }
.matrix-hint { font-size: 0.8rem; color: var(--color-text-muted); }
.perm-matrix-grid { display: inline-grid; gap: 0.25rem; align-items: stretch; }
.perm-matrix-grid > * { padding: 0.35rem 0.45rem; font-size: 0.75rem; }
.perm-matrix-grid .grid-head { color: var(--color-text-muted); text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em; }
.perm-matrix-grid .perm-head { display: flex; align-items: flex-end; justify-content: flex-start; padding: 0.35rem 0.45rem; font-size: 0.75rem; }
.perm-matrix-grid .role-head { display: flex; align-items: flex-end; justify-content: center; }
.perm-matrix-grid .role-head span { writing-mode: vertical-rl; transform: rotate(180deg); font-size: 0.65rem; }
.perm-matrix-grid .add-role-head { cursor: pointer; }
.perm-name { font-weight: 600; color: var(--color-heading); padding: 0.35rem 0.45rem; font-size: 0.75rem; }
.roles-grid { display: flex; gap: var(--space-lg); margin-top: var(--space-lg); }
.role-column { flex: 1; min-width: 200px; border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: var(--space-md); }
.role-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--space-md); }
.role-name { display: flex; align-items: center; gap: var(--space-xs); font-size: 1.1rem; color: var(--color-heading); }
.role-actions { display: flex; gap: var(--space-xs); }
.plus-btn { background: var(--color-accent-soft); color: var(--color-accent); border: none; border-radius: var(--radius-sm); padding: 0.25rem 0.45rem; font-size: 1.1rem; cursor: pointer; }
.plus-btn:hover { background: rgba(37, 99, 235, 0.18); }
.user-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: var(--space-xs); }
.user-chip { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: 0.45rem 0.6rem; display: flex; justify-content: space-between; gap: var(--space-sm); cursor: grab; }
.user-chip:focus { outline: 2px solid var(--color-accent); outline-offset: 1px; }
.user-chip .meta { font-size: 0.7rem; color: var(--color-text-muted); }
.empty-role { border: 1px dashed var(--color-border-strong); border-radius: var(--radius-md); padding: var(--space-sm); display: flex; flex-direction: column; gap: var(--space-xs); align-items: flex-start; }
.empty-text { margin: 0; }
.delete-icon { color: var(--color-danger); }
.delete-icon:hover { background: var(--color-danger-bg); color: var(--color-danger-text); }
.muted { color: var(--color-text-muted); }

@media (max-width: 720px) {
  .roles-grid { flex-direction: column; }
}
</style>
