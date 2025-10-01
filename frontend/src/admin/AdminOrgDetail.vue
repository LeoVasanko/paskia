<script setup>
import { computed } from 'vue'

const props = defineProps({
  selectedOrg: Object,
  permissions: Array
})

const emit = defineEmits(['updateOrg', 'createRole', 'updateRole', 'deleteRole', 'createUserInRole', 'openUser', 'toggleRolePermission', 'onRoleDragOver', 'onRoleDrop', 'onUserDragStart'])

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

function permissionDisplayName(id) {
  return props.permissions.find(p => p.id === id)?.display_name || id
}

function toggleRolePermission(role, pid, checked) {
  emit('toggleRolePermission', role, pid, checked)
}
</script>

<template>
  <h2 class="org-title" :title="selectedOrg.uuid">
    <span class="org-name">{{ selectedOrg.display_name }}</span>
    <button @click="$emit('updateOrg', selectedOrg)" class="icon-btn" aria-label="Rename organization" title="Rename organization">✏️</button>
  </h2>

    <div class="matrix-wrapper">
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
          <div class="grid-head role-head add-role-head" title="Add role" @click="$emit('createRole', selectedOrg)" role="button">➕</div>

          <template v-for="pid in selectedOrg.permissions" :key="pid">
            <div class="perm-name" :title="pid">{{ permissionDisplayName(pid) }}</div>
            <div
              v-for="r in sortedRoles"
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
        v-for="r in sortedRoles"
        :key="r.uuid"
        class="role-column"
        @dragover="$emit('onRoleDragOver', $event)"
        @drop="e => $emit('onRoleDrop', e, selectedOrg, r)"
      >
        <div class="role-header">
          <strong class="role-name" :title="r.uuid">
            <span>{{ r.display_name }}</span>
            <button @click="$emit('updateRole', r)" class="icon-btn" aria-label="Edit role" title="Edit role">✏️</button>
          </strong>
          <div class="role-actions">
            <button @click="$emit('createUserInRole', selectedOrg, r)" class="plus-btn" aria-label="Add user" title="Add user">➕</button>
          </div>
        </div>
        <template v-if="r.users.length > 0">
          <ul class="user-list">
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
              draggable="true"
              @dragstart="e => $emit('onUserDragStart', e, u, selectedOrg.uuid)"
              @click="$emit('openUser', u)"
              :title="u.uuid"
            >
              <span class="name">{{ u.display_name }}</span>
              <span class="meta">{{ u.last_seen ? new Date(u.last_seen).toLocaleDateString() : '—' }}</span>
            </li>
          </ul>
        </template>
        <div v-else class="empty-role">
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