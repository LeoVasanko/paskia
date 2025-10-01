<script setup>
import { computed } from 'vue'

const props = defineProps({
  info: Object,
  orgs: Array,
  permissions: Array,
  permissionSummary: Object
})

const emit = defineEmits(['createOrg', 'openOrg', 'updateOrg', 'deleteOrg', 'toggleOrgPermission', 'openDialog', 'deletePermission', 'renamePermissionDisplay'])

const sortedOrgs = computed(() => [...props.orgs].sort((a,b)=> {
  const nameCompare = a.display_name.localeCompare(b.display_name)
  return nameCompare !== 0 ? nameCompare : a.uuid.localeCompare(b.uuid)
}))
const sortedPermissions = computed(() => [...props.permissions].sort((a,b)=> a.id.localeCompare(b.id)))

function permissionDisplayName(id) {
  return props.permissions.find(p => p.id === id)?.display_name || id
}

function getRoleNames(org) {
  return org.roles
    .slice()
    .sort((a, b) => a.display_name.localeCompare(b.display_name))
    .map(r => r.display_name)
    .join(', ')
}
</script>

<template>
  <div class="permissions-section">
    <h2>{{ info.is_global_admin ? 'Organizations' : 'Your Organizations' }}</h2>
    <div class="actions">
      <button v-if="info.is_global_admin" @click="$emit('createOrg')">+ Create Org</button>
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
        <tr v-for="o in sortedOrgs" :key="o.uuid">
          <td>
            <a href="#org/{{o.uuid}}" @click.prevent="$emit('openOrg', o)">{{ o.display_name }}</a>
            <button v-if="info.is_global_admin || info.is_org_admin" @click="$emit('updateOrg', o)" class="icon-btn edit-org-btn" aria-label="Rename organization" title="Rename organization">✏️</button>
          </td>
          <td class="role-names">{{ getRoleNames(o) }}</td>
          <td class="center">{{ o.roles.reduce((acc,r)=>acc + r.users.length,0) }}</td>
          <td v-if="info.is_global_admin" class="center">
            <button @click="$emit('deleteOrg', o)" class="icon-btn delete-icon" aria-label="Delete organization" title="Delete organization">❌</button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <div v-if="info.is_global_admin" class="permissions-section">
    <h2>Permissions</h2>
    <div class="matrix-wrapper">
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
            :title="o.display_name"
          >
            <span>{{ o.display_name }}</span>
          </div>

          <template v-for="p in sortedPermissions" :key="p.id">
            <div class="perm-name" :title="p.id">
              <span class="display-text">{{ p.display_name }}</span>
            </div>
            <div
              v-for="o in sortedOrgs"
              :key="o.uuid + '-' + p.id"
              class="matrix-cell"
            >
              <input
                type="checkbox"
                :checked="o.permissions.includes(p.id)"
                @change="e => $emit('toggleOrgPermission', o, p.id, e.target.checked)"
              />
            </div>
          </template>
        </div>
      </div>
      <p class="matrix-hint muted">Toggle which permissions each organization can grant to its members.</p>
    </div>
    <div class="actions">
      <button v-if="info.is_global_admin" @click="$emit('openDialog', 'perm-create', { display_name: '', id: '' })">+ Create Permission</button>
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
          <tr v-for="p in sortedPermissions" :key="p.id">
            <td class="perm-name-cell">
              <div class="perm-title">
                <span class="display-text">{{ p.display_name }}</span>
                <button @click="$emit('renamePermissionDisplay', p)" class="icon-btn edit-display-btn" aria-label="Edit display name" title="Edit display name">✏️</button>
              </div>
              <div class="perm-id-info">
                <span class="id-text">{{ p.id }}</span>
              </div>
            </td>
            <td class="perm-members center">{{ permissionSummary[p.id]?.userCount || 0 }}</td>
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
.actions { display: flex; flex-wrap: wrap; gap: var(--space-sm); align-items: center; }
.actions button { width: auto; }
.org-table a { text-decoration: none; color: var(--color-link); }
.org-table a:hover { text-decoration: underline; }
.org-table .center { width: 6rem; min-width: 6rem; }
.org-table .role-names { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.perm-name-cell { display: flex; flex-direction: column; gap: 0.3rem; }
.perm-title { font-weight: 600; color: var(--color-heading); }
.perm-id-info { font-size: 0.8rem; color: var(--color-text-muted); }
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
.perm-matrix-grid .org-head { display: flex; align-items: flex-end; justify-content: center; }
.perm-matrix-grid .org-head span { writing-mode: vertical-rl; transform: rotate(180deg); font-size: 0.65rem; }
.perm-name { font-weight: 600; color: var(--color-heading); padding: 0.35rem 0.45rem; font-size: 0.75rem; }
.display-text { margin-right: var(--space-xs); }
.edit-display-btn { padding: 0.1rem 0.2rem; font-size: 0.8rem; }
.edit-org-btn { padding: 0.1rem 0.2rem; font-size: 0.8rem; margin-left: var(--space-xs); }
.perm-actions { text-align: center; }
.center { text-align: center; }
.muted { color: var(--color-text-muted); }
</style>