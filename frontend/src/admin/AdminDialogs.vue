<script setup>
import { computed } from 'vue'
import Modal from '@/components/Modal.vue'
import NameEditForm from '@/components/NameEditForm.vue'
import { useAuthStore } from '@/stores/auth'

const props = defineProps({
  dialog: Object,
  PERMISSION_ID_PATTERN: String,
  settings: Object
})

const emit = defineEmits(['submitDialog', 'closeDialog', 'resetOidcSecret', 'createPermissionForClient'])

const NAME_EDIT_TYPES = new Set(['org-update', 'role-update', 'user-update-name'])
const NO_SUBMIT_TYPES = new Set([])
const rpId = computed(() => props.settings?.rp_id || 'the configured domain')
const discoveryUrl = computed(() => `${window.location.origin}/.well-known/openid-configuration`)

// Initialize validation properties
if (props.dialog?.data && props.dialog.type === 'server-config') {
  if (!('authHostValidation' in props.dialog.data)) {
    props.dialog.data.authHostValidation = null
  }
}

const isValidationInvalid = computed(() => {
  if (props.dialog?.type !== 'server-config') return false
  const d = props.dialog.data
  if (d.authHostValidation?.startsWith('invalid') || d.authHostValidation === 'validating') return true
  if (d.originValidation?.some(v => v === 'invalid' || v === 'validating')) return true
  return false
})

// Copy-to-clipboard helper
const authStore = useAuthStore()
function copyText(value, label) {
  navigator.clipboard.writeText(value).then(() => {
    authStore.showMessage(`${label} copied to clipboard`, 'success', 1500)
  })
}

function addOrigin() {
  const d = props.dialog?.data
  if (d) {
    d.origins.push(rpId.value)
    d.originValidation.push(null)
    validateOrigin(d.origins[d.origins.length - 1], d.origins.length - 1)
  }
}
function removeOrigin(i) {
  const d = props.dialog?.data
  if (d) {
    d.origins.splice(i, 1)
    d.originValidation.splice(i, 1)
  }
}
function stripScheme(val, i) {
  const d = props.dialog?.data
  if (d) d.origins[i] = val.replace(/^https:\/\//, '').replace(/\/+$/, '')
}
function stripSchemeAuthHost() {
  const d = props.dialog?.data
  if (d && d.auth_host) d.auth_host = d.auth_host.replace(/^https:\/\//, '').replace(/\/+$/, '')
}
function focusOriginStart(e) {
  e.target.setSelectionRange(0, 0)
}

function validateOriginDomain(origin, rpId) {
  if (!origin.trim()) return false
  try {
    const url = origin.startsWith('http') ? new URL(origin) : new URL('https://' + origin)
    const hostname = url.hostname
    return hostname === rpId || hostname.endsWith('.' + rpId)
  } catch {
    return false
  }
}

async function validateOriginConnectivity(origin, i) {
  const d = props.dialog?.data
  if (!d) return

  d.originValidation[i] = 'validating'
  try {
    const cleanOrigin = origin.replace(/\/+$/, '')
    const testUrl = cleanOrigin.startsWith('http') ? cleanOrigin : 'https://' + cleanOrigin
    const response = await fetch(testUrl + '/auth/api/settings', {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    })
    if (response.ok) {
      const data = await response.json()
      // Check if it returns valid settings (has rp_id and matches current rp_id)
      const result = (data.rp_id && data.rp_id === rpId.value) ? 'valid' : 'invalid'
      // Only update if the origin hasn't changed
      if (d.origins[i] === origin) {
        d.originValidation[i] = result
      }
    } else {
      if (d.origins[i] === origin) {
        d.originValidation[i] = 'invalid'
      }
    }
  } catch (e) {
    if (d.origins[i] === origin) {
      d.originValidation[i] = 'invalid'
    }
  }
}

function validateOrigin(origin, i) {
  const d = props.dialog?.data
  if (!d) return

  const id = rpId.value
  if (validateOriginDomain(origin, id)) {
    validateOriginConnectivity(origin, i)
  } else {
    d.originValidation[i] = 'invalid'
  }
}

async function validateAuthHostConnectivity(authHost) {
  const d = props.dialog?.data
  if (!d) return

  d.authHostValidation = 'validating'
  try {
    const cleanAuthHost = authHost.replace(/\/+$/, '')
    const testUrl = cleanAuthHost.startsWith('http') ? cleanAuthHost : 'https://' + cleanAuthHost
    const response = await fetch(testUrl + '/auth/api/settings', {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    })
    if (response.ok) {
      const data = await response.json()
      // Check if it returns valid settings (has rp_id and matches current rp_id)
      const result = (data.rp_id && data.rp_id === rpId.value) ? 'valid' : 'invalid'
      // Only update if the auth_host hasn't changed
      if (d.auth_host === authHost) {
        d.authHostValidation = result
      }
    } else {
      if (d.auth_host === authHost) {
        d.authHostValidation = 'invalid-connectivity'
      }
    }
  } catch (e) {
    if (d.auth_host === authHost) {
      d.authHostValidation = 'invalid-connectivity'
    }
  }
}

function validateAuthHost() {
  const d = props.dialog?.data
  if (!d || !d.auth_host?.trim()) {
    d.authHostValidation = null // Allow empty
    return
  }

  const id = rpId.value
  if (validateOriginDomain(d.auth_host, id)) {
    validateAuthHostConnectivity(d.auth_host)
  } else {
    d.authHostValidation = 'invalid-domain'
  }
}
</script>

<template>
  <Modal v-if="dialog.type" @close="$emit('closeDialog')">
      <h3 class="modal-title">
        <template v-if="dialog.type==='org-create'">Create Organization</template>
        <template v-else-if="dialog.type==='org-update'">Rename Organization</template>
        <template v-else-if="dialog.type==='role-create'">Create Role</template>
        <template v-else-if="dialog.type==='role-update'">Edit Role</template>
        <template v-else-if="dialog.type==='user-create'">Add User To Role</template>
        <template v-else-if="dialog.type==='user-update-name'">Edit User Name</template>
        <template v-else-if="dialog.type==='perm-create' || dialog.type==='perm-display'">{{ dialog.type === 'perm-create' ? 'Create Permission' : 'Edit Permission' }}</template>
        <template v-else-if="dialog.type==='oidc-edit'">{{ dialog.data?.isNew ? 'New OIDC Client' : 'OIDC Client' }}</template>
        <template v-else-if="dialog.type==='server-config'">Server Options</template>
        <template v-else-if="dialog.type==='confirm'">Confirm</template>
      </h3>
      <form @submit.prevent="$emit('submitDialog')" class="modal-form">
        <template v-if="dialog.type==='org-create'">
          <label>Name
            <input ref="nameInput" v-model="dialog.data.name" required />
          </label>
        </template>
        <template v-else-if="dialog.type==='org-update'">
          <NameEditForm
            label="Organization Name"
            v-model="dialog.data.name"
            :busy="dialog.busy"
            :error="dialog.error"
            @cancel="$emit('closeDialog')"
          />
        </template>
        <template v-else-if="dialog.type==='role-create'">
          <label>Role Name
            <input v-model="dialog.data.name" placeholder="Role name" required />
          </label>
        </template>
        <template v-else-if="dialog.type==='role-update'">
          <NameEditForm
            label="Role Name"
            v-model="dialog.data.name"
            :busy="dialog.busy"
            :error="dialog.error"
            @cancel="$emit('closeDialog')"
          />
        </template>
        <template v-else-if="dialog.type==='user-create'">
          <p class="small muted">Role: {{ dialog.data.role.display_name }}</p>
          <label>Display Name
            <input v-model="dialog.data.name" placeholder="User display name" required />
          </label>
        </template>
        <template v-else-if="dialog.type==='user-update-name'">
          <NameEditForm
            label="Display Name"
            v-model="dialog.data.name"
            :busy="dialog.busy"
            :error="dialog.error"
            @cancel="$emit('closeDialog')"
          />
        </template>
        <template v-else-if="dialog.type==='perm-create' || dialog.type==='perm-display'">
          <label>Display Name
            <input ref="displayNameInput" v-model="dialog.data.display_name" required />
          </label>
          <label>Permission Scope
            <input v-model="dialog.data.scope" required :pattern="PERMISSION_ID_PATTERN" title="Allowed: A-Za-z0-9:._~-" data-form-type="other" />
          </label>
          <p class="small muted">E.g. yourapp:reports. Changing the scope name may break deployed applications.</p>
          <label>Domain Scope
            <input v-model="dialog.data.domain" data-form-type="other" />
          </label>
          <p class="small muted">A domain ({{ rpId }} or subdomain) restricts this permission to that host. An OIDC client UUID sends it as a <em>groups</em> claim to that client.</p>
        </template>
        <template v-else-if="dialog.type==='server-config'">
          <label>Site Branding (rp-name)
            <input v-model="dialog.data.rp_name" :placeholder="rpId" />
          </label>
          <label>Dedicated Authentication Site (auth-host)
            <input v-model="dialog.data.auth_host" @input="validateAuthHost()" :class="{ 'input-error': dialog.data.authHostValidation?.startsWith('invalid') }" />
          </label>
          <p v-if="dialog.data.authHostValidation === 'validating'" class="small muted">Validating...</p>
          <p v-else-if="dialog.data.authHostValidation === 'valid'" class="small muted">Valid</p>
          <p v-else-if="dialog.data.authHostValidation === 'invalid-domain'" class="small muted">Invalid domain</p>
          <p v-else-if="dialog.data.authHostValidation === 'invalid-connectivity'" class="small muted">Well-formed but unreachable</p>
          <p v-else-if="dialog.data.authHostValidation === 'invalid'" class="small muted">Invalid configuration</p>
          <p v-else-if="dialog.data.authHostValidation === 'invalid'" class="small muted">Enter {{ rpId }} or any subdomain of it.</p>
          <div class="origin-label">
            Allowed Origins
            <button type="button" class="icon-btn origin-add-btn" @click="addOrigin" aria-label="Add origin" title="Add origin">➕</button>
          </div>
          <div v-if="dialog.data.origins.length" class="origin-list">
            <div v-for="(_, i) in dialog.data.origins" :key="i" class="origin-row">
              <input
                :value="dialog.data.origins[i]"
                @input="e => { dialog.data.origins[i] = e.target.value; validateOrigin(e.target.value, i) }"
                @focus="focusOriginStart"
                class="origin-input"
                :class="{ 'input-error': dialog.data.originValidation[i] === 'invalid' }"
              />
              <button type="button" class="icon-btn delete-icon" @click="removeOrigin(i)" aria-label="Remove origin" title="Remove origin">❌</button>
            </div>
          </div>
          <p v-if="!dialog.data.origins.length" class="small muted">{{ rpId }} and all subdomains allowed.</p>
          <p v-else class="small muted">Only the above sites are allowed to authenticate.</p>
        </template>
        <template v-else-if="dialog.type==='confirm'">
          <p>{{ dialog.data.message }}</p>
        </template>
        <div v-if="dialog.error && !NAME_EDIT_TYPES.has(dialog.type)" class="error small">{{ dialog.error }}</div>
        <div v-if="!NAME_EDIT_TYPES.has(dialog.type) && !NO_SUBMIT_TYPES.has(dialog.type)" class="modal-actions">
          <button
            type="button"
            class="btn-secondary"
            @click="$emit('closeDialog')"
            :disabled="dialog.busy"
          >
            Cancel
          </button>
          <button
            type="submit"
            class="btn-primary"
            :disabled="dialog.busy || isValidationInvalid"
          >
            {{ dialog.type==='confirm' ? 'OK' : 'Save' }}
          </button>
        </div>
        <div v-else-if="NO_SUBMIT_TYPES.has(dialog.type)" class="modal-actions">
          <button
            type="button"
            class="btn-primary"
            @click="$emit('closeDialog')"
          >
            Close
          </button>
        </div>
      </form>
  </Modal>
</template>

<style scoped>
.optional { font-weight: normal; color: var(--color-text-muted); font-size: 0.85em; }
.oidc-divider { border: none; border-top: 1px solid var(--color-border); margin: var(--space-sm) 0; }
.oidc-dl { display: grid; grid-template-columns: auto 1fr; gap: 0.2rem 1rem; align-items: baseline; margin: 0; }
.oidc-dl dt { font-size: 0.85rem; color: var(--color-text-muted); white-space: nowrap; }
.oidc-dl dd { margin: 0; cursor: pointer; overflow: hidden; }
.oidc-dl output { font-family: var(--font-mono, monospace); font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
.oidc-reset-row { display: flex; align-items: center; gap: var(--space-sm); flex-wrap: wrap; }
.oidc-groups { cursor: default; }
.oidc-group { cursor: pointer; }
.oidc-group output { white-space: normal; word-break: break-all; }

/* Server config origins */
.origin-label { font-weight: 600; font-size: 0.95rem; margin-top: var(--space-sm); display: flex; align-items: center; gap: var(--space-sm); }
.origin-list { display: flex; flex-direction: column; gap: 0.4rem; }
.origin-row { display: flex; align-items: center; gap: var(--space-xs); }
.origin-input { flex: 1; min-width: 8rem; font-family: var(--font-mono, monospace); }
.origin-row .delete-icon { flex-shrink: 0; }
.origin-add-btn { font-size: 1.2rem; }

.input-error {
  border-color: var(--color-error);
  background: var(--color-error-bg, rgba(239, 68, 68, 0.05));
}
</style>
