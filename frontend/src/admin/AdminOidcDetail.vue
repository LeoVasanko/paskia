<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { getDirection, navigateButtonRow } from '@/utils/keynav'
import { useAuthStore } from '@/stores/auth'

const props = defineProps({
  client: Object,
  permissions: Array,
  domains: Array,
  isNew: { type: Boolean, default: false },
  navigationDisabled: { type: Boolean, default: false }
})

const emit = defineEmits(['save', 'cancel', 'delete', 'resetSecret', 'createPermission', 'navigateOut'])

const authStore = useAuthStore()
const headerRef = ref(null)

// Helper function to build URLs
function authSitePath(path) {
  const url = new URL(authStore.settings.auth_site_url)
  url.pathname = path
  return url.toString()
}

// Local form state
const name = ref('')
const redirectUris = ref('')
const clientSecret = ref(null)

// Computed
const clientId = computed(() => props.client?.client_id || props.client?.uuid || '')
// One discovery URL per domain (the OIDC provider is instance-global;
// any configured host works — the RP must use its chosen one consistently)
const discoveryUrls = computed(() => {
  const origins = new Set()
  for (const d of props.domains || []) {
    const url = d.site_url && new URL(d.site_url)
    if (url) origins.add(url.origin)
  }
  if (!origins.size) origins.add(new URL(authStore.settings.auth_site_url).origin)
  return [...origins].sort().map(o => `${o}/.well-known/openid-configuration`)
})
const iconUrl = computed(() => authSitePath('/favicon.ico'))

// Groups (permissions) scoped to this client
const clientGroups = computed(() => {
  if (!props.client || !props.permissions) return []
  const clientUuid = props.client.uuid || props.client.client_id
  return props.permissions.filter(p => p.domain === clientUuid).sort((a, b) => a.scope.localeCompare(b.scope))
})

// Initialize form data from props
watch(() => props.client, (c) => {
  if (c) {
    name.value = c.name || ''
    redirectUris.value = Array.isArray(c.redirect_uris) ? c.redirect_uris.join('\n') : (c.redirect_uris || '')
    clientSecret.value = c.client_secret || null
  }
}, { immediate: true })

// Copy-to-clipboard helper
function copyText(value, label) {
  navigator.clipboard.writeText(value).then(() => {
    authStore.showMessage(`${label} copied to clipboard`, 'success', 1500)
  })
}

function handleResetSecret() {
  emit('resetSecret', clientId.value)
}

// When parent resets secret, update local state
watch(() => props.client?.client_secret, (newSecret) => {
  if (newSecret) {
    clientSecret.value = newSecret
  }
})

function handleSave() {
  const trimmedName = name.value.trim()
  if (!trimmedName) {
    authStore.showMessage('Client name is required', 'error')
    return
  }
  const uris = redirectUris.value.trim()
  const redirect_uris = uris ? uris.split('\n').map(u => u.trim()).filter(u => u) : []

  emit('save', {
    client_id: clientId.value,
    client_secret: clientSecret.value,
    name: trimmedName,
    redirect_uris,
    isNew: props.isNew
  })
}

function handleDelete() {
  emit('delete', props.client)
}

function handleCreatePermission() {
  emit('createPermission', clientId.value)
}

function handleCancel() {
  emit('cancel')
}

// Keyboard navigation
function handleHeaderKeydown(event) {
  if (props.navigationDisabled) return

  const direction = getDirection(event)
  if (!direction) return

  event.preventDefault()

  if (direction === 'left' || direction === 'right') {
    navigateButtonRow(headerRef.value, event.target, direction, { itemSelector: 'button, a' })
  } else if (direction === 'up') {
    emit('navigateOut', 'up')
  }
}

function focusFirstElement() {
  const firstFocusable = headerRef.value?.querySelector('button, a, input')
  if (firstFocusable) firstFocusable.focus()
}

defineExpose({ focusFirstElement })
</script>

<template>
  <div class="oidc-detail">
    <form @submit.prevent="handleSave" class="oidc-form">
      <!-- Client credentials section -->
      <section class="section-block">
        <div class="section-header">
          <h2>Client Configuration</h2>
          <p class="section-description">Configure these values in the client application.</p>
        </div>
        <div class="section-body">

        <dl class="oidc-dl">
          <dt>Authentication Name</dt>
          <dd>
            <output @click="copyText(authStore.settings.rp_name, 'Authentication Name')" title="Click to copy">{{ authStore.settings.rp_name }}</output>
            <span class="small muted"> (Login With, may affect URLs – optional)</span>
          </dd>

          <dt>Client ID</dt>
          <dd><output @click="copyText(clientId, 'Client ID')" title="Click to copy">{{ clientId }}</output></dd>

          <dt>Client Secret <button v-if="!clientSecret" type="button" class="icon-btn" @click="handleResetSecret" title="Revoke and re-generate secret">🔄</button></dt>
          <dd>
            <output v-if="clientSecret" @click="copyText(clientSecret, 'Client Secret')" title="Click to copy">{{ clientSecret }}</output>
            <span v-else class="small muted">(only stored in hashed form)</span>
          </dd>

          <dt class="discovery-dt">Auto Discovery URL
            <span v-if="discoveryUrls.length > 1" class="small muted">Any one — pick the site your users should log in on, and use it consistently.</span>
          </dt>
          <dd class="discovery-dd">
            <span class="discovery-urls">
              <output v-for="url in discoveryUrls" :key="url" @click="copyText(url, 'OpenID Connect Auto Discovery URL')" title="Click to copy">{{ url }}</output>
            </span>
          </dd>

          <dt>Icon URL</dt>
          <dd>
            <output @click="copyText(iconUrl, 'Icon URL')" title="Click to copy">{{ iconUrl }}</output>
            <span class="small muted"> (optional)</span>
          </dd>


          <template v-if="clientGroups.length">
            <dt>Groups Claim Name</dt>
            <dd>
              <output @click="copyText('groups', 'Groups Claim Name')" title="Click to copy">groups</output>
            </dd>
          </template>

          <dt>Groups <button type="button" class="icon-btn" @click="handleCreatePermission" title="Add permission scoped to this client">➕</button></dt>
          <dd class="oidc-groups">
            <template v-if="clientGroups.length">
              <output v-for="group in clientGroups" :key="group.uuid" class="oidc-group" @click="copyText(group.scope, 'Group Value')" :title="group.display_name">{{ group.scope }}</output>
            </template>
            <span v-else class="small muted">(no permissions defined)</span>
          </dd>
        </dl>

        <span class="warning-text">
          <strong v-if="clientSecret">⚠️ {{ isNew ? 'Save the secret now — it cannot be retrieved later.' : 'Saving will prevent access with the old secret.' }}</strong>
          <span v-else>ℹ️ The client may use groups to check for required permissions.</span>
        </span>
        </div>
      </section>

      <!-- Editable fields -->
      <section class="section-block">
        <div class="section-header">
          <h2>Paskia Configuration</h2>
        </div>
        <div class="section-body">
        <label>Client Name
          <input v-model="name" required />
        </label>

        <label>Redirect URIs
          <p class="small muted">This should be provided by the client application.</p>
          <textarea v-model="redirectUris" placeholder="(autodiscover one on first use)" rows="3"></textarea>
        </label>
        </div>
      </section>

      <!-- Actions -->
      <div class="oidc-actions">
        <button type="button" class="btn-secondary" @click="handleCancel">Cancel</button>
        <button v-if="!isNew" type="button" class="btn-danger" @click="handleDelete">Delete Client</button>
        <button type="submit" class="btn-primary">Save</button>
      </div>
    </form>
  </div>
</template>

<style scoped>
.oidc-detail {
  display: flex;
  flex-direction: column;
  gap: var(--space-lg);
}

.oidc-header {
  margin-bottom: 0;
}

.oidc-header h2 {
  margin: 0;
}

.oidc-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-lg);
}

.oidc-dl {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 0.3rem 1rem;
  align-items: baseline;
  margin: var(--space-sm) 0;
}

.oidc-dl dt {
  font-size: 0.85rem;
  color: var(--color-text-muted);
  white-space: nowrap;
}

.oidc-dl dd {
  margin: 0;
  overflow: hidden;
  display: flex;
  align-items: baseline;
  gap: 0.5em;
}

.oidc-dl output {
  font-family: var(--font-mono, monospace);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
}

.discovery-dt {
  white-space: normal;
  max-width: 20em;
}

.discovery-dt .small {
  display: block;
  font-weight: normal;
}

.discovery-dd {
  flex-direction: column;
  align-items: stretch;
  gap: 0.25rem;
}

.discovery-urls {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
  min-width: 0;
}

.warning-text {
  display: block;
  font-size: 0.9rem;
  min-height: 1.4em;
}

.oidc-group { display: block; }
.oidc-group { white-space: normal; word-break: break-all; }

.section-body label {
  display: flex;
  flex-direction: column;
  gap: var(--space-xs);
  font-weight: 500;
}

.oidc-actions {
  display: flex;
  gap: var(--space-sm);
  justify-content: flex-end;
  margin-top: var(--space-md);
}
</style>
