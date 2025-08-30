<template>
  <div class="credential-list">
    <div v-if="loading"><p>Loading credentials...</p></div>
    <div v-else-if="!credentials?.length"><p>No passkeys found.</p></div>
    <div v-else>
      <div
        v-for="credential in credentials"
        :key="credential.credential_uuid"
        :class="['credential-item', { 'current-session': credential.is_current_session }]"
      >
        <div class="credential-header">
          <div class="credential-icon">
            <img
              v-if="getCredentialAuthIcon(credential)"
              :src="getCredentialAuthIcon(credential)"
              :alt="getCredentialAuthName(credential)"
              class="auth-icon"
              width="32"
              height="32"
            >
            <span v-else class="auth-emoji">🔑</span>
          </div>
          <div class="credential-info">
            <h4>{{ getCredentialAuthName(credential) }}</h4>
          </div>
          <div class="credential-dates">
            <span class="date-label">Created:</span>
            <span class="date-value">{{ formatDate(credential.created_at) }}</span>
            <span class="date-label" v-if="credential.last_used">Last used:</span>
            <span class="date-value" v-if="credential.last_used">{{ formatDate(credential.last_used) }}</span>
          </div>
          <div class="credential-actions" v-if="allowDelete">
            <button
              @click="$emit('delete', credential)"
              class="btn-delete-credential"
              :disabled="credential.is_current_session"
              :title="credential.is_current_session ? 'Cannot delete current session credential' : 'Delete passkey'"
            >🗑️</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { formatDate } from '@/utils/helpers'

const props = defineProps({
  credentials: { type: Array, default: () => [] },
  aaguidInfo: { type: Object, default: () => ({}) },
  loading: { type: Boolean, default: false },
  allowDelete: { type: Boolean, default: false },
})

const getCredentialAuthName = (credential) => {
  const info = props.aaguidInfo?.[credential.aaguid]
  return info ? info.name : 'Unknown Authenticator'
}

const getCredentialAuthIcon = (credential) => {
  const info = props.aaguidInfo?.[credential.aaguid]
  if (!info) return null
  const isDarkMode = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
  const iconKey = isDarkMode ? 'icon_dark' : 'icon_light'
  return info[iconKey] || null
}
</script>

<style scoped>
.credential-list { display: flex; flex-direction: column; gap: .75rem; margin-top: .5rem; }
.credential-item { border: 1px solid #ddd; border-radius: 8px; padding: .5rem .75rem; background: #fff; }
.credential-header { display: flex; align-items: center; gap: 1rem; }
.credential-icon { width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; }
.auth-icon { border-radius: 6px; }
.credential-info { flex: 1 1 auto; }
.credential-info h4 { margin: 0; font-size: .9rem; }
.credential-dates { display: grid; grid-auto-flow: column; gap: .4rem; font-size: .65rem; align-items: center; }
.date-label { font-weight: 600; }
.credential-actions { margin-left: auto; }
.btn-delete-credential { background: none; border: none; cursor: pointer; font-size: .9rem; }
.btn-delete-credential:disabled { opacity: .3; cursor: not-allowed; }
</style>
