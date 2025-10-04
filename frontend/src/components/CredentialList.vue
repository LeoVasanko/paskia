<template>
  <div class="credential-list">
    <div v-if="loading"><p>Loading credentials...</p></div>
    <div v-else-if="!credentials?.length"><p>No passkeys found.</p></div>
    <template v-else>
      <div
        v-for="credential in credentials"
        :key="credential.credential_uuid"
        :class="['credential-item', { 'current-session': credential.is_current_session } ]"
      >
        <div class="item-top">
          <div class="item-icon">
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
          <h4 class="item-title">{{ getCredentialAuthName(credential) }}</h4>
          <div class="item-actions">
            <span v-if="credential.is_current_session" class="badge badge-current">Current</span>
            <button
              v-if="allowDelete"
              @click="$emit('delete', credential)"
              class="btn-card-delete"
              :disabled="credential.is_current_session"
              :title="credential.is_current_session ? 'Cannot delete current session credential' : 'Delete passkey'"
            >🗑️</button>
          </div>
        </div>
        <div class="item-details">
          <div class="credential-dates">
            <span class="date-label">Created:</span>
            <span class="date-value">{{ formatDate(credential.created_at) }}</span>
            <span class="date-label">Last used:</span>
            <span class="date-value">{{ formatDate(credential.last_used) }}</span>
            <span class="date-label">Last verified:</span>
            <span class="date-value">{{ formatDate(credential.last_verified) }}</span>
          </div>
        </div>
      </div>
    </template>
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
