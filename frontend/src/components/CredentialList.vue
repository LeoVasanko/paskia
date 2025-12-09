<template>
  <div class="credential-list">
    <div v-if="loading"><p>Loading credentials...</p></div>
    <div v-else-if="!credentials?.length"><p>No passkeys found.</p></div>
    <template v-else>
      <div
        v-for="credential in credentials"
        :key="credential.credential_uuid"
        :class="['credential-item', {
          'current-session': credential.is_current_session && !hoveredCredentialUuid && !hoveredSessionCredentialUuid,
          'is-hovered': hoveredCredentialUuid === credential.credential_uuid,
          'is-linked-session': hoveredSessionCredentialUuid === credential.credential_uuid
        }]"
        tabindex="0"
        @mousedown.prevent
        @click.capture="handleCardClick"
        @focusin="handleCredentialFocus(credential.credential_uuid)"
        @focusout="handleCredentialBlur($event)"
        @keydown="handleDelete($event, credential)"
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
            <span v-if="credential.is_current_session && !hoveredCredentialUuid && !hoveredSessionCredentialUuid" class="badge badge-current">Current</span>
            <span v-else-if="hoveredCredentialUuid === credential.credential_uuid" class="badge badge-current">Selected</span>
            <span v-else-if="hoveredSessionCredentialUuid === credential.credential_uuid" class="badge badge-current">Linked</span>
            <button
              v-if="allowDelete"
              @click="$emit('delete', credential)"
              class="btn-card-delete"
              :disabled="credential.is_current_session"
              :title="credential.is_current_session ? 'Cannot delete current session credential' : 'Delete passkey'"
              tabindex="-1"
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
import { formatDate } from '@/utils/helpers'

const props = defineProps({
  credentials: { type: Array, default: () => [] },
  aaguidInfo: { type: Object, default: () => ({}) },
  loading: { type: Boolean, default: false },
  allowDelete: { type: Boolean, default: false },
  hoveredCredentialUuid: { type: String, default: null },
  hoveredSessionCredentialUuid: { type: String, default: null },
})

const emit = defineEmits(['delete', 'credentialHover'])

const handleCredentialFocus = (uuid) => {
  emit('credentialHover', uuid)
}

const handleCredentialBlur = (event) => {
  // Only clear if focus moved outside this element
  if (!event.currentTarget.contains(event.relatedTarget)) {
    emit('credentialHover', null)
  }
}

const handleCardClick = (event) => {
  if (!event.currentTarget.matches(':focus')) {
    event.currentTarget.focus()
    event.stopPropagation()
  }
}

const handleDelete = (event, credential) => {
  const apple = navigator.userAgent.includes('Mac OS')
  if (event.key === 'Delete' || apple && event.key === 'Backspace') {
    event.preventDefault()
    if (props.allowDelete && !credential.is_current_session) emit('delete', credential)
  }
}

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

<style>
.btn-card-delete {
  display: none;
}
.credential-item:focus .btn-card-delete {
  display: block;
}
</style>
