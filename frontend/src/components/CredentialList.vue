<template>
  <div class="credential-list" tabindex="0" @focusin="handleListFocus" @keydown="handleListKeydown">
    <div v-if="loading"><p>Loading credentials...</p></div>
    <div v-else-if="!credentials?.length"><p>No passkeys found.</p></div>
    <template v-else>
      <div
        v-for="credential in credentials"
        :key="credential.credential"
        :class="['credential-item', {
          'current-session': credential.is_current_session && !hoveredCredentialUuid && !hoveredSessionCredentialUuid,
          'is-hovered': hoveredCredentialUuid === credential.credential,
          'is-linked-session': hoveredSessionCredentialUuid === credential.credential
        }]"
        tabindex="-1"
        @mousedown.prevent
        @click.capture="handleCardClick"
        @focusin="handleCredentialFocus(credential.credential)"
        @focusout="handleCredentialBlur($event)"
        @keydown="handleItemKeydown($event, credential)"
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
            <span v-else-if="hoveredCredentialUuid === credential.credential" class="badge badge-current">Selected</span>
            <span v-else-if="hoveredSessionCredentialUuid === credential.credential" class="badge badge-current">Linked</span>
            <button
              v-if="allowDelete"
              @click="$emit('delete', credential)"
              class="btn-card-delete"
              :disabled="credential.is_current_session"
              :title="credential.is_current_session ? 'Cannot delete current session credential' : 'Delete passkey and terminate any linked sessions.'"
              tabindex="-1"
            >❌</button>
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
import { navigateGrid, handleEscape, handleDeleteKey, getDirection } from '@/utils/keynav'

const props = defineProps({
  credentials: { type: Array, default: () => [] },
  aaguidInfo: { type: Object, default: () => ({}) },
  loading: { type: Boolean, default: false },
  allowDelete: { type: Boolean, default: false },
  hoveredCredentialUuid: { type: String, default: null },
  hoveredSessionCredentialUuid: { type: String, default: null },
  navigationDisabled: { type: Boolean, default: false },
})

const emit = defineEmits(['delete', 'credentialHover', 'navigate-out'])

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
  handleDeleteKey(event, () => {
    if (props.allowDelete && !credential.is_current_session) emit('delete', credential)
  })
}

const handleListFocus = (event) => {
  if (props.navigationDisabled) return

  const list = event.currentTarget
  // If focus came to the list container itself (not a child), focus first item
  if (event.target === list) {
    const firstItem = list.querySelector('.credential-item')
    if (firstItem) {
      firstItem.focus()
    }
  }
}

const handleListKeydown = (event) => {
  if (props.navigationDisabled) return

  // Escape emits navigate-out
  handleEscape(event, (dir) => emit('navigate-out', dir))
}

const handleItemKeydown = (event, credential) => {
  // Handle delete (always allowed even with modal)
  handleDelete(event, credential)
  if (event.defaultPrevented) return

  if (props.navigationDisabled) return

  // Arrow key navigation
  const direction = getDirection(event)
  if (direction) {
    event.preventDefault()
    const list = event.currentTarget.closest('.credential-list')
    const result = navigateGrid(list, event.currentTarget, direction, { itemSelector: '.credential-item' })
    if (result === 'boundary') {
      emit('navigate-out', direction)
    }
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
