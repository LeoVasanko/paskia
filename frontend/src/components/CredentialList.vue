<template>
  <div class="credential-list">
    <div v-if="loading"><p>Loading credentials...</p></div>
    <div v-else-if="!credentials?.length"><p>No passkeys found.</p></div>
    <template v-else>
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

<style scoped>
.credential-list {
  width: 100%;
  margin-top: var(--space-sm);
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 1rem 1.25rem;
  align-items: stretch;
}

.credential-item {
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  padding: 0.85rem 1rem;
  background: var(--color-surface);
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  width: 28rem;
  height: 100%;
  transition: border-color 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease;
}

.credential-item:hover {
  border-color: var(--color-border-strong);
  box-shadow: 0 10px 24px rgba(15, 23, 42, 0.12);
  transform: translateY(-1px);
}

.credential-item.current-session {
  border-color: var(--color-accent);
  background: rgba(37, 99, 235, 0.08);
}

.credential-header {
  display: flex;
  align-items: flex-start;
  gap: 1rem;
  flex-wrap: wrap;
  flex: 1 1 auto;
}

.credential-icon {
  width: 40px;
  height: 40px;
  display: grid;
  place-items: center;
  background: var(--color-surface-subtle, transparent);
  border-radius: var(--radius-sm);
  border: 1px solid var(--color-border);
}

.auth-icon {
  border-radius: var(--radius-sm);
}

.credential-info {
  flex: 1 1 150px;
  min-width: 0;
}

.credential-info h4 {
  margin: 0;
  font-size: 1rem;
  font-weight: 600;
  color: var(--color-heading);
}

.credential-dates {
  display: grid;
  grid-auto-flow: row;
  grid-template-columns: auto 1fr;
  gap: 0.35rem 0.5rem;
  font-size: 0.75rem;
  align-items: center;
  color: var(--color-text-muted);
}

.date-label {
  font-weight: 600;
}

.date-value {
  color: var(--color-text);
}

.credential-actions {
  margin-left: auto;
  display: flex;
  align-items: center;
}

.btn-delete-credential {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 1rem;
  color: var(--color-danger);
  padding: 0.25rem 0.35rem;
  border-radius: var(--radius-sm);
}

.btn-delete-credential:hover:not(:disabled) {
  background: rgba(220, 38, 38, 0.08);
}

.btn-delete-credential:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

@media (max-width: 600px) {
  .credential-list {
    grid-template-columns: 1fr;
  }
}
</style>
