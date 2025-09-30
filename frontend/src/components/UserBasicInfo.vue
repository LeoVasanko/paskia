<template>
  <div v-if="userLoaded" class="user-info">
    <h3 class="user-name-heading">
      <span class="icon">👤</span>
      <span class="user-name-row">
        <span class="display-name" :title="name">{{ name }}</span>
        <button v-if="canEdit && updateEndpoint" class="mini-btn" @click="emit('editName')" title="Edit name">✏️</button>
      </span>
    </h3>
    <div v-if="orgDisplayName || roleName" class="org-role-sub">
      <div class="org-line" v-if="orgDisplayName">{{ orgDisplayName }}</div>
      <div class="role-line" v-if="roleName">{{ roleName }}</div>
    </div>
    <span><strong>Visits:</strong></span>
    <span>{{ visits || 0 }}</span>
    <span><strong>Registered:</strong></span>
    <span>{{ formatDate(createdAt) }}</span>
    <span><strong>Last seen:</strong></span>
    <span>{{ formatDate(lastSeen) }}</span>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { formatDate } from '@/utils/helpers'

const props = defineProps({
  name: { type: String, required: true },
  visits: { type: [Number, String], default: 0 },
  createdAt: { type: [String, Number, Date], default: null },
  lastSeen: { type: [String, Number, Date], default: null },
  updateEndpoint: { type: String, default: null },
  canEdit: { type: Boolean, default: true },
  loading: { type: Boolean, default: false },
  orgDisplayName: { type: String, default: '' },
  roleName: { type: String, default: '' }
})

const emit = defineEmits(['saved', 'editName'])
const authStore = useAuthStore()

const userLoaded = computed(() => !!props.name)
</script>

<style scoped>
.user-info { display: grid; grid-template-columns: auto 1fr; gap: 10px; }
.user-info h3 { grid-column: span 2; }
.org-role-sub { grid-column: span 2; display:flex; flex-direction:column; margin: -0.15rem 0 0.25rem; }
.org-line { font-size: .7rem; font-weight:600; line-height:1.1; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
.role-line { font-size:.65rem; color: var(--color-text-muted); line-height:1.1; }
.user-info span { text-align: left; }
.user-name-heading { display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; margin: 0 0 0.25rem 0; }
.user-name-row { display: inline-flex; align-items: center; gap: 0.35rem; max-width: 100%; }
.user-name-row.editing { flex: 1 1 auto; }
.icon { flex: 0 0 auto; }
.display-name { font-weight: 600; font-size: 1.05em; line-height: 1.2; max-width: 14ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.name-input { width: auto; flex: 1 1 140px; min-width: 120px; padding: 6px 8px; font-size: 0.9em; border: 1px solid var(--color-border-strong); border-radius: 6px; background: var(--color-surface); color: var(--color-text); }
.user-name-heading .name-input { width: auto; }
.name-input:focus { outline: none; border-color: var(--color-accent); box-shadow: var(--focus-ring); }
.mini-btn { width: auto; padding: 4px 6px; margin: 0; font-size: 0.75em; line-height: 1; background: var(--color-surface-muted); border: 1px solid var(--color-border-strong); border-radius: 6px; cursor: pointer; transition: background 0.2s, transform 0.15s, color 0.2s ease; color: var(--color-text); }
.mini-btn:hover:not(:disabled) { background: var(--color-accent-soft); color: var(--color-accent); }
.mini-btn:active:not(:disabled) { transform: translateY(1px); }
.mini-btn:disabled { opacity: 0.5; cursor: not-allowed; }
@media (max-width: 480px) { .user-name-heading { flex-direction: column; align-items: flex-start; } .user-name-row.editing { width: 100%; } .display-name { max-width: 100%; } }
</style>
