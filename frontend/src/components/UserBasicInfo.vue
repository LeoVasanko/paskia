<template>
  <div v-if="userLoaded" class="user-info" :class="{ 'has-extra': $slots.default }">
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
    <span class="info-label"><strong>Visits:</strong></span>
    <span class="info-value">{{ visits || 0 }}</span>
    <span class="info-label"><strong>Registered:</strong></span>
    <span class="info-value">{{ formatDate(createdAt) }}</span>
    <span class="info-label"><strong>Last seen:</strong></span>
    <span class="info-value">{{ formatDate(lastSeen) }}</span>
    <div v-if="$slots.default" class="user-info-extra">
      <slot></slot>
    </div>
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
.user-info.has-extra {
  grid-template-columns: auto 1fr;
  grid-template-areas:
    "heading heading"
    "org org"
    "label1 value1"
    "label2 value2"
    "label3 value3"
    "extra extra";
}

.user-info:not(.has-extra) {
  grid-template-columns: auto 1fr;
  grid-template-areas:
    "heading heading"
    "org org"
    "label1 value1"
    "label2 value2"
    "label3 value3";
}

@media (min-width: 769px) {
  .user-info.has-extra {
    grid-template-columns: auto 1fr 2fr;
    grid-template-areas:
      "heading heading extra"
      "org org extra"
      "label1 value1 extra"
      "label2 value2 extra"
      "label3 value3 extra";
  }
}

.user-name-heading { grid-area: heading; display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; margin: 0 0 0.25rem 0; }
.org-role-sub { grid-area: org; display:flex; flex-direction:column; margin: -0.15rem 0 0.25rem; }
.org-line { font-size: .7rem; font-weight:600; line-height:1.1; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
.role-line { font-size:.65rem; color: var(--color-text-muted); line-height:1.1; }
.info-label:nth-of-type(1) { grid-area: label1; }
.info-value:nth-of-type(2) { grid-area: value1; }
.info-label:nth-of-type(3) { grid-area: label2; }
.info-value:nth-of-type(4) { grid-area: value2; }
.info-label:nth-of-type(5) { grid-area: label3; }
.info-value:nth-of-type(6) { grid-area: value3; }
.user-info-extra { grid-area: extra; padding-left: 2rem; border-left: 1px solid var(--color-border); }
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
@media (max-width: 768px) { .user-info-extra { padding-left: 0; padding-top: 1rem; border-left: none; border-top: 1px solid var(--color-border); } }
@media (max-width: 480px) { .user-name-heading { flex-direction: column; align-items: flex-start; } .user-name-row.editing { width: 100%; } .display-name { max-width: 100%; } }
</style>
