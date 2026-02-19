<template>
  <div v-if="userLoaded" class="user-info" :class="{ 'has-extra': $slots.default }">
    <div class="user-info-content">
      <div class="user-picture">
        <span>👤</span>
      </div>
      <h3 class="user-name-heading">
        <span class="user-name-row">
          <span class="display-name" :title="name">{{ name }}</span>
          <button v-if="canEdit && updateEndpoint" class="mini-btn" @click="emit('edit')" title="Edit profile">✏️</button>
        </span>
      </h3>
      <div v-if="orgDisplayName || roleName" class="org-role-sub">
        <div class="org-line" v-if="orgDisplayName">{{ orgDisplayName }}</div>
        <div class="role-line" v-if="roleName">{{ roleName }}</div>
      </div>
      <div class="info-fields-block">
        <div v-if="preferred_username" class="contact-item">🆔 {{ preferred_username }}</div>
        <a v-if="email" :href="`mailto:${email}`" class="contact-link">✉️ {{ email }}</a>
        <a v-if="telephone" :href="`tel:${telephone}`" class="contact-link">📞 {{ telephone }}</a>
      </div>
      <div class="info-line">
        <span v-if="visits">
          <span class="info-date">{{ formatDate(createdAt) }}</span>
          <span class="info-punct"> – </span>
          <span class="info-date">{{ formatDate(lastSeen) }}</span>
          <span class="info-punct"> ×</span>
          <span class="info-count">{{ visits }}</span>
        </span>
        <span v-else>
          <span class="info-label">Created </span>
          <span class="info-date">{{ formatDate(createdAt) }}</span>
          <span class="info-punct"> — Never signed in</span>
        </span>
      </div>
    </div>
    <div v-if="$slots.default" class="user-info-extra">
      <slot></slot>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { formatDate } from '@/utils/helpers'

const props = defineProps({
  name: { type: String, required: true },
  email: { type: String, default: null },
  preferred_username: { type: String, default: null },
  telephone: { type: String, default: null },
  visits: { type: [Number, String], default: 0 },
  createdAt: { type: [String, Number, Date], default: null },
  lastSeen: { type: [String, Number, Date], default: null },
  updateEndpoint: { type: String, default: null },
  canEdit: { type: Boolean, default: true },
  loading: { type: Boolean, default: false },
  orgDisplayName: { type: String, default: '' },
  roleName: { type: String, default: '' }
})

const emit = defineEmits(['saved', 'edit'])
const authStore = useAuthStore()

const userLoaded = computed(() => !!props.name)
</script>

<style scoped>
.user-info.has-extra {
  grid-template-columns: minmax(0, 1fr) 14rem;
  grid-template-areas:
    "content extra";
  gap: 1.5rem;
}

.user-info:not(.has-extra) {
  grid-template-columns: minmax(0, 1fr);
  grid-template-areas:
    "content";
}

@media (max-width: 720px) {
  .user-info.has-extra {
    grid-template-columns: 1fr;
    grid-template-areas:
      "content"
      "extra";
  }
}

.user-info-content {
  grid-area: content;
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) minmax(0, 1fr);
  grid-template-areas:
    "picture heading fields"
    "picture org fields"
    ". info info";
  gap: 0 1rem;
  min-width: 0;
}

.user-picture { grid-area: picture; display: flex; align-items: flex-start; font-size: 2em; line-height: 1; }
.user-name-heading { grid-area: heading; display: flex; align-items: center; flex-wrap: wrap; margin: 0 0 0.25rem 0; min-width: 0; }
.org-role-sub { grid-area: org; display: flex; flex-direction: column; min-width: 0; }
.org-line { font-size: .7rem; font-weight: 600; line-height: 1.1; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
.role-line { font-size: .65rem; color: var(--color-text-muted); line-height: 1.1; }
.info-fields-block { grid-area: fields; display: flex; flex-direction: column; gap: 0.25rem; min-width: 0; }
.contact-item { display: block; color: var(--color-text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.contact-link { color: var(--color-text); text-decoration: none; display: block; transition: transform 0.1s ease; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.contact-link:hover { transform: scale(1.01); }
.info-line { grid-area: info; line-height: 1.4; font-size: 0.9em; }
.info-date { color: var(--color-text) !important; }
.info-label { color: var(--color-text) !important; }
.info-punct { color: var(--color-text-muted) !important; }
.info-count { color: var(--color-text-muted) !important; }
.user-info-extra { grid-area: extra; padding-left: 1rem; border-left: 1px solid var(--color-border); flex-shrink: 0; }
.user-name-row { display: inline-flex; align-items: center; gap: 0.35rem; max-width: 100%; min-width: 0; }
.display-name { font-weight: 600; font-size: 1.05em; line-height: 1.2; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
.mini-btn { width: auto; padding: 4px 6px; margin: 0; font-size: 0.75em; line-height: 1; cursor: pointer; background: transparent; }
.mini-btn:hover:not(:disabled) { background: var(--color-accent-soft); color: var(--color-accent); }
.mini-btn:active:not(:disabled) { transform: translateY(1px); }
.mini-btn:disabled { opacity: 0.5; cursor: not-allowed; }
@media (max-width: 720px) { .user-info-extra { padding-left: 0; padding-top: 1rem; margin-top: 1rem; border-left: none; border-top: 1px solid var(--color-border); } }
</style>
