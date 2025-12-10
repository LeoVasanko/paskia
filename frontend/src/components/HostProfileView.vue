<template>
  <section class="view-root host-view" data-view="host-profile">
    <header class="view-header">
      <h1>{{ headingTitle }}</h1>
      <p class="view-lede">{{ subheading }}</p>
    </header>

    <section class="section-block" ref="userInfoSection">
      <div class="section-body">
        <UserBasicInfo
          v-if="user"
          :name="user.user_name"
          :visits="user.visits || 0"
          :created-at="user.created_at"
          :last-seen="user.last_seen"
          :org-display-name="orgDisplayName"
          :role-name="roleDisplayName"
          :can-edit="false"
        />
        <p v-else class="empty-state">
          {{ initializing ? 'Loading your account…' : 'No active session found.' }}
        </p>
      </div>
    </section>

    <section class="section-block">
      <div class="section-body host-actions">
        <div class="button-row" ref="buttonRow" @keydown="handleButtonRowKeydown">
          <button
            type="button"
            class="btn-secondary"
            @click="goBack"
          >
            Back
          </button>
          <button
            type="button"
            class="btn-danger"
            :disabled="authStore.isLoading"
            @click="logout"
          >
            {{ authStore.isLoading ? 'Signing out…' : 'Logout' }}
          </button>
          <button
            v-if="authSiteUrl"
            type="button"
            class="btn-primary"
            :disabled="authStore.isLoading"
            @click="goToAuthSite"
          >
            Full Profile
          </button>
        </div>
        <p class="note"><strong>Logout</strong> from {{ currentHost }}, or access your <strong>Full Profile</strong> at {{ authSiteHost }} (you may need to sign in again).</p>
      </div>
    </section>
  </section>
</template>

<script setup>
import { computed, ref } from 'vue'
import UserBasicInfo from '@/components/UserBasicInfo.vue'
import { useAuthStore } from '@/stores/auth'
import { goBack } from '@/utils/helpers'
import { getDirection, navigateButtonRow } from '@/utils/keynav'

defineProps({
  initializing: {
    type: Boolean,
    default: false
  }
})

const authStore = useAuthStore()
const currentHost = window.location.host

// Template refs for navigation
const userInfoSection = ref(null)
const buttonRow = ref(null)

const user = computed(() => authStore.userInfo?.user || null)
const orgDisplayName = computed(() => authStore.userInfo?.org?.display_name || '')
const roleDisplayName = computed(() => authStore.userInfo?.role?.display_name || '')

const headingTitle = computed(() => {
  const service = authStore.settings?.rp_name
  return service ? `${service} account` : 'Account overview'
})

const subheading = computed(() => {
  return `You're signed in to ${currentHost}.`
})

const authSiteHost = computed(() => authStore.settings?.auth_host || '')
const authSiteUrl = computed(() => {
  const host = authSiteHost.value
  if (!host) return ''
  let path = authStore.settings?.ui_base_path ?? '/auth/'
  if (!path.startsWith('/')) path = `/${path}`
  if (!path.endsWith('/')) path = `${path}/`
  const protocol = window.location.protocol || 'https:'
  return `${protocol}//${host}${path}`
})

const goToAuthSite = () => {
  if (!authSiteUrl.value) return
  window.location.href = authSiteUrl.value
}

const logout = async () => {
  await authStore.logout()
}

// Keyboard navigation for button row
const handleButtonRowKeydown = (event) => {
  const direction = getDirection(event)
  if (!direction) return

  event.preventDefault()

  if (direction === 'left' || direction === 'right') {
    navigateButtonRow(buttonRow.value, event.target, direction, { itemSelector: 'button' })
  }
  // Up does nothing (no elements above to navigate to)
  // Down does nothing (no elements below to navigate to)
}
</script>

<style scoped>
.host-view { padding: 3rem 1.5rem 4rem; }
.host-actions { display: flex; flex-direction: column; gap: 0.75rem; }
.host-actions .button-row { gap: 0.75rem; flex-wrap: wrap; }
.host-actions .button-row button { flex: 0 0 auto; }
.note { margin: 0; color: var(--color-text-muted); }
.empty-state { margin: 0; color: var(--color-text-muted); }
@media (max-width: 600px) {
  .host-actions .button-row { flex-direction: column; }
  .host-actions .button-row button { width: 100%; }
}
</style>
