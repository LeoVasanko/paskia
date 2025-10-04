<template>
  <div class="app-shell">
    <StatusMessage />
    <main class="view-root host-view">
      <div class="view-content">
        <header class="view-header">
          <h1>{{ headingTitle }}</h1>
          <p class="view-lede">{{ subheading }}</p>
          <p v-if="authSiteUrl" class="view-hint">
            Manage your full profile on
            <a :href="authSiteUrl">{{ authSiteHost }}</a> (you may need to login again).
          </p>
        </header>

        <section class="section-block">
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
            <div class="button-row">
              <button
                v-if="authSiteUrl"
                type="button"
                class="btn-secondary"
                :disabled="authStore.isLoading"
                @click="goToAuthSite"
              >
                Open full profile
              </button>
              <button
                type="button"
                class="btn-danger"
                :disabled="authStore.isLoading"
                @click="logout"
              >
                {{ authStore.isLoading ? 'Signing out…' : 'Logout' }}
              </button>
            </div>
            <p class="note">Signed in on <strong>{{ currentHost }}</strong>.</p>
          </div>
        </section>
      </div>
    </main>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import StatusMessage from '@/components/StatusMessage.vue'
import UserBasicInfo from '@/components/UserBasicInfo.vue'
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()
const initializing = ref(true)
const currentHost = window.location.host

const user = computed(() => authStore.userInfo?.user || null)
const orgDisplayName = computed(() => authStore.userInfo?.org?.display_name || '')
const roleDisplayName = computed(() => authStore.userInfo?.role?.display_name || '')

const headingTitle = computed(() => {
  const service = authStore.settings?.rp_name
  return service ? `${service} account` : 'Account overview'
})

const subheading = computed(() => {
  const service = authStore.settings?.rp_name || 'this service'
  return `You\u2019re signed in via ${service} on ${currentHost}.`
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

onMounted(async () => {
  try {
    await authStore.loadSettings()
    const service = authStore.settings?.rp_name
    if (service) document.title = `${service} · Account summary`
    await authStore.loadUserInfo()
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unable to load session details'
    authStore.showMessage(message, 'error', 4000)
  } finally {
    initializing.value = false
  }
})
</script>

<style scoped>
.host-view { padding: 3rem 1.5rem 4rem; }
.host-actions { display: flex; flex-direction: column; gap: 0.75rem; }
.host-actions .button-row { gap: 0.75rem; flex-wrap: wrap; }
.host-actions .button-row button { flex: 0 0 auto; }
.note { margin: 0; color: var(--color-text-muted); }
.link { color: var(--color-accent); text-decoration: none; }
.link:hover { text-decoration: underline; }
.view-hint { margin-top: 0.5rem; color: var(--color-text-muted); }
.empty-state { margin: 0; color: var(--color-text-muted); }
@media (max-width: 600px) {
  .host-actions .button-row { flex-direction: column; }
  .host-actions .button-row button { width: 100%; }
}
</style>
