<template>
  <div class="view-root host-profile" data-view="host-profile">
    <div class="surface surface--tight">
      <!-- Heading/lede belong to the standalone page; in the dialog the host
           page already provides the surrounding context. -->
      <header v-if="!inIframe" class="view-header center">
        <h1>{{ headingTitle }}</h1>
        <p class="view-lede">{{ subheading }}</p>
      </header>

      <section class="section-block">
        <div class="section-body">
          <UserBasicInfo
            v-if="sessionCtx && info"
            :name="sessionCtx.user.display_name"
            :avatar-url="info.user.avatar_url"
            :visits="info.user.visits"
            :created-at="info.user.created_at"
            :last-seen="info.user.last_seen"
            :email="sessionCtx.user.email"
            :telephone="sessionCtx.user.telephone"
            :org-display-name="orgDisplayName"
            :role-name="roleDisplayName"
            :can-edit="false"
          />
          <p v-else class="empty-state">
            {{ loading ? 'Loading your account…' : 'No active session found.' }}
          </p>
        </div>
      </section>

      <section class="section-block">
        <div class="section-body host-actions">
          <div class="button-row" ref="buttonRow" @keydown="handleButtonRowKeydown">
            <button
              type="button"
              class="btn-secondary"
              @click="$emit('back')"
            >
              Back
            </button>
            <button
              v-if="sessionCtx"
              type="button"
              class="btn-danger"
              :disabled="busy"
              @click="logout"
            >
              {{ busy ? 'Signing out…' : 'Logout' }}
            </button>
            <button
              type="button"
              class="btn-primary"
              :disabled="busy"
              @click="goToAuthSite"
            >
              Full Profile
            </button>
          </div>
          <p v-if="!inIframe" class="note"><strong>Logout</strong> from {{ currentHost }}, or view your <strong>Full Profile</strong> at {{ authSiteHost }} (you may need to sign in again).</p>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import UserBasicInfo from '@/components/UserBasicInfo.vue'
import { getSettings } from '@/utils/settings'
import { fetchJson, settings as paskiaSettings } from 'paskia'
import { updateThemeFromSession } from '@/utils/theme'
import { getDirection, navigateButtonRow } from '@/utils/keynav'

// Data may be provided by the parent (full-page /auth/ app already loaded it
// into the store); otherwise the component fetches it itself (restricted iframe).
const props = defineProps({
  ctx: {
    type: Object,
    default: null
  },
  userInfo: {
    type: Object,
    default: null
  },
  settings: {
    type: Object,
    default: null
  }
})

const emit = defineEmits(['back', 'logout'])

const inIframe = window.parent !== window
const currentHost = window.location.host

const fetchedCtx = ref(null)
const fetchedInfo = ref(null)
const fetchedSettings = ref(null)
const loading = ref(!(props.ctx && props.userInfo))
const busy = ref(false)

// Template refs for navigation
const buttonRow = ref(null)

const sessionCtx = computed(() => props.ctx || fetchedCtx.value)
const info = computed(() => props.userInfo || fetchedInfo.value)
const settingsData = computed(() => props.settings || fetchedSettings.value)
const orgDisplayName = computed(() => sessionCtx.value?.org?.display_name ?? '')
const roleDisplayName = computed(() => sessionCtx.value?.role?.display_name ?? '')

const headingTitle = computed(() => {
  const service = settingsData.value?.rp_name
  return service ? `${service} account` : 'Account overview'
})

const subheading = computed(() => {
  return `You're signed in to ${currentHost}.`
})

const authSiteHost = computed(() => settingsData.value?.auth_host || '')
const authSiteUrl = computed(() => {
  // Fall back to the current host when no separate auth host is configured;
  // the full profile is at ui_base_path either way.
  const host = authSiteHost.value || currentHost
  let path = settingsData.value?.ui_base_path ?? '/auth/'
  if (!path.startsWith('/')) path = `/${path}`
  if (!path.endsWith('/')) path = `${path}/`
  const protocol = window.location.protocol || 'https:'
  return `${protocol}//${host}${path}`
})

const goToAuthSite = () => {
  if (!authSiteUrl.value) return
  // Inside an iframe, open the full profile in a new window and close the
  // frame (auth-back) so the host page regains focus.
  if (inIframe) {
    window.open(authSiteUrl.value, '_blank')
    emit('back')
  } else {
    window.location.href = authSiteUrl.value
  }
}

const logout = async () => {
  if (busy.value) return
  busy.value = true
  try {
    await fetchJson('/auth/api/logout', { method: 'POST', timeout: paskiaSettings.auth_ms })
  } catch (error) {
    console.error('Logout error:', error)
  }
  // The parent decides how to react: the full-page app reloads, the iframe
  // host receives auth-logout and closes the frame.
  emit('logout')
}

// Keyboard navigation for button row
const handleButtonRowKeydown = (event) => {
  const direction = getDirection(event)
  if (!direction) return

  event.preventDefault()

  if (direction === 'left' || direction === 'right') {
    navigateButtonRow(buttonRow.value, event.target, direction, { itemSelector: 'button' })
  }
}

onMounted(async () => {
  if (!props.settings) {
    getSettings().then((data) => { fetchedSettings.value = data })
  }
  if (props.ctx && props.userInfo) return
  try {
    const [validateData, infoData] = await Promise.all([
      fetchJson('/auth/api/validate', { method: 'POST', timeout: paskiaSettings.auth_ms }),
      fetchJson('/auth/api/user-info', { method: 'GET', timeout: paskiaSettings.auth_ms })
    ])
    fetchedCtx.value = validateData.ctx
    fetchedInfo.value = infoData
    updateThemeFromSession(validateData.ctx)
  } catch (error) {
    if (error.status !== 401 && error.status !== 403) {
      console.error('Failed to load account summary:', error)
    }
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.view-root.host-profile { min-height: 100vh; align-items: center; justify-content: center; padding: 2rem 1rem; }
.surface.surface--tight {
  max-width: 520px;
  margin: 0 auto;
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 1.75rem;
}
</style>
