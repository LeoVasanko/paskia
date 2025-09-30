<template>
  <section class="view-root" data-view="profile">
    <div class="view-content">
      <header class="view-header">
        <h1>👋 Welcome!</h1>
        <Breadcrumbs :entries="[{ label: 'Auth', href: '/auth/' }, ...(isAdmin ? [{ label: 'Admin', href: '/auth/admin/' }] : [])]" />
        <p class="view-lede">Manage your account details and passkeys.</p>
      </header>

      <section class="section-block">
        <UserBasicInfo
          v-if="authStore.userInfo?.user"
          :name="authStore.userInfo.user.user_name"
          :visits="authStore.userInfo.user.visits || 0"
          :created-at="authStore.userInfo.user.created_at"
          :last-seen="authStore.userInfo.user.last_seen"
          :loading="authStore.isLoading"
          update-endpoint="/auth/api/user/display-name"
          @saved="authStore.loadUserInfo()"
        />
      </section>

      <section class="section-block">
        <div class="section-header">
          <h2>Your Passkeys</h2>
          <p class="section-description">Keep at least one trusted passkey so you can always sign in.</p>
        </div>
        <div class="section-body">
          <CredentialList
            :credentials="authStore.userInfo?.credentials || []"
            :aaguid-info="authStore.userInfo?.aaguid_info || {}"
            :loading="authStore.isLoading"
            allow-delete
            @delete="handleDelete"
          />
          <div class="button-row">
            <button @click="addNewCredential" class="btn-primary">
              Add New Passkey
            </button>
            <button @click="authStore.currentView = 'device-link'" class="btn-secondary">
              Add Another Device
            </button>
          </div>
        </div>
      </section>

      <section class="section-block">
        <div class="button-row">
          <button @click="logout" class="btn-danger logout-button">
            Logout
          </button>
        </div>
      </section>
    </div>
  </section>
</template>

<script setup>
import { ref, onMounted, onUnmounted, computed } from 'vue'
import Breadcrumbs from '@/components/Breadcrumbs.vue'
import CredentialList from '@/components/CredentialList.vue'
import UserBasicInfo from '@/components/UserBasicInfo.vue'
import { useAuthStore } from '@/stores/auth'
import passkey from '@/utils/passkey'

const authStore = useAuthStore()
const updateInterval = ref(null)

onMounted(() => {
  updateInterval.value = setInterval(() => {
    // Trigger Vue reactivity to update formatDate fields
    if (authStore.userInfo) {
      authStore.userInfo = { ...authStore.userInfo }
    }
  }, 60000) // Update every minute
})

onUnmounted(() => {
  if (updateInterval.value) {
    clearInterval(updateInterval.value)
  }
})

const addNewCredential = async () => {
  try {
    authStore.isLoading = true
    authStore.showMessage('Adding new passkey...', 'info')
    await passkey.register()
    await authStore.loadUserInfo()
    authStore.showMessage('New passkey added successfully!', 'success', 3000)
  } catch (error) {
    console.error('Failed to add new passkey:', error)
    authStore.showMessage(error.message, 'error')
  } finally {
    authStore.isLoading = false
  }
}

const handleDelete = async (credential) => {
  const credentialId = credential?.credential_uuid
  if (!credentialId) return
  if (!confirm('Are you sure you want to delete this passkey?')) return
  try {
    await authStore.deleteCredential(credentialId)
    authStore.showMessage('Passkey deleted successfully!', 'success', 3000)
  } catch (error) {
    authStore.showMessage(`Failed to delete passkey: ${error.message}`, 'error')
  }
}

const logout = async () => {
  await authStore.logout()
}

const isAdmin = computed(() => !!(authStore.userInfo?.is_global_admin || authStore.userInfo?.is_org_admin))
</script>

<style scoped>
.view-lede {
  margin: 0;
  color: var(--color-text-muted);
  font-size: 1rem;
}

.section-header {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}

.section-description {
  margin: 0;
  color: var(--color-text-muted);
}

.logout-button {
  align-self: flex-start;
}

@media (max-width: 720px) {
  .logout-button {
    width: 100%;
  }
}
</style>

