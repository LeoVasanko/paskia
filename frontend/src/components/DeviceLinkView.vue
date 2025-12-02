<template>
  <section class="view-root view-root--narrow view-device-link">
    <header class="view-header">
      <h1>📱 Add Another Device</h1>
      <p class="view-lede">Generate a one-time link to set up passkeys on a new device.</p>
    </header>
    <RegistrationLinkModal
      inline
              :endpoint="'/auth/api/user/create-link'"
      :user-name="userName"
      :auto-copy="false"
      :prefix-copy-with-user-name="!!userName"
      show-close-in-inline
      @copied="onCopied"
    />
    <div class="button-row" style="margin-top:1rem;">
      <button @click="authStore.currentView = 'profile'" class="btn-secondary">Back to Profile</button>
    </div>
  </section>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import RegistrationLinkModal from '@/components/RegistrationLinkModal.vue'

const authStore = useAuthStore()
const userName = ref(null)
const onCopied = () => {
  authStore.showMessage('Link copied to clipboard!', 'success', 2500)
  authStore.currentView = 'profile'
}

onMounted(async () => {
  // Extract optional admin-provided query parameters (?user=Name&emoji=😀)
  const params = new URLSearchParams(location.search)
  const qUser = params.get('user')
  if (qUser) userName.value = qUser.trim()
})

</script>

<style scoped>
.view-lede {
  margin: 0;
  color: var(--color-text-muted);
}

.qr-link {
  text-decoration: none;
  color: var(--color-text);
}

.button-row {
  justify-content: flex-start;
}

@media (max-width: 720px) {
  .button-row {
    flex-direction: column;
  }

  .button-row button {
    width: 100%;
  }
}
</style>
