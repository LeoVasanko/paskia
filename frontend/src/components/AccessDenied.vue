<template>
  <div class="message-container">
    <div class="message-content">
      <h2>{{ icon }} {{ title }}</h2>
      <p v-if="message" class="error-detail">{{ message }}</p>
      <div class="button-row">
        <button class="btn-secondary" @click="goBack">Back</button>
        <button class="btn-primary" @click="reload">Reload Page</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { goBack } from '@/utils/helpers'

const props = defineProps({
  title: { type: String, default: 'Access Denied' },
  icon: { type: String, default: '🔒' },
  message: { type: String, default: null },
})

function reload() {
  window.location.reload()
}
</script>

<style scoped>
.message-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100vh;
  padding: 2rem;
}

.message-content {
  text-align: center;
  max-width: 480px;
}

.message-content h2 {
  margin: 0 0 1rem;
  color: var(--color-heading);
}

.message-content .error-detail {
  margin: 0 0 1.5rem;
  color: var(--color-text-muted);
}

.message-content .button-row {
  display: flex;
  gap: 0.75rem;
  justify-content: center;
}
</style>
