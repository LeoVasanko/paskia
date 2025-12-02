<template>
  <div class="message-container">
    <div class="message-content">
      <h2>🔒 Authentication Required</h2>
      <p>{{ message }}</p>
      <div class="button-row">
        <button class="btn-primary" @click="$emit('reload')">Reload Page</button>
      </div>
    </div>
  </div>
</template>

<script setup>
defineProps({
  message: {
    type: String,
    default: 'You need to authenticate to access this page.'
  }
})

defineEmits(['reload'])
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

.message-content p {
  color: var(--color-text-muted);
  margin: 0 0 1.5rem;
}

.message-content .button-row {
  display: flex;
  gap: 0.75rem;
  justify-content: center;
}
</style>
