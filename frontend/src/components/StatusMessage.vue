<template>
  <div v-if="authStore.status.show" class="global-status" style="display: block;">
    <div :class="['status', authStore.status.type]">
      {{ authStore.status.message }}
    </div>
  </div>
</template>

<script setup>
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()
</script>
