<script setup>
import Modal from '@/components/Modal.vue'

// Shared frame for the admin dialogs: Modal wrapper, title, form with
// error display and Cancel/Save actions. The dialog's fields go in the
// default slot; optional extra content attached next to the modal panel
// (e.g. the domain origins diagnostics) goes in the 'attached' slot.
defineProps({
  title: { type: String, required: true },
  busy: Boolean,
  error: { type: String, default: '' },
  submitLabel: { type: String, default: 'Save' },
  // Block submit (e.g. while domain-origin validation has hard errors)
  submitDisabled: Boolean,
  // Name-edit dialogs render their own error message and action buttons
  // — the frame then only provides the title and the form element
  bare: Boolean
})

defineEmits(['submit', 'close'])
</script>

<template>
  <Modal @close="$emit('close')">
    <template #attached>
      <slot name="attached" />
    </template>
    <h3 class="modal-title">{{ title }}</h3>
    <form @submit.prevent="$emit('submit')" class="modal-form">
      <slot />
      <div v-if="error && !bare" class="error small">{{ error }}</div>
      <div v-if="!bare" class="modal-actions">
        <button
          type="button"
          class="btn-secondary"
          @click="$emit('close')"
          :disabled="busy"
        >
          Cancel
        </button>
        <button
          type="submit"
          class="btn-primary"
          :disabled="busy || submitDisabled"
        >
          {{ submitLabel }}
        </button>
      </div>
    </form>
  </Modal>
</template>
