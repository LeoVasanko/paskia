<template>
  <div class="name-edit-form">
    <label :for="resolvedInputId">{{ label }}
      <input
        :id="resolvedInputId"
        ref="inputRef"
        :type="inputType"
        :placeholder="placeholder"
        v-model="localValue"
        :disabled="busy"
        required
      />
    </label>
    <div v-if="error" class="error small">{{ error }}</div>
    <div class="modal-actions" @keydown="handleActionsKeydown">
      <button
        type="button"
        class="btn-secondary"
        @click="handleCancel"
        :disabled="busy"
      >
        {{ cancelText }}
      </button>
      <button
        type="submit"
        class="btn-primary"
        :disabled="busy"
        data-nav-primary
      >
        {{ submitText }}
      </button>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { getDirection } from '@/utils/keynav'

const props = defineProps({
  modelValue: { type: String, default: '' },
  label: { type: String, default: 'Name' },
  placeholder: { type: String, default: '' },
  submitText: { type: String, default: 'Save' },
  cancelText: { type: String, default: 'Cancel' },
  busy: { type: Boolean, default: false },
  error: { type: String, default: '' },
  autoFocus: { type: Boolean, default: true },
  autoSelect: { type: Boolean, default: true },
  inputId: { type: String, default: null },
  inputType: { type: String, default: 'text' }
})

const emit = defineEmits(['update:modelValue', 'cancel'])
const inputRef = ref(null)
const generatedId = `name-edit-${Math.random().toString(36).slice(2, 10)}`

const localValue = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val)
})

const resolvedInputId = computed(() => props.inputId || generatedId)

const handleActionsKeydown = (event) => {
  const direction = getDirection(event)
  if (direction === 'up') {
    event.preventDefault()
    inputRef.value?.focus()
    return
  }
  // Left/right navigation is handled globally by keynav
}

function handleCancel() {
  emit('cancel')
}

</script>

<style scoped>
.name-edit-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
}
</style>
