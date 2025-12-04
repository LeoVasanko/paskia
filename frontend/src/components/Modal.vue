<template>
  <div class="modal-overlay" @keydown.esc="$emit('close')" tabindex="-1">
    <div class="modal" role="dialog" aria-modal="true">
      <slot />
    </div>
  </div>
</template>

<script setup>
defineEmits(['close'])
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: transparent;
  backdrop-filter: blur(.1rem) brightness(0.7);
  -webkit-backdrop-filter: blur(.1rem) brightness(0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-xl);
  padding: calc(var(--space-lg) - var(--space-xs));
  max-width: 500px;
  width: min(500px, 90vw);
  max-height: 90vh;
  overflow-y: auto;
}

.modal :deep(.modal-title),
.modal :deep(h3) {
  margin: 0 0 var(--space-md);
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--color-heading);
}

.modal :deep(form) {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
}

.modal :deep(.modal-form) {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
}

.modal :deep(.modal-form label) {
  display: flex;
  flex-direction: column;
  gap: var(--space-xs);
  font-weight: 500;
}

.modal :deep(.modal-form input),
.modal :deep(.modal-form textarea) {
  padding: var(--space-md);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  background: var(--color-bg);
  color: var(--color-text);
  font-size: 1rem;
  line-height: 1.4;
  min-height: 2.5rem;
}

.modal :deep(.modal-form input:focus),
.modal :deep(.modal-form textarea:focus) {
  outline: none;
  border-color: var(--color-accent);
  box-shadow: 0 0 0 2px #c7d2fe;
}

.modal :deep(.modal-actions) {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-sm);
  margin-top: var(--space-md);
  margin-bottom: var(--space-xs);
}
</style>
