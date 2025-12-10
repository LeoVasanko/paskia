<template>
  <div class="modal-overlay" @keydown.esc="$emit('close')" @keydown="handleOverlayKeydown" tabindex="-1">
    <div class="modal" role="dialog" aria-modal="true">
      <slot />
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import { navigateButtonRow, getDirection, focusPreferred, focusDialogDefault } from '@/utils/keynav'

const props = defineProps({
  // Optional: provide a fallback element to focus if original element is gone
  focusFallback: { type: [HTMLElement, Object], default: null },
  // Optional: index to help find next sibling when item is deleted
  focusIndex: { type: Number, default: -1 },
  // Optional: selector for finding siblings when restoring focus
  focusSiblingSelector: { type: String, default: '' }
})

defineEmits(['close'])

// Store the element that had focus before modal opened
const previouslyFocusedElement = ref(null)

/**
 * Try to restore focus to the original element, or find a suitable fallback.
 * Called on unmount to restore focus when modal closes.
 */
const restoreFocus = () => {
  const prev = previouslyFocusedElement.value
  if (!prev) return

  // Check if the original element still exists in DOM and is focusable
  if (document.body.contains(prev) && !prev.disabled) {
    prev.focus()
    return
  }

  // Original element is gone (deleted) - try to find a sibling
  if (props.focusSiblingSelector && props.focusIndex >= 0) {
    // Find container that has items matching the selector
    const containers = [
      props.focusFallback?.$el || props.focusFallback,
      prev.closest('[data-nav-group]'),
      prev.parentElement?.closest('section'),
      document.querySelector('.view-root')
    ].filter(Boolean)

    for (const container of containers) {
      if (!container) continue
      const siblings = container.querySelectorAll(props.focusSiblingSelector)
      if (siblings.length > 0) {
        // Try to focus the next item, or the previous if we were at the end
        const targetIndex = Math.min(props.focusIndex, siblings.length - 1)
        const target = siblings[targetIndex]
        if (target && !target.disabled) {
          target.focus()
          return
        }
      }
    }
  }

  // Fall back to the provided fallback element
  const fallback = props.focusFallback?.$el || props.focusFallback
  if (fallback && document.body.contains(fallback)) {
    const focusable = fallback.querySelector?.('button:not([disabled]), a, [tabindex="0"]') || fallback
    if (focusable?.focus) {
      focusable.focus()
      return
    }
  }
}

const handleOverlayKeydown = (event) => {
  const direction = getDirection(event)
  if (!direction) return

  // Check if we're in a modal-actions row
  const target = event.target
  const actionsRow = target.closest('.modal-actions')

  if (actionsRow && (direction === 'left' || direction === 'right')) {
    event.preventDefault()
    navigateButtonRow(actionsRow, target, direction, { itemSelector: 'button' })
  } else if (direction === 'up' && actionsRow) {
    // From actions, try to go back to last input or focusable element in form
    event.preventDefault()
    const form = actionsRow.closest('form') || actionsRow.closest('.modal-form')
    const inputs = form?.querySelectorAll('input, textarea, select, button:not(.modal-actions button)')
    if (inputs && inputs.length > 0) {
      inputs[inputs.length - 1].focus()
    }
  } else if (direction === 'down' && !actionsRow) {
    // From an input, try to go to modal-actions
    const form = target.closest('form') || target.closest('.modal-form')
    if (form) {
      event.preventDefault()
      const actions = form.querySelector('.modal-actions')
      if (actions) {
        focusPreferred(actions, { primarySelector: '.btn-primary', itemSelector: 'button' })
      }
    }
  }
}

onMounted(() => {
  // Save currently focused element before modal takes focus
  previouslyFocusedElement.value = document.activeElement

  // Autofocus the most appropriate element:
  // - For form dialogs (rename, edit): focus first input and select text
  // - For other dialogs: focus primary button (or fallback)
  nextTick(() => {
    const modal = document.querySelector('.modal')
    if (modal) {
      // Mark primary button for keyboard navigation
      const primaryBtn = modal.querySelector('.modal-actions .btn-primary')
      if (primaryBtn) {
        primaryBtn.setAttribute('data-nav-primary', '')
      }
      // Focus the most appropriate element
      focusDialogDefault(modal)
    }
  })
})

onUnmounted(() => {
  // Restore focus when modal closes
  restoreFocus()
})
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
