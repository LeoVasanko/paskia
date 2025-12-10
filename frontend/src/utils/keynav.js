/**
 * Keyboard Navigation Module
 *
 * Provides reusable arrow key navigation for button groups and grids.
 *
 * Concepts:
 * - Group: A container with focusable elements (buttons, links, items)
 * - Button row: Left/right arrows navigate between buttons, up/down navigate to adjacent groups
 * - Grid: A responsive grid of items; arrows follow the visual grid layout
 *
 * Data attributes for customization:
 * - data-nav-group: Marks a navigation group container
 * - data-nav-primary: Marks the preferred element to focus when entering a group
 * - data-nav-items: CSS selector for focusable items within the group (default: 'button, a, [tabindex="0"], [tabindex="-1"]:not([disabled])')
 *
 * Automatic navigation:
 * - Buttons/links inside .button-row or .modal-actions get automatic left/right arrow navigation
 * - No need for explicit @keydown handlers on elements
 * - Call initKeyboardNavigation() once at app startup to enable global navigation
 */

// Direction mapping from key events
const DIRECTION_MAP = {
  ArrowLeft: 'left',
  ArrowRight: 'right',
  ArrowUp: 'up',
  ArrowDown: 'down'
}

// Input types that use left/right arrows for internal cursor movement
const TEXT_INPUT_TYPES = new Set([
  'text', 'email', 'password', 'search', 'tel', 'url', 'number'
])

/**
 * Get the direction from a keyboard event.
 * For text inputs with content, left/right arrows return null to preserve cursor movement.
 * @param {KeyboardEvent} event
 * @returns {string|null} 'left', 'right', 'up', 'down', or null
 */
export const getDirection = (event) => {
  const direction = DIRECTION_MAP[event.key]
  if (!direction) return null

  // For text inputs, preserve left/right for cursor movement when there's content
  const target = event.target
  const isTextInput = (target.tagName === 'INPUT' && TEXT_INPUT_TYPES.has(target.type)) || target.tagName === 'TEXTAREA'
  if (isTextInput && (direction === 'left' || direction === 'right')) {
    // Only allow navigation when input is empty
    if (target.value !== '') return null
  }

  return direction
}

/**
 * Get focusable elements within a container
 * @param {HTMLElement} container
 * @param {string} selector - CSS selector for items (optional)
 * @returns {HTMLElement[]}
 */
export const getFocusableItems = (container, selector = null) => {
  if (!container) return []
  const sel = selector || container.dataset?.navItems || 'button:not([disabled]), a, [tabindex="0"], [tabindex="-1"]:not([disabled])'
  return Array.from(container.querySelectorAll(sel))
}

/**
 * Get grid layout information for a container
 * @param {HTMLElement} container
 * @param {string} itemSelector - CSS selector for grid items
 * @returns {{ items: HTMLElement[], cols: number } | null}
 */
export const getGridInfo = (container, itemSelector) => {
  const items = getFocusableItems(container, itemSelector)
  if (items.length === 0) return null

  // Calculate columns by checking which items share the same top position
  const firstTop = items[0].getBoundingClientRect().top
  let cols = 0
  for (const item of items) {
    if (Math.abs(item.getBoundingClientRect().top - firstTop) < 5) cols++
    else break
  }
  return { items, cols: Math.max(1, cols) }
}

/**
 * Navigate within a horizontal button row
 * @param {HTMLElement} container - The container element
 * @param {HTMLElement} current - Currently focused element
 * @param {string} direction - 'left', 'right', 'up', or 'down'
 * @param {Object} options
 * @param {string} options.itemSelector - CSS selector for buttons
 * @returns {'moved'|'boundary'|'none'} Result of navigation
 */
export const navigateButtonRow = (container, current, direction, options = {}) => {
  const items = getFocusableItems(container, options.itemSelector)
  if (items.length === 0) return 'none'

  const currentIndex = items.indexOf(current)
  if (currentIndex === -1) return 'none'

  if (direction === 'left') {
    if (currentIndex > 0) {
      items[currentIndex - 1].focus()
      return 'moved'
    }
    return 'boundary'
  }

  if (direction === 'right') {
    if (currentIndex < items.length - 1) {
      items[currentIndex + 1].focus()
      return 'moved'
    }
    return 'boundary'
  }

  // Up/down are always boundaries for button rows
  return 'boundary'
}

/**
 * Navigate within a responsive grid
 * @param {HTMLElement} container - The grid container
 * @param {HTMLElement} current - Currently focused element
 * @param {string} direction - 'left', 'right', 'up', or 'down'
 * @param {Object} options
 * @param {string} options.itemSelector - CSS selector for grid items
 * @returns {'moved'|'boundary'|'none'} Result of navigation
 */
export const navigateGrid = (container, current, direction, options = {}) => {
  const grid = getGridInfo(container, options.itemSelector)
  if (!grid) return 'none'

  const { items, cols } = grid
  const currentIndex = items.indexOf(current)
  if (currentIndex === -1) return 'none'

  const row = Math.floor(currentIndex / cols)
  const col = currentIndex % cols
  let newIndex = currentIndex

  switch (direction) {
    case 'left':
      if (col === 0) return 'boundary'
      newIndex = currentIndex - 1
      break
    case 'right':
      if (currentIndex >= items.length - 1) return 'boundary'
      newIndex = currentIndex + 1
      break
    case 'up':
      if (row === 0) return 'boundary'
      newIndex = currentIndex - cols
      break
    case 'down':
      if (currentIndex + cols >= items.length) return 'boundary'
      newIndex = currentIndex + cols
      break
    default:
      return 'none'
  }

  if (newIndex !== currentIndex) {
    items[newIndex].focus()
    return 'moved'
  }
  return 'none'
}

/**
 * Focus the preferred element in a group (primary or first focusable)
 * @param {HTMLElement} container
 * @param {Object} options
 * @param {string} options.primarySelector - CSS selector for primary element
 * @param {string} options.itemSelector - CSS selector for items
 * @returns {HTMLElement|null} The focused element, or null if none found
 */
export const focusPreferred = (container, options = {}) => {
  if (!container) return null

  // First try data-nav-primary
  const primary = container.querySelector('[data-nav-primary]') ||
                  (options.primarySelector && container.querySelector(options.primarySelector))
  if (primary) {
    primary.focus()
    return primary
  }

  // Fall back to first focusable
  const items = getFocusableItems(container, options.itemSelector)
  if (items.length > 0) {
    items[0].focus()
    return items[0]
  }

  return null
}

/**
 * Focus a specific item by index in a group
 * @param {HTMLElement} container
 * @param {number} index - Index of item to focus (negative counts from end)
 * @param {Object} options
 * @param {string} options.itemSelector - CSS selector for items
 * @returns {HTMLElement|null} The focused element, or null if not found
 */
export const focusAtIndex = (container, index, options = {}) => {
  if (!container) return null

  const items = getFocusableItems(container, options.itemSelector)
  if (items.length === 0) return null

  // Support negative indices
  const resolvedIndex = index < 0 ? items.length + index : index
  if (resolvedIndex >= 0 && resolvedIndex < items.length) {
    items[resolvedIndex].focus()
    return items[resolvedIndex]
  }

  return null
}

/**
 * Create a keydown handler for button row navigation
 * @param {Object} options
 * @param {() => HTMLElement} options.getContainer - Function returning the container element
 * @param {string} options.itemSelector - CSS selector for buttons
 * @param {(direction: string) => void} options.onBoundary - Called when navigation hits a boundary
 * @param {() => boolean} options.isDisabled - Function returning whether navigation is disabled
 * @returns {(event: KeyboardEvent) => void}
 */
export const createButtonRowHandler = (options) => {
  const { getContainer, itemSelector, onBoundary, isDisabled } = options

  return (event) => {
    if (isDisabled?.()) return

    const direction = getDirection(event)
    if (!direction) return

    event.preventDefault()
    const container = getContainer()

    if (direction === 'up' || direction === 'down') {
      // Vertical navigation always exits button rows
      onBoundary?.(direction)
      return
    }

    const result = navigateButtonRow(container, event.target, direction, { itemSelector })
    if (result === 'boundary') {
      onBoundary?.(direction)
    }
  }
}

/**
 * Create a keydown handler for grid navigation
 * @param {Object} options
 * @param {() => HTMLElement} options.getContainer - Function returning the container element
 * @param {string} options.itemSelector - CSS selector for grid items
 * @param {(direction: string) => void} options.onBoundary - Called when navigation hits a boundary
 * @param {() => boolean} options.isDisabled - Function returning whether navigation is disabled
 * @returns {(event: KeyboardEvent) => void}
 */
export const createGridHandler = (options) => {
  const { getContainer, itemSelector, onBoundary, isDisabled } = options

  return (event) => {
    if (isDisabled?.()) return

    const direction = getDirection(event)
    if (!direction) return

    event.preventDefault()
    const container = getContainer()
    const result = navigateGrid(container, event.target, direction, { itemSelector })

    if (result === 'boundary') {
      onBoundary?.(direction)
    }
  }
}

/**
 * Handle escape key to navigate out of a component
 * @param {KeyboardEvent} event
 * @param {(direction: string) => void} onNavigateOut - Callback with direction
 * @param {() => boolean} isDisabled - Function returning whether navigation is disabled
 */
export const handleEscape = (event, onNavigateOut, isDisabled) => {
  if (isDisabled?.()) return false
  if (event.key !== 'Escape') return false

  event.preventDefault()
  onNavigateOut?.('up')
  return true
}

/**
 * Handle delete/backspace key for item deletion
 * @param {KeyboardEvent} event
 * @param {() => void} onDelete - Callback to perform deletion
 * @returns {boolean} Whether the key was handled
 */
export const handleDeleteKey = (event, onDelete) => {
  const isMac = navigator.userAgent.includes('Mac OS')
  if (event.key === 'Delete' || (isMac && event.key === 'Backspace')) {
    event.preventDefault()
    onDelete?.()
    return true
  }
  return false
}

/**
 * Focus the most appropriate button in a dialog/modal.
 * Priority: .btn-primary > .btn-secondary > any button
 * @param {HTMLElement} container - The dialog/modal container element
 * @returns {HTMLElement|null} The focused element, or null if none found
 */
export const focusDialogButton = (container) => {
  if (!container) return null

  // Priority order for button selection
  const selectors = [
    '.btn-primary:not([disabled])',
    '.btn-secondary:not([disabled])',
    'button:not([disabled])'
  ]

  for (const selector of selectors) {
    const btn = container.querySelector(selector)
    if (btn) {
      btn.focus()
      return btn
    }
  }

  return null
}

/**
 * Focus the most appropriate element in a dialog/modal.
 * For dialogs with input fields (rename/edit forms): focuses first input and selects text
 * For other dialogs: focuses primary button (or fallback)
 * @param {HTMLElement} container - The dialog/modal container element
 * @returns {HTMLElement|null} The focused element, or null if none found
 */
export const focusDialogDefault = (container) => {
  if (!container) return null

  // Check for input fields first (form dialogs like rename)
  const input = container.querySelector('input:not([disabled]):not([type="hidden"]), textarea:not([disabled])')
  if (input) {
    input.focus()
    // Select text for better UX in rename dialogs
    if (typeof input.select === 'function') {
      input.select()
    }
    return input
  }

  // Fall back to button focus for non-form dialogs
  return focusDialogButton(container)
}

/**
 * Standard keydown handler for button rows with left/right navigation.
 * Can be used directly on buttons or on a container with event delegation.
 * Automatically finds the .button-row or .modal-actions container.
 * @param {KeyboardEvent} event - The keydown event
 * @param {Object} options
 * @param {(direction: string) => void} options.onBoundary - Called when navigation hits a boundary (up/down or edge)
 */
export const handleButtonKeydown = (event, options = {}) => {
  const direction = getDirection(event)
  if (!direction) return

  // Find the button row container
  const target = event.target
  if (target.tagName !== 'BUTTON' && target.tagName !== 'A') return

  const container = target.closest('.button-row, .modal-actions')
  if (!container) return

  if (direction === 'left' || direction === 'right') {
    event.preventDefault()
    const result = navigateButtonRow(container, target, direction, { itemSelector: 'button, a' })
    if (result === 'boundary') {
      options.onBoundary?.(direction)
    }
  } else if (direction === 'up' || direction === 'down') {
    // Vertical navigation exits button rows
    options.onBoundary?.(direction)
  }
}

/**
 * Install keyboard navigation on a container element.
 * Handles arrow key navigation for buttons within .button-row or .modal-actions.
 * Uses event delegation so no need to add handlers to individual buttons.
 * @param {HTMLElement} container - The container element to enable navigation on
 * @param {Object} options
 * @param {(direction: string) => void} options.onBoundary - Called when navigation hits a boundary
 * @returns {() => void} Cleanup function to remove the event listener
 */
export const installKeyboardNav = (container, options = {}) => {
  if (!container) return () => {}

  const handler = (event) => handleButtonKeydown(event, options)
  container.addEventListener('keydown', handler)

  return () => container.removeEventListener('keydown', handler)
}

// ============================================================================
// Global Automatic Keyboard Navigation
// ============================================================================

/**
 * Selector for containers that should have automatic button row navigation
 */
const BUTTON_ROW_SELECTOR = '.button-row, .modal-actions, .actions, .role-actions, .ancillary-actions'

/**
 * Global keydown handler for automatic button row navigation.
 * Handles arrow key navigation for buttons/links within .button-row or .modal-actions containers.
 * @param {KeyboardEvent} event
 */
const globalKeydownHandler = (event) => {
  const direction = getDirection(event)
  if (!direction) return

  // Only handle buttons and links
  const target = event.target
  if (target.tagName !== 'BUTTON' && target.tagName !== 'A') return

  // Find the button row container
  const container = target.closest(BUTTON_ROW_SELECTOR)
  if (!container) return

  if (direction === 'left' || direction === 'right') {
    event.preventDefault()
    navigateButtonRow(container, target, direction, { itemSelector: 'button:not([disabled]), a' })
  }
  // Note: up/down navigation is intentionally not handled globally
  // Components can add their own handlers for vertical navigation between groups
}

let globalNavInitialized = false

/**
 * Initialize global keyboard navigation.
 * Call this once at app startup to enable automatic arrow key navigation
 * for buttons within .button-row and .modal-actions containers.
 * Safe to call multiple times (only initializes once).
 */
export const initKeyboardNavigation = () => {
  if (globalNavInitialized) return
  if (typeof document === 'undefined') return // SSR safety

  document.addEventListener('keydown', globalKeydownHandler)
  globalNavInitialized = true
}

/**
 * Cleanup global keyboard navigation (useful for testing).
 */
export const destroyKeyboardNavigation = () => {
  if (!globalNavInitialized) return
  if (typeof document === 'undefined') return

  document.removeEventListener('keydown', globalKeydownHandler)
  globalNavInitialized = false
}
