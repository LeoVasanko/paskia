<template>
  <section :class="['section-block', sectionClass]" data-component="session-list-section">
    <div class="section-header">
      <h2>Active Sessions</h2>
      <p class="section-description">{{ sectionDescription }}</p>
    </div>
    <div class="section-body">
      <div>
        <template v-if="sessionsArray.length">
          <div v-for="(group, key) in groupedSessions" :key="key" class="session-group" tabindex="0" @keydown="handleGroupKeydown($event, key)">
            <span :class="['session-group-host', { 'is-current-site': group.isCurrentSite }]">
              <span class="session-group-icon">{{ group.isOIDC ? '🪪' : '🌐' }}</span>
              <template v-if="group.isOIDC">{{ group.displayName }}</template>
              <a v-else-if="key" :href="hostUrl(key)" tabindex="-1" target="_blank" rel="noopener noreferrer">{{ key }}</a>
              <template v-else>Unbound host</template>
            </span>
            <div class="session-list">
              <div
                v-for="session in group.sessions"
                :key="session.key"
                :class="['session-item', {
                  'is-current': session.is_current && !hoveredIp && !hoveredCredentialUuid,
                  'is-hovered': hoveredSession?.key === session.key,
                  'is-linked-credential': hoveredCredentialUuid === session.credential
                }]"
                tabindex="-1"
                @mousedown.prevent
                @click.capture="handleCardClick"
                @focusin="handleSessionFocus(session)"
                @focusout="handleSessionBlur($event)"
                @keydown="handleItemKeydown($event, session)"
              >
                <div class="item-top">
                  <h4 class="item-title">{{ session.user_agent || '—' }}</h4>
                  <div class="item-actions">
                    <span v-if="session.is_current && !hoveredIp && !hoveredCredentialUuid" class="badge badge-current">Current</span>
                    <span v-else-if="hoveredSession?.key === session.key" class="badge badge-current">Selected</span>
                    <span v-else-if="hoveredCredentialUuid === session.credential" class="badge badge-current">Linked</span>
                    <span v-else-if="!hoveredCredentialUuid && isSameHost(session.ip)" class="badge">Same IP</span>
                    <button
                      @click="$emit('terminate', session)"
                      class="btn-card-delete"
                      :disabled="isTerminating(session.key)"
                      :title="isTerminating(session.key) ? 'Terminating...' : 'Terminate session'"
                      tabindex="-1"
                    >❌</button>
                  </div>
                </div>
                <div class="item-details">
                  <div class="session-dates">
                    <span class="date-label">{{ formatDate(session.last_renewed) }}</span>
                    <span class="date-value" @click="copyIp(session.ip)" title="Click to copy full IP">{{ displayIp(session.ip) }}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </template>
        <div v-else class="empty-state"><p>{{ emptyMessage }}</p></div>
      </div>
    </div>
  </section>
</template>

<script setup>
import { computed, ref } from 'vue'
import { formatDate } from '@/utils/helpers'
import { useAuthStore } from '@/stores/auth'
import { hostIP } from '@/utils/helpers'
import { navigateGrid, handleDeleteKey, handleEscape, getDirection } from '@/utils/keynav'

const props = defineProps({
  sessions: { type: Object, default: () => ({}) },
  emptyMessage: { type: String, default: 'You currently have no other active sessions.' },
  sectionDescription: { type: String, default: "Review where you're signed in and end any sessions you no longer recognize." },
  terminatingSessions: { type: Object, default: () => ({}) },
  hoveredCredentialUuid: { type: String, default: null },
  navigationDisabled: { type: Boolean, default: false },
  sectionClass: { type: String, default: '' },
})

const emit = defineEmits(['terminate', 'sessionHover', 'navigate-out'])

const authStore = useAuthStore()

const hoveredIp = ref(null)
const hoveredSession = ref(null)

const handleSessionFocus = (session) => {
  hoveredSession.value = session
  hoveredIp.value = session.ip || null
  emit('sessionHover', session)
}

const handleSessionBlur = (event) => {
  // Only clear if focus moved outside this element
  if (!event.currentTarget.contains(event.relatedTarget)) {
    hoveredSession.value = null
    hoveredIp.value = null
    emit('sessionHover', null)
  }
}

const handleCardClick = (event) => {
  if (!event.currentTarget.matches(':focus')) {
    event.currentTarget.focus()
    event.stopPropagation()
  }
}

const isTerminating = (sessionKey) => !!props.terminatingSessions[sessionKey]

const handleGroupKeydown = (event, host) => {
  const group = event.currentTarget
  const sessionList = group.querySelector('.session-list')
  const items = sessionList?.querySelectorAll('.session-item')
  const allGroups = Array.from(document.querySelectorAll('.session-group'))
  const groupIndex = allGroups.indexOf(group)

  // Enter on group header opens link (always allowed)
  if (event.key === 'Enter' && event.target === group) {
    if (host) group.querySelector('a')?.click()
    return
  }

  if (props.navigationDisabled) return

  // Arrow keys to enter the grid from the group
  const direction = getDirection(event)
  if (['down', 'right'].includes(direction) && event.target === group) {
    event.preventDefault()
    items?.[0]?.focus()
    return
  }

  // Up/Left from group navigates to previous group or out
  if (['up', 'left'].includes(direction) && event.target === group) {
    event.preventDefault()
    if (groupIndex > 0) {
      allGroups[groupIndex - 1].focus()
    } else {
      emit('navigate-out', 'up')
    }
    return
  }

  // Escape emits navigate-out
  handleEscape(event, (dir) => emit('navigate-out', dir))
}

const handleItemKeydown = (event, session) => {
  // Handle delete (always allowed even with modal)
  handleDeleteKey(event, () => {
    if (!isTerminating(session.key)) emit('terminate', session)
  })
  if (event.defaultPrevented) return

  if (props.navigationDisabled) return

  // Arrow key navigation
  const direction = getDirection(event)
  if (direction) {
    event.preventDefault()
    const group = event.currentTarget.closest('.session-group')
    const sessionListEl = group.querySelector('.session-list')
    const result = navigateGrid(sessionListEl, event.currentTarget, direction, { itemSelector: '.session-item' })

    // Custom boundary handling for session list
    if (result === 'boundary') {
      if (direction === 'left' || direction === 'up') {
        // At left/top edge, focus group
        group?.focus()
      } else if (direction === 'down' || direction === 'right') {
        // Try to navigate to next group or emit navigate-out
        const allGroups = Array.from(document.querySelectorAll('.session-group'))
        const groupIndex = allGroups.indexOf(group)

        if (groupIndex < allGroups.length - 1) {
          allGroups[groupIndex + 1].focus()
        } else {
          emit('navigate-out', 'down')
        }
      }
    }
  }

  // Escape focuses the group
  if (event.key === 'Escape') {
    event.preventDefault()
    event.currentTarget.closest('.session-group')?.focus()
  }
}

const hostUrl = (host) => {
  // Assume http if there's a port number, https otherwise
  const protocol = host.includes(':') ? 'http' : 'https'
  return `${protocol}://${host}`
}

const copyIp = async (ip) => {
  if (!ip) return
  try {
    await navigator.clipboard.writeText(ip)
    authStore.showMessage('Full IP copied to clipboard!', 'success', 2000)
  } catch (err) {
    console.error('Failed to copy IP:', err)
    authStore.showMessage('Failed to copy IP', 'error', 3000)
  }
}

const displayIp = ip => hostIP(ip) ?? ip

// Convert sessions dict to array with key attached
const sessionsArray = computed(() =>
  Object.entries(props.sessions || {}).map(([key, session]) => ({ ...session, key }))
)

const currentHostIP = computed(() => {
  if (hoveredIp.value) return hostIP(hoveredIp.value)
  const current = sessionsArray.value.find(s => s.is_current)
  return current ? hostIP(current.ip) : null
})

const isSameHost = ip => currentHostIP.value && hostIP(ip) === currentHostIP.value

const groupedSessions = computed(() => {
  const groups = {}
  for (const session of sessionsArray.value) {
    const groupKey = session.client || session.host || ''
    if (!groups[groupKey]) {
      groups[groupKey] = { sessions: [], isCurrentSite: false, isOIDC: !!session.client, displayName: session.client_name || groupKey }
    }
    groups[groupKey].sessions.push(session)
    if (session.is_current_host) groups[groupKey].isCurrentSite = true
  }
  for (const groupKey in groups) groups[groupKey].sessions.sort((a, b) => new Date(b.last_renewed) - new Date(a.last_renewed))
  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' })
  const sorted = Object.entries(groups).sort(([, a], [, b]) => {
    if (a.isOIDC !== b.isOIDC) return a.isOIDC ? 1 : -1
    return collator.compare(a.displayName, b.displayName) || collator.compare(a.sessions[0]?.client || '', b.sessions[0]?.client || '')
  })
  return Object.fromEntries(sorted)
})
</script>
