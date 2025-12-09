<template>
  <section class="section-block" data-component="session-list-section">
    <div class="section-header">
      <h2>Login Sessions</h2>
      <p class="section-description">{{ sectionDescription }}</p>
    </div>
    <div class="section-body">
      <div>
        <template v-if="Array.isArray(sessions) && sessions.length">
          <div v-for="(group, host) in groupedSessions" :key="host" class="session-group">
            <h3 :class="['session-group-host', { 'is-current-site': group.isCurrentSite }]">
              <template v-if="host"><a :href="hostUrl(host)">🌐 {{ host }}</a></template>
              <template v-else>🌐 Unbound host</template>
            </h3>
            <div class="session-list">
              <div
                v-for="session in group.sessions"
                :key="session.id"
                :class="['session-item', {
                  'is-current': session.is_current && !hoveredIp && !hoveredCredentialUuid,
                  'is-hovered': hoveredSession?.id === session.id,
                  'is-linked-credential': hoveredCredentialUuid === session.credential_uuid
                }]"
                tabindex="0"
                @mousedown.prevent
                @click.capture="handleCardClick"
                @focusin="handleSessionFocus(session)"
                @focusout="handleSessionBlur($event)"
                @keydown="handleDelete($event, session)"
              >
                <div class="item-top">
                  <h4 class="item-title">{{ session.user_agent }}</h4>
                  <div class="item-actions">
                    <span v-if="session.is_current && !hoveredIp && !hoveredCredentialUuid" class="badge badge-current">Current</span>
                    <span v-else-if="hoveredSession?.id === session.id" class="badge badge-current">Selected</span>
                    <span v-else-if="hoveredCredentialUuid === session.credential_uuid" class="badge badge-current">Linked</span>
                    <span v-else-if="!hoveredCredentialUuid && isSameHost(session.ip)" class="badge">Same IP</span>
                    <button
                      @click="$emit('terminate', session)"
                      class="btn-card-delete"
                      :disabled="isTerminating(session.id)"
                      :title="isTerminating(session.id) ? 'Terminating...' : 'Terminate session'"
                      tabindex="-1"
                    >🗑️</button>
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

const props = defineProps({
  sessions: { type: Array, default: () => [] },
  emptyMessage: { type: String, default: 'You currently have no other active sessions.' },
  sectionDescription: { type: String, default: "Review where you're signed in and end any sessions you no longer recognize." },
  terminatingSessions: { type: Object, default: () => ({}) },
  hoveredCredentialUuid: { type: String, default: null },
})

const emit = defineEmits(['terminate', 'sessionHover'])

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

const handleDelete = (event, session) => {
  const apple = navigator.userAgent.includes('Mac OS')
  if (event.key === 'Delete' || apple && event.key === 'Backspace') {
    event.preventDefault()
    if (!isTerminating(session.id)) emit('terminate', session)
  }
}

const isTerminating = (sessionId) => !!props.terminatingSessions[sessionId]

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

const currentHostIP = computed(() => {
  if (hoveredIp.value) return hostIP(hoveredIp.value)
  const current = props.sessions.find(s => s.is_current)
  return current ? hostIP(current.ip) : null
})

const isSameHost = ip => currentHostIP.value && hostIP(ip) === currentHostIP.value

const groupedSessions = computed(() => {
  const groups = {}
  for (const session of props.sessions) {
    const host = session.host || ''
    if (!groups[host]) {
      groups[host] = { sessions: [], isCurrentSite: false }
    }
    groups[host].sessions.push(session)
    if (session.is_current_host) {
      groups[host].isCurrentSite = true
    }
  }
  // Sort sessions within each group by last_renewed descending
  for (const host in groups) {
    groups[host].sessions.sort((a, b) => new Date(b.last_renewed) - new Date(a.last_renewed))
  }
  // Sort groups by host name (natural sort)
  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' })
  const sortedHosts = Object.keys(groups).sort(collator.compare)
  const sortedGroups = {}
  for (const host of sortedHosts) {
    sortedGroups[host] = groups[host]
  }
  return sortedGroups
})
</script>

<style>
.session-group-host {
  font-size: 1em;
  font-weight: 600;
  margin: 0.5rem 0 0.5rem -1.2rem;
}
.session-group-host.is-current-site {
  color: var(--color-accent);
}
.btn-card-delete {
  display: none;
}
.session-item:focus .btn-card-delete {
  display: block;
}
</style>
