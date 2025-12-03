<template>
  <section class="section-block" data-component="session-list-section">
    <div class="section-header">
      <h2>Active Sessions</h2>
      <p class="section-description">{{ sectionDescription }}</p>
    </div>
    <div class="section-body">
      <div :class="['session-list']">
        <template v-if="Array.isArray(sessions) && sessions.length">
          <div v-for="(group, host) in groupedSessions" :key="host" class="session-group">
            <h3 :class="['session-group-host', { 'is-current-site': group.isCurrentSite }]">
              <template v-if="host"><a :href="hostUrl(host)">🌐 {{ host }}</a></template>
              <template v-else>🌐 Unbound host</template>
            </h3>
            <div class="session-group-sessions">
              <div
                v-for="session in group.sessions"
                :key="session.id"
                :class="['session-item', { 'is-current': session.is_current }]"
              >
                <div class="item-top">
                  <h4 class="item-title">{{ session.user_agent }}</h4>
                  <div class="item-actions">
                    <span v-if="session.is_current" class="badge badge-current">Current</span>
                    <span v-else-if="isSameNetwork(session.ip)" class="badge">Same IP</span>
                    <button
                      v-if="allowTerminate"
                      @click="$emit('terminate', session)"
                      class="btn-card-delete"
                      :disabled="isTerminating(session.id)"
                      :title="isTerminating(session.id) ? 'Terminating...' : 'Terminate session'"
                    >🗑️</button>
                  </div>
                </div>
                <div class="item-details">
                  <div class="session-dates">
                    <span class="date-label">{{ formatDate(session.last_renewed) }}</span>
                    <span class="date-value">{{ session.ip }}</span>
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
import { computed } from 'vue'
import { formatDate } from '@/utils/helpers'

const props = defineProps({
  sessions: { type: Array, default: () => [] },
  allowTerminate: { type: Boolean, default: true },
  emptyMessage: { type: String, default: 'You currently have no other active sessions.' },
  sectionDescription: { type: String, default: "Review where you're signed in and end any sessions you no longer recognize." },
  terminatingSessions: { type: Object, default: () => ({}) }
})

const emit = defineEmits(['terminate'])

const isTerminating = (sessionId) => !!props.terminatingSessions[sessionId]

const hostUrl = (host) => {
  // Assume http if there's a port number, https otherwise
  const protocol = host.includes(':') ? 'http' : 'https'
  return `${protocol}://${host}`
}

// Extract /64 prefix for IPv6, or return full IP for IPv4
const getNetworkPrefix = (ip) => {
  if (!ip) return null
  // Check if IPv6 (contains colon)
  if (ip.includes(':')) {
    // Expand and get first 4 groups (64 bits)
    const parts = ip.split(':')
    // Take first 4 parts for /64 prefix
    return parts.slice(0, 4).join(':')
  }
  // IPv4 - return as-is
  return ip
}

const currentNetworkPrefix = computed(() => {
  const current = props.sessions.find(s => s.is_current)
  return current ? getNetworkPrefix(current.ip) : null
})

const isSameNetwork = (ip) => {
  if (!currentNetworkPrefix.value || !ip) return false
  return getNetworkPrefix(ip) === currentNetworkPrefix.value
}

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
.session-meta-info {
  grid-column: span 2;
}
[data-component="session-list-section"] .session-list {
  display: flex;
  flex-direction: column;
  gap: 1.5em;
}
.session-group {
  display: flex;
  flex-direction: column;
  gap: 0.5em;
}
.session-group-host {
  font-size: 1em;
  font-weight: 600;
  margin: 0;
}
.session-group-host a {
  color: inherit;
  text-decoration: none;
}
.session-group-host a:hover {
  text-decoration: underline;
}
.session-group-host.is-current-site {
  color: var(--color-accent);
}
.session-group-sessions {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(var(--card-width), 1fr));
  gap: 0.5em;
  align-items: start;
}
.session-group-sessions .session-item {
  width: auto;
  height: auto;
  padding: 0.75rem;
  gap: 0.5rem;
}
.session-group-sessions .session-item .item-title {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.session-group-sessions .session-item .item-details {
  margin-left: 0;
}
.session-group-sessions .session-item .session-dates {
  grid-template-columns: auto 1fr;
}
</style>
