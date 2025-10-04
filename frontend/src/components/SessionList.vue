<template>
  <section class="section-block" data-component="session-list-section">
    <div class="section-header">
      <h2>Active Sessions</h2>
      <p class="section-description">{{ sectionDescription }}</p>
    </div>
    <div class="section-body">
      <div :class="['session-list']">
        <template v-if="Array.isArray(sessions) && sessions.length">
          <div
            v-for="session in sessions"
            :key="session.id"
            :class="['session-item', { 'is-current': session.is_current }]"
          >
            <div class="item-top">
              <div class="item-icon">
                <span class="session-emoji">🌐</span>
              </div>
              <h4 class="item-title">{{ sessionHostLabel(session) }}</h4>
              <div class="item-actions">
                <span v-if="session.is_current" class="badge badge-current">Current</span>
                <span v-else-if="session.is_current_host" class="badge">This host</span>
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
              <div class="session-details">Last used: {{ formatDate(session.last_renewed) }}</div>
              <div class="session-meta-info">{{ session.user_agent }} {{ session.ip }}</div>
            </div>
          </div>
        </template>
        <div v-else class="empty-state"><p>{{ emptyMessage }}</p></div>
      </div>
    </div>
  </section>
</template>

<script setup>
import { } from 'vue'
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

const sessionHostLabel = (session) => {
  if (!session || !session.host) return 'Unbound host'
  return session.host
}
</script>