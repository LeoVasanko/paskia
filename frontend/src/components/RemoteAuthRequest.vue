<template>
  <div class="remote-auth-inline">
    <!-- Success state -->
    <div v-if="completed" class="success-section">
      <p class="success-message">✅ {{ successMessage }}</p>
    </div>

    <!-- Error state -->
    <div v-else-if="error" class="error-section">
      <p class="error-message">{{ error }}</p>
      <button class="btn-primary" @click="retry">Try Again</button>
    </div>

    <!-- Connecting phase -->
    <div v-else-if="phase === 'connecting'" class="auth-display">
      <div class="auth-content">
        <div class="pairing-code-section">
          <p class="pairing-label">Enter the code words:</p>
          <div class="slot-machine" aria-hidden="true">
            <div class="slot-reel" v-for="(word, index) in animatedWords" :key="index">
              <div class="slot-word">{{ word }}</div>
            </div>
          </div>
          <p class="site-url">{{ siteUrlDisplay }}</p>
        </div>
      </div>

      <div class="waiting-indicator">
        <div class="spinner-small"></div>
        <span>Generating code…</span>
      </div>
    </div>

    <!-- Waiting/Authenticating phase - show codes -->
    <div v-else class="auth-display">
      <div class="auth-content">
        <div v-if="pairingCode" class="pairing-code-section">
          <p class="pairing-label">Enter the code words:</p>
          <div class="slot-machine stopped">
            <div class="slot-reel" v-for="(word, index) in displayCode.split(' ')" :key="index">
              <div class="slot-word">{{ word }}</div>
            </div>
          </div>
          <p class="site-url">{{ siteUrlDisplay }}</p>
        </div>
      </div>

      <div class="waiting-indicator">
        <div class="spinner-small"></div>
        <span>{{ waitingMessage }}</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import aWebSocket from '@/utils/awaitable-websocket'
import { b64dec, b64enc } from '@/utils/base64url'
import { getSettings } from '@/utils/settings'
import { solvePoW } from '@/utils/pow'
import { words } from '@/utils/wordlist'

const props = defineProps({
  active: { type: Boolean, default: false }
})

const emit = defineEmits(['authenticated', 'cancelled', 'error', 'register'])

const pairingCode = ref(null)
const completed = ref(false)
const error = ref(null)
const phase = ref('connecting')
const settings = ref(null)
const animatedWords = ref(['', '', ''])
let ws = null
let wordAnimationTimer = null

const displayCode = computed(() => pairingCode.value ? pairingCode.value.replace(/\./g, ' ') : '')

const siteUrlDisplay = computed(() => {
  if (!settings.value) return ''
  const authSiteUrl = settings.value.auth_site_url || `${location.protocol}//${location.host}/auth/`
  // Remove the protocol and any trailing slash
  const withoutProtocol = authSiteUrl.replace(/^https?:\/\//, '')
  return withoutProtocol.endsWith('/') ? withoutProtocol.slice(0, -1) : withoutProtocol
})

const waitingMessage = computed(() => {
  return phase.value === 'authenticating'
    ? 'Complete on another device…'
    : 'Waiting for authentication…'
})

const successMessage = computed(() => 'Authenticated successfully!')

function getRandomWord() {
  return words[Math.floor(Math.random() * words.length)]
}

function startWordAnimation() {
  // Initialize with random words
  animatedWords.value = [getRandomWord(), getRandomWord(), getRandomWord()]

  let updateCount = 0
  const maxUpdates = 20 // Number of cycles before stopping

  // Different intervals for each slot to spin independently
  const intervals = [
    setInterval(() => {
      const newWords = [...animatedWords.value]
      newWords[0] = getRandomWord()
      animatedWords.value = newWords
    }, 140),
    setInterval(() => {
      const newWords = [...animatedWords.value]
      newWords[1] = getRandomWord()
      animatedWords.value = newWords
    }, 170),
    setInterval(() => {
      const newWords = [...animatedWords.value]
      newWords[2] = getRandomWord()
      animatedWords.value = newWords
    }, 200)
  ]

  wordAnimationTimer = intervals

  // Stop all after max updates
  setTimeout(() => {
    intervals.forEach(interval => clearInterval(interval))
    wordAnimationTimer = null
  }, maxUpdates * 170) // Average interval time
}

function stopWordAnimation() {
  if (wordAnimationTimer) {
    if (Array.isArray(wordAnimationTimer)) {
      wordAnimationTimer.forEach(interval => clearInterval(interval))
    } else {
      clearInterval(wordAnimationTimer)
    }
    wordAnimationTimer = null
  }
}

async function startRemoteAuth() {
  error.value = null
  completed.value = false
  pairingCode.value = null
  phase.value = 'connecting'

  // Start word animation
  startWordAnimation()

  try {
    settings.value = await getSettings()
    const authHost = settings.value?.auth_host
    const wsPath = '/auth/ws/remote-auth/request'
    const wsUrl = authHost && location.host !== authHost ? `//${authHost}${wsPath}` : wsPath

    ws = await aWebSocket(wsUrl)

    // PoW challenge
    const powChallenge = await ws.receive_json()
    if (powChallenge.status) {
      throw new Error(powChallenge.detail || `Failed to connect: ${powChallenge.status}`)
    }
    if (powChallenge.pow) {
      const challenge = b64dec(powChallenge.pow.challenge)
      const nonces = await solvePoW(challenge, powChallenge.pow.work)
      ws.send_json({ pow: b64enc(nonces), action: 'login' })
    }

    // Receive the pairing code
    const res = await ws.receive_json()

    if (res.status) {
      throw new Error(res.detail || `Failed to create remote auth request: ${res.status}`)
    }

    pairingCode.value = res.pairing_code

    // Stop word animation
    stopWordAnimation()

    phase.value = 'waiting'

    // Wait for authentication
    while (true) {
      const msg = await ws.receive_json()

      if (msg.status === 'locked') {
        // Someone has entered the code and is authenticating
        phase.value = 'authenticating'
      } else if (msg.status === 'paired') {
        // Legacy/compatibility: Device paired, now authenticating
        phase.value = 'authenticating'
      } else if (msg.status === 'authenticated') {
        // Success
        completed.value = true
        emit('authenticated', { exchange_code: msg.exchange_code })
        break
      } else if (msg.status === 'denied') {
        // Explicitly denied by the authenticating device
        throw new Error('Access denied')
      } else if (msg.status === 'completed') {
        // Registration flow
        if (msg.reset_token) {
          completed.value = true
          emit('register', msg.reset_token)
        }
        break
      } else if (msg.status === 'error' || msg.detail) {
        throw new Error(msg.detail || 'Remote authentication failed')
      }
    }
  } catch (err) {
    console.error('Remote authentication error:', err)
    const message = err.message || 'Authentication failed'
    error.value = message
    emit('error', message)
  } finally {
    if (ws) {
      ws.close()
      ws = null
    }
  }
}

function retry() {
  startRemoteAuth()
}

function cancel() {
  if (ws) {
    ws.close()
    ws = null
  }
  emit('cancelled')
}

watch(() => props.active, (newVal) => {
  if (newVal && !pairingCode.value && !error.value && !completed.value) {
    startRemoteAuth()
  }
})

onMounted(() => {
  if (props.active) {
    startRemoteAuth()
  }
})

onUnmounted(() => {
  if (ws) {
    ws.close()
    ws = null
  }
  stopWordAnimation()
})

defineExpose({ retry, cancel })
</script>

<style scoped>
.remote-auth-inline {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  width: 100%;
}

.loading-section {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
  padding: 2rem 1rem;
  min-height: 180px;
  justify-content: center;
}

.loading-section p {
  margin: 0;
  color: var(--color-text-muted);
  font-size: 0.95rem;
}

.spinner {
  width: 40px;
  height: 40px;
  border: 3px solid var(--color-border);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

.auth-display {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
  width: 100%;
  min-height: 180px;
}

.auth-content {
  display: flex;
  gap: 2rem;
  align-items: center;
  justify-content: center;
  flex-wrap: nowrap;
}

.loading-placeholder {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
  width: 100%;
  padding: 1rem;
}

.loading-placeholder p {
  margin: 0;
  color: var(--color-text-muted);
  font-size: 0.95rem;
}

.pairing-code-section {
  flex: 0 0 auto;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  width: 280px;
  max-width: 100%;
}

.pairing-label {
  margin: 0;
  font-size: 0.875rem;
  color: var(--color-text-muted);
  font-weight: 500;
  text-align: center;
}

.slot-machine {
  padding: 0.875rem 1rem;
  background: var(--color-surface-hover, rgba(0, 0, 0, 0.03));
  border: 2px solid var(--color-border);
  border-radius: var(--radius-sm, 6px);
  font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
  display: flex;
  align-items: center;
  user-select: none;
  pointer-events: none;
  white-space: nowrap;
  overflow: hidden;
}

.slot-reel {
  overflow: hidden;
  background: var(--color-surface, rgba(255, 255, 255, 0.5));
}

.slot-machine:not(.stopped) .slot-reel:nth-child(1) {
  animation: slotSpin 0.14s ease-in-out infinite;
}

.slot-machine:not(.stopped) .slot-reel:nth-child(2) {
  animation: slotSpin 0.17s ease-in-out infinite;
}

.slot-machine:not(.stopped) .slot-reel:nth-child(3) {
  animation: slotSpin 0.20s ease-in-out infinite;
}

.slot-word {
  font-size: 1.25rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-align: center;
  width: 100%;
}

.slot-machine:not(.stopped) .slot-reel:nth-child(1) .slot-word {
  animation: wordRoll 0.14s ease-in-out infinite;
}

.slot-machine:not(.stopped) .slot-reel:nth-child(2) .slot-word {
  animation: wordRoll 0.17s ease-in-out infinite;
}

.slot-machine:not(.stopped) .slot-reel:nth-child(3) .slot-word {
  animation: wordRoll 0.20s ease-in-out infinite;
}

@keyframes slotSpin {
  0% {
    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.1);
  }
  50% {
    box-shadow: inset 0 4px 8px rgba(0, 0, 0, 0.2);
  }
  100% {
    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.1);
  }
}

@keyframes wordRoll {
  0% {
    transform: translateY(-30%) scale(0.9);
    opacity: 0.4;
    filter: blur(1.5px);
  }
  25% {
    transform: translateY(-10%) scale(0.95);
    opacity: 0.6;
    filter: blur(1px);
  }
  50% {
    transform: translateY(0) scale(1);
    opacity: 1;
    filter: blur(0);
  }
  75% {
    transform: translateY(10%) scale(0.95);
    opacity: 0.6;
    filter: blur(1px);
  }
  100% {
    transform: translateY(30%) scale(0.9);
    opacity: 0.4;
    filter: blur(1.5px);
  }
}

.site-url {
  margin: 0.5rem 0 0;
  font-size: 0.8rem;
  color: var(--color-text-muted);
  text-align: center;
  font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
  opacity: 0.8;
}

.waiting-indicator {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.75rem;
  background: var(--color-surface-hover, rgba(0, 0, 0, 0.02));
  border-radius: var(--radius-sm, 6px);
  font-size: 0.875rem;
  color: var(--color-text-muted);
}

.spinner-small {
  width: 16px;
  height: 16px;
  border: 2px solid var(--color-border);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

.success-section {
  padding: 1rem;
  text-align: center;
  min-height: 180px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.success-message {
  margin: 0;
  font-size: 1rem;
  color: var(--color-success, #10b981);
  font-weight: 500;
}

.error-section {
  padding: 1rem;
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  min-height: 180px;
}

.error-message {
  margin: 0;
  font-size: 0.95rem;
  color: var(--color-error, #ef4444);
}

.error-section button {
  margin-top: 0.75rem;
}

/* Responsive adjustments */
@media (max-width: 640px) {
  .auth-content {
    gap: 1.5rem;
    flex-direction: column;
    align-items: center;
  }

  .pairing-code-section {
    width: 100%;
    max-width: 280px;
  }
}

@media (max-width: 480px) {
  .pairing-code {
    font-size: 1.1rem;
    padding: 0.75rem 0.875rem;
  }

  .pairing-code-section {
    width: 100%;
    max-width: 100%;
  }
}
</style>
