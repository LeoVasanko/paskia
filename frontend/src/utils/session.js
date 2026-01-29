import { onMounted, onUnmounted } from 'vue'
import { apiJson } from './api'

const POLL_INTERVAL = 60 * 1000
const IDLE_TIMEOUT = 5 * 60 * 1000

export function useSessionValidation(userUuid, onSessionLost) {
  let pollTimer = null
  let idleTimer = null
  let active = false

  function resetIdleTimer() {
    if (idleTimer) clearTimeout(idleTimer)
    if (!active) startPolling()
    idleTimer = setTimeout(stopPolling, IDLE_TIMEOUT)
  }

  async function validate() {
    try {
      const data = await apiJson('/auth/api/validate', { method: 'POST' })
      const newUuid = data.ctx?.user?.uuid
      if (newUuid !== userUuid.value) {
        window.location.reload()
      }
    } catch (error) {
      if (error.name !== 'NetworkError') {
        stopPolling()
        onSessionLost(error)
      }
    }
  }

  function startPolling() {
    if (active) return
    active = true
    pollTimer = setInterval(validate, POLL_INTERVAL)
  }

  function stopPolling() {
    active = false
    if (pollTimer) {
      clearInterval(pollTimer)
      pollTimer = null
    }
  }

  onMounted(() => {
    window.addEventListener('pointermove', resetIdleTimer)
    window.addEventListener('pointerdown', resetIdleTimer)
    resetIdleTimer()
  })

  onUnmounted(() => {
    window.removeEventListener('pointermove', resetIdleTimer)
    window.removeEventListener('pointerdown', resetIdleTimer)
    if (idleTimer) clearTimeout(idleTimer)
    stopPolling()
  })
}
