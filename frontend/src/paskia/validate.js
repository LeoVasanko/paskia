import { apiJson } from './fetch.js'

const POLL_INTERVAL = 60 * 1000
const IDLE_TIMEOUT = 5 * 60 * 1000

export class SessionValidator {
  constructor(userUuidGetter, onSessionLost) {
    this.userUuidGetter = userUuidGetter
    this.onSessionLost = onSessionLost
    this.pollTimer = null
    this.idleTimer = null
    this.active = false
    this.resetIdleTimer = this.resetIdleTimer.bind(this)
  }

  resetIdleTimer() {
    if (this.idleTimer) clearTimeout(this.idleTimer)
    if (!this.active) this.startPolling()
    this.idleTimer = setTimeout(() => this.stopPolling(), IDLE_TIMEOUT)
  }

  async validate() {
    try {
      const data = await apiJson('/auth/api/validate', { method: 'POST' })
      const newUuid = data.ctx?.user?.uuid
      if (newUuid !== this.userUuidGetter()) {
        window.location.reload()
      }
    } catch (error) {
      if (error.name !== 'NetworkError') {
        this.stopPolling()
        this.onSessionLost(error)
      }
    }
  }

  startPolling() {
    if (this.active) return
    this.active = true
    this.pollTimer = setInterval(() => this.validate(), POLL_INTERVAL)
  }

  stopPolling() {
    this.active = false
    if (this.pollTimer) {
      clearInterval(this.pollTimer)
      this.pollTimer = null
    }
  }

  start() {
    window.addEventListener('pointermove', this.resetIdleTimer)
    window.addEventListener('pointerdown', this.resetIdleTimer)
    this.resetIdleTimer()
  }

  stop() {
    window.removeEventListener('pointermove', this.resetIdleTimer)
    window.removeEventListener('pointerdown', this.resetIdleTimer)
    if (this.idleTimer) clearTimeout(this.idleTimer)
    this.stopPolling()
  }
}
