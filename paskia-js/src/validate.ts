import { apiJson } from './fetch'
import settings from './settings'

export class SessionValidator {
  private userUuidGetter: () => string | undefined
  private onSessionLost: (error: Error) => void
  private pollTimer: ReturnType<typeof setInterval> | null = null
  private idleTimer: ReturnType<typeof setTimeout> | null = null
  private active = false

  constructor(userUuidGetter: () => string | undefined, onSessionLost: (error: Error) => void) {
    this.userUuidGetter = userUuidGetter
    this.onSessionLost = onSessionLost
    this.resetIdleTimer = this.resetIdleTimer.bind(this)
  }

  resetIdleTimer(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer)
    if (!this.active) this.startPolling()
    this.idleTimer = setTimeout(() => this.stopPolling(), settings.idle_ms)
  }

  async validate(): Promise<void> {
    try {
      const data = await apiJson<{ ctx?: { user?: { uuid?: string } } }>('/auth/api/validate', { method: 'POST', timeout: settings.auth_ms })
      const newUuid = data.ctx?.user?.uuid
      if (newUuid !== this.userUuidGetter()) {
        window.location.reload()
      }
    } catch (error) {
      if ((error as Error).name !== 'NetworkError') {
        this.stopPolling()
        this.onSessionLost(error as Error)
      }
    }
  }

  startPolling(): void {
    if (this.active) return
    this.active = true
    this.pollTimer = setInterval(() => this.validate(), settings.poll_ms)
  }

  stopPolling(): void {
    this.active = false
    if (this.pollTimer) {
      clearInterval(this.pollTimer)
      this.pollTimer = null
    }
  }

  start(): void {
    window.addEventListener('pointermove', this.resetIdleTimer)
    window.addEventListener('pointerdown', this.resetIdleTimer)
    this.resetIdleTimer()
  }

  stop(): void {
    window.removeEventListener('pointermove', this.resetIdleTimer)
    window.removeEventListener('pointerdown', this.resetIdleTimer)
    if (this.idleTimer) clearTimeout(this.idleTimer)
    this.stopPolling()
  }
}
