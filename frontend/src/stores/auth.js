import { defineStore } from 'pinia'
import { register, authenticate } from '@/utils/passkey'
import { getSettings } from '@/utils/settings'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    // Auth State
    userInfo: null, // Contains the full user info response: {user, credentials, aaguid_info}
    isLoading: false,

    // Settings
    settings: null,

    // UI State
    currentView: 'login',
    status: {
      message: '',
      type: 'info',
      show: false
    },
  }),
  getters: {
  },
  actions: {
    setLoading(flag) {
      this.isLoading = !!flag
    },
    showMessage(message, type = 'info', duration = 3000) {
      this.status = {
        message,
        type,
        show: true
      }
      if (duration > 0) {
        setTimeout(() => {
          this.status.show = false
        }, duration)
      }
    },
    async setSessionCookie(sessionToken) {
      const response = await fetch('/auth/api/set-session', {
        method: 'POST',
        headers: {'Authorization': `Bearer ${sessionToken}`},
      })
      const result = await response.json()
      if (result.detail) {
        throw new Error(result.detail)
      }
      return result
    },
    async register() {
      this.isLoading = true
      try {
        const result = await register()
        await this.setSessionCookie(result.session_token)
        await this.loadUserInfo()
        this.selectView()
        return result
      } finally {
        this.isLoading = false
      }
    },
    async authenticate() {
      this.isLoading = true
      try {
        const result = await authenticate()

        await this.setSessionCookie(result.session_token)
        await this.loadUserInfo()
        this.selectView()

        return result
      } finally {
        this.isLoading = false
      }
    },
    selectView() {
      if (!this.userInfo) this.currentView = 'login'
      else this.currentView = 'profile'
    },
    async loadSettings() {
      this.settings = await getSettings()
    },
    async loadUserInfo() {
      const response = await fetch('/auth/api/user-info', { method: 'POST' })
      let result = null
      try {
        result = await response.json()
      } catch (_) {
        // ignore JSON parse errors (unlikely)
      }
      if (response.status === 401 && result?.detail) {
        this.showMessage(result.detail, 'error', 5000)
        throw new Error(result.detail)
      }
      if (result?.detail) {
        // Other error style
        this.showMessage(result.detail, 'error', 5000)
        throw new Error(result.detail)
      }
      this.userInfo = result
      console.log('User info loaded:', result)
    },
    async deleteCredential(uuid) {
  const response = await fetch(`/auth/api/user/credential/${uuid}`, {method: 'Delete'})
      const result = await response.json()
      if (result.detail) throw new Error(`Server: ${result.detail}`)

      await this.loadUserInfo()
    },
    async terminateSession(sessionId) {
      try {
        const res = await fetch(`/auth/api/user/session/${sessionId}`, { method: 'DELETE' })
        let payload = null
        try {
          payload = await res.json()
        } catch (_) {
          // ignore JSON parse errors
        }
        if (!res.ok || payload?.detail) {
          const message = payload?.detail || 'Failed to terminate session'
          throw new Error(message)
        }
        if (payload?.current_session_terminated) {
          sessionStorage.clear()
          location.reload()
          return
        }
        await this.loadUserInfo()
        this.showMessage('Session terminated', 'success', 2500)
      } catch (error) {
        console.error('Terminate session error:', error)
        throw error
      }
    },
    async logout() {
      try {
        const res = await fetch('/auth/api/logout', {method: 'POST'})
        if (!res.ok) {
          let message = 'Logout failed'
          try {
            const data = await res.json()
            if (data?.detail) message = data.detail
          } catch (_) {
            // ignore JSON parse errors
          }
          throw new Error(message)
        }
        sessionStorage.clear()
        location.reload()
      } catch (error) {
        console.error('Logout error:', error)
        this.showMessage(error.message, 'error')
      }
    },
    async logoutEverywhere() {
      try {
        const res = await fetch('/auth/api/user/logout-all', {method: 'POST'})
        if (!res.ok) {
          let message = 'Logout failed'
          try {
            const data = await res.json()
            if (data?.detail) message = data.detail
          } catch (_) {
            // ignore JSON parse errors
          }
          throw new Error(message)
        }
        sessionStorage.clear()
        location.reload()
      } catch (error) {
        console.error('Logout-all error:', error)
        this.showMessage(error.message, 'error')
      }
    },
  }
})
