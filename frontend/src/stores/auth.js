import { defineStore } from 'pinia'
import { register, authenticate } from '@/utils/passkey'
import { getSettings } from '@/utils/settings'
import { apiJson } from '@/paskia/fetch'

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
    showMessage(message, type = 'info', duration = null) {
      // Default duration: 5 seconds for errors, 3 seconds for others
      const effectiveDuration = duration ?? (type === 'error' ? 5000 : 3000)
      this.status = {
        message,
        type,
        show: true
      }
      if (effectiveDuration > 0) {
        setTimeout(() => {
          this.status.show = false
        }, effectiveDuration)
      }
    },
    async setSessionCookie(result) {
      if (!result?.session_token) {
        console.error('setSessionCookie called with missing session_token:', result)
        throw new Error('Authentication response missing session_token')
      }
      return await apiJson('/auth/api/set-session', {
        method: 'POST',
        headers: {'Authorization': `Bearer ${result.session_token}`},
      })
    },
    async register() {
      this.isLoading = true
      try {
        const result = await register()
        await this.setSessionCookie(result)
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

        await this.setSessionCookie(result)
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
      try {
        this.userInfo = await apiJson('/auth/api/user-info', { method: 'POST' })
        console.log('User info loaded:', this.userInfo)
      } catch (error) {
        // Suppress toast for 401/403 errors - the auth iframe will handle these
        if (error.status === 401 || error.status === 403) {
          console.log('Authentication required:', error.message)
        } else {
          this.showMessage(error.message || 'Failed to load user info', 'error', 5000)
        }
        throw error
      }
    },
    async deleteCredential(uuid) {
      await apiJson(`/auth/api/user/credential/${uuid}`, { method: 'DELETE' })
      await this.loadUserInfo()
    },
    async terminateSession(sessionId) {
      try {
        const payload = await apiJson(`/auth/api/user/session/${sessionId}`, { method: 'DELETE' })
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
        await apiJson('/auth/api/logout', {method: 'POST'})
        sessionStorage.clear()
        location.reload()
      } catch (error) {
        console.error('Logout error:', error)
        // Suppress toast for 401/403 errors - the auth iframe will handle these
        if (error.status !== 401 && error.status !== 403) {
          this.showMessage(error.message, 'error')
        }
      }
    },
    async logoutEverywhere() {
      try {
        await apiJson('/auth/api/user/logout-all', {method: 'POST'})
        sessionStorage.clear()
        location.reload()
      } catch (error) {
        console.error('Logout-all error:', error)
        // Suppress toast for 401/403 errors - the auth iframe will handle these
        if (error.status !== 401 && error.status !== 403) {
          this.showMessage(error.message, 'error')
        }
      }
    },
  }
})
