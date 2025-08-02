import { defineStore } from 'pinia'
import { registerUser, authenticateUser, registerWithToken } from '@/utils/passkey'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    // Auth State
    currentUser: null,
    currentCredentials: [],
    aaguidInfo: {},
    isLoading: false,

    // UI State
    currentView: 'login', // 'login', 'register', 'profile', 'device-link'
    status: {
      message: '',
      type: 'info',
      show: false
    },
  }),
  actions: {
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
      const response = await fetch('/auth/set-session', {
        method: 'POST',
        headers: {'Authorization': `Bearer ${sessionToken}`},
      })
      const result = await response.json()
      if (result.error) {
        throw new Error(result.error)
      }
      return result
    },
    async register(user_name) {
      this.isLoading = true
      try {
        const result = await registerUser(user_name)

        await this.setSessionCookie(result.session_token)

        this.currentUser = {
          user_id: result.user_id,
          user_name: user_name,
        }

        return result
      } finally {
        this.isLoading = false
      }
    },
    async authenticate() {
      this.isLoading = true
      try {
        const result = await authenticateUser()

        await this.setSessionCookie(result.session_token)
        await this.loadUserInfo()

        return result
      } finally {
        this.isLoading = false
      }
    },
    async loadUserInfo() {
      const response = await fetch('/auth/user-info', {method: 'POST'})
      const result = await response.json()
      if (result.error) throw new Error(`Server: ${result.error}`)

      this.currentUser = result.user
      this.currentCredentials = result.credentials || []
      this.aaguidInfo = result.aaguid_info || {}
    },
    async deleteCredential(uuid) {
      const response = await fetch(`/auth/credential/${uuid}`, {method: 'DELETE'})
      const result = await response.json()
      if (result.error) throw new Error(`Server: ${result.error}`)

      await this.loadUserInfo()
    },
    async logout() {
      try {
        await fetch('/auth/logout', {method: 'POST'})
      } catch (error) {
        console.error('Logout error:', error)
      }

      this.currentUser = null
      this.currentCredentials = []
      this.aaguidInfo = {}
    },
  }
})
