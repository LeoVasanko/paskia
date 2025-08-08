import { defineStore } from 'pinia'
import { register, authenticate } from '@/utils/passkey'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    // Auth State
    userInfo: null, // Contains the full user info response: {user, credentials, aaguid_info, session_type, authenticated}
    isLoading: false,

    // UI State
    currentView: 'login', // 'login', 'profile', 'device-link', 'reset'
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

        return result
      } finally {
        this.isLoading = false
      }
    },
    selectView() {
      if (!this.userInfo) this.currentView = 'login'
      else if (this.userInfo.authenticated) this.currentView = 'profile'
      else this.currentView = 'reset'
    },
    async loadUserInfo() {
      const response = await fetch('/auth/user-info', {method: 'POST'})
      const result = await response.json()
      if (result.detail) throw new Error(`Server: ${result.detail}`)
      this.userInfo = result
      console.log('User info loaded:', result)
    },
    async deleteCredential(uuid) {
      const response = await fetch(`/auth/credential/${uuid}`, {method: 'Delete'})
      const result = await response.json()
      if (result.detail) throw new Error(`Server: ${result.detail}`)

      await this.loadUserInfo()
    },
    async logout() {
      try {
        await fetch('/auth/logout', {method: 'POST'})
      } catch (error) {
        console.error('Logout error:', error)
      }

      this.userInfo = null
    },
  }
})
