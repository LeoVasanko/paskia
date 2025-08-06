import { defineStore } from 'pinia'
import { registerUser, authenticateUser, registerWithToken } from '@/utils/passkey'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    // Auth State
    userInfo: null, // Contains the full user info response: {user, credentials, aaguid_info, session_type, authenticated}
    isLoading: false,

    // UI State
    currentView: 'login', // 'login', 'register', 'profile', 'reset'
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
    async register(user_name) {
      this.isLoading = true
      try {
        const result = await registerUser(user_name)

        this.userInfo = {
          user: {
            user_id: result.user_id,
            user_name: user_name,
          },
          credentials: [],
          aaguid_info: {},
          session_type: null,
          authenticated: false
        }

        await this.setSessionCookie(result.session_token)
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
