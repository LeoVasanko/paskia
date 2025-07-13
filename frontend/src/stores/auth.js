import { defineStore } from 'pinia'
import { registerUser, authenticateUser, registerWithToken } from '@/utils/passkey'
import aWebSocket from '@/utils/awaitable-websocket'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    // Auth State
    currentUser: null,
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
    async validateStoredToken() {
      try {
        const response = await fetch('/auth/validate-token')
        const result = await response.json()
        return result.status === 'success'
      } catch (error) {
        return false
      }
    },
    async setSessionCookie(sessionToken) {
      const response = await fetch('/auth/set-session', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${sessionToken}`,
          'Content-Type': 'application/json'
        },
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
      const response = await fetch('/auth/user-info')
      const result = await response.json()
      if (result.error) throw new Error(`Server: ${result.error}`)

      this.currentUser = result.user
    },
    async loadCredentials() {
      this.isLoading = true
      try {
        const response = await fetch('/auth/user-credentials')
        const result = await response.json()
        if (result.error) throw new Error(`Server: ${result.error}`)

        this.currentCredentials = result.credentials
        this.aaguidInfo = result.aaguid_info || {}
      } finally {
        this.isLoading = false
      }
    },
    async addNewCredential() {
      this.isLoading = true;
      try {
        const result = await registerWithToken()
        await this.loadCredentials()
        return result;
      } catch (error) {
        throw new Error(`Failed to add new credential: ${error.message}`)
      } finally {
        this.isLoading = false
      }
    },
    async deleteCredential(credentialId) {
      const response = await fetch('/auth/delete-credential', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ credential_id: credentialId })
      })
      const result = await response.json()
      if (result.error) throw new Error(`Server: ${result.error}`)

      await this.loadCredentials()
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
    async checkResetCookieAndRegister() {
      const passphrase = getCookie('reset')
      if (passphrase) {
        // Abandon existing session
        await fetch('/auth/logout', { method: 'POST', credentials: 'include' })

        // Register additional token for the user
        try {
          const result = await registerUserFromCookie()
          await this.setSessionCookie(result.session_token)
          this.currentUser = {
            user_id: result.user_id,
            user_name: result.user_name,
          }
        } catch (error) {
          console.error('Failed to register additional token:', error)
        }
      }
    },
  }
})
