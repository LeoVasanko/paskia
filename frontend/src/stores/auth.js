import { defineStore } from 'pinia'
import { register, authenticate } from '@/utils/passkey'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    // Auth State
    userInfo: null, // Contains the full user info response: {user, credentials, aaguid_info, session_type, authenticated}
    settings: null, // Server provided settings (/auth/settings)
    isLoading: false,

    // UI State
    currentView: 'login',
    status: {
      message: '',
      type: 'info',
      show: false
    },
  }),
  getters: {
    uiBasePath(state) {
      const configured = state.settings?.ui_base_path || '/auth/'
      if (!configured.endsWith('/')) return `${configured}/`
      return configured
    },
    adminUiPath() {
      const base = this.uiBasePath
      return base === '/' ? '/admin/' : `${base}admin/`
    },
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
    uiHref(suffix = '') {
      const trimmed = suffix.startsWith('/') ? suffix.slice(1) : suffix
      if (!trimmed) return this.uiBasePath
      if (this.uiBasePath === '/') return `/${trimmed}`
      return `${this.uiBasePath}${trimmed}`
    },
    adminHomeHref() {
      return this.adminUiPath
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
      else if (this.userInfo.authenticated) this.currentView = 'profile'
      else this.currentView = 'login'
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
    async loadSettings() {
      try {
  const res = await fetch('/auth/api/settings')
        if (!res.ok) return
        const data = await res.json()
        this.settings = data
        if (data?.rp_name) {
          document.title = data.rp_name
        }
      } catch (_) {
        // ignore
      }
    },
    async deleteCredential(uuid) {
  const response = await fetch(`/auth/api/credential/${uuid}`, {method: 'Delete'})
      const result = await response.json()
      if (result.detail) throw new Error(`Server: ${result.detail}`)

      await this.loadUserInfo()
    },
    async logout() {
      try {
        await fetch('/auth/api/logout', {method: 'POST'})
        sessionStorage.clear()
        location.reload()
      } catch (error) {
        console.error('Logout error:', error)
        this.showMessage(error.message, 'error')
      }
    },
  }
})
