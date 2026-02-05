// Theme override utilities - shared across apps
// User preference or URL hash can force light/dark mode

const TRANSITION_ID = 'theme-transition'
const STORAGE_KEY = 'paskia-theme'

/** Apply theme by setting class on documentElement */
export function applyTheme(theme, element = document.documentElement, animate = false) {
  // Add temporary transition for smooth theme change
  if (animate) {
    let transitionStyle = document.getElementById(TRANSITION_ID)
    if (!transitionStyle) {
      transitionStyle = document.createElement('style')
      transitionStyle.id = TRANSITION_ID
      transitionStyle.textContent = '*, *::before, *::after { transition: background-color 0.3s, color 0.3s, border-color 0.3s, box-shadow 0.3s !important; }'
      document.head.appendChild(transitionStyle)
    }
    setTimeout(() => document.getElementById(TRANSITION_ID)?.remove(), 350)
  }
  // If no explicit theme, check system preference
  const isDark = theme === 'dark' || (theme !== 'light' && matchMedia('(prefers-color-scheme:dark)').matches)
  element.classList.toggle('dark', isDark)
}

/** Get theme from localStorage cache */
export function getCachedTheme() {
  return localStorage.getItem(STORAGE_KEY) || ''
}

/** Cache theme in localStorage */
export function setCachedTheme(theme) {
  if (theme) localStorage.setItem(STORAGE_KEY, theme)
  else localStorage.removeItem(STORAGE_KEY)
}

/** Initialize theme from user preference (with localStorage cache for fast load) */
export function initThemeFromCache() {
  applyTheme(getCachedTheme())
}

/** Update theme from session context (call after login/session load) */
export function updateThemeFromSession(ctx, animate = false) {
  const theme = ctx?.user?.theme || ''
  setCachedTheme(theme)
  applyTheme(theme, document.documentElement, animate)
}
