// Early theme for restricted app - user preference (localStorage) wins, then URL param
import { applyTheme, getCachedTheme } from '@/utils/theme.js'

function getTheme() {
  const params = new URLSearchParams(location.hash.slice(1))
  return getCachedTheme() || params.get('theme') || ''
}

// Apply theme class to document root
applyTheme(getTheme())
addEventListener('hashchange', () => applyTheme(getTheme()))
