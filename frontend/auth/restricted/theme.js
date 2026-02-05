// Early theme for restricted app - first URL param wins, then localStorage
import { applyTheme, getCachedTheme } from '@/utils/theme.js'

function getTheme() {
  const params = new URLSearchParams(location.hash.slice(1))
  return params.get('theme') || getCachedTheme() || ''
}

// Apply theme class to document root
applyTheme(getTheme())
addEventListener('hashchange', () => applyTheme(getTheme()))
