// Early theme for restricted app - first URL param wins, then localStorage
import { themeColors, applyTheme, getCachedTheme } from '@/utils/theme.js'

function getTheme() {
  const params = new URLSearchParams(location.hash.slice(1))
  return params.get('theme') || getCachedTheme() || ''
}

// Use .surface selector to preserve transparent background
applyTheme(getTheme(), '.surface')
addEventListener('hashchange', () => applyTheme(getTheme(), '.surface'))
