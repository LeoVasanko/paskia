// Early theme override script - runs before Vue to prevent flicker
// Parses ?theme=light or ?theme=dark from URL hash and injects CSS overrides

const themeColors = {
  light: {
    'color-canvas': '#ffffff',
    'color-surface': '#eff6ff',
    'color-surface-subtle': '#dbeafe',
    'color-border': '#2563eb',
    'color-border-strong': '#1e40af',
    'color-heading': '#1e3a8a',
    'color-text': '#1e293b',
    'color-text-muted': '#475569',
    'color-link': '#1d4ed8',
    'color-link-hover': '#1e40af',
    'color-accent': '#2563eb',
    'color-accent-strong': '#1e40af',
    'color-accent-contrast': '#ffffff',
    'color-success-text': '#166534',
    'color-success-bg': '#dcfce7',
    'color-error-text': '#b91c1c',
    'color-error-bg': '#fee2e2',
    'color-info-text': '#1e40af',
    'color-info-bg': '#dbeafe',
    'color-danger': '#dc2626',
    'shadow-soft': '0 10px 30px rgba(30, 64, 175, 0.15)',
  },
  dark: {
    'color-canvas': '#0f172a',
    'color-surface': '#141b2f',
    'color-surface-subtle': '#1b243b',
    'color-border': '#25304a',
    'color-border-strong': '#3d4d6b',
    'color-heading': '#fff',
    'color-text': '#e2e8f0',
    'color-text-muted': '#94a3b8',
    'color-link': '#60a5fa',
    'color-link-hover': '#93c5fd',
    'color-accent': '#60a5fa',
    'color-accent-strong': '#3b82f6',
    'color-accent-contrast': '#0b1120',
    'color-success-text': '#34d399',
    'color-success-bg': '#1a4d2e',
    'color-error-text': '#fca5a5',
    'color-error-bg': '#4a1f1f',
    'color-info-text': '#bae6fd',
    'color-info-bg': '#1e3a5f',
    'color-danger': '#f87171',
    'shadow-soft': '0 0 0 #000000',
  }
}

const STYLE_ID = 'theme-override'

function applyTheme() {
  const params = new URLSearchParams(location.hash.slice(1))
  const theme = params.get('theme')

  // Remove existing override
  document.getElementById(STYLE_ID)?.remove()

  if (theme && themeColors[theme]) {
    const css = `.surface { ${Object.entries(themeColors[theme]).map(([k, v]) => `--${k}: ${v}`).join('; ')}; }`
    const style = document.createElement('style')
    style.id = STYLE_ID
    style.textContent = css
    document.head.appendChild(style)
  }
}

applyTheme()
addEventListener('hashchange', applyTheme)
