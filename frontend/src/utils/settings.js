let _settingsPromise = null
let _settings = null

export function getSettingsCached() { return _settings }

export async function getSettings() {
  if (_settings) return _settings
  if (_settingsPromise) return _settingsPromise
  _settingsPromise = fetch('/auth/api/settings')
    .then(r => (r.ok ? r.json() : {}))
    .then(obj => { _settings = obj || {}; return _settings })
    .catch(() => { _settings = {}; return _settings })
  return _settingsPromise
}

export function uiBasePath() {
  const base = _settings?.ui_base_path || '/auth/'
  if (base === '/') return '/'
  return base.endsWith('/') ? base : base + '/'
}

export function adminUiPath() { return uiBasePath() === '/' ? '/admin/' : uiBasePath() + 'admin/' }

export function makeUiHref(suffix = '') {
  const trimmed = suffix.startsWith('/') ? suffix.slice(1) : suffix
  if (!trimmed) return uiBasePath()
  if (uiBasePath() === '/') return '/' + trimmed
  return uiBasePath() + trimmed
}