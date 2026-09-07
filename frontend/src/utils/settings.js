let _settingsPromise = null
let _settings = null
let _requestGen = 0

export function getSettingsCached() { return _settings }

export async function getSettings(force = false) {
  if (force) { _settings = null; _settingsPromise = null; _requestGen++ }
  if (_settings) return _settings
  if (_settingsPromise) return _settingsPromise
  const gen = _requestGen
  const stale = () => getSettings() // superseded by a force reset: defer to the fresh state
  _settingsPromise = fetch('/auth/api/settings')
    .then(r => (r.ok ? r.json() : {}))
    .then(obj => gen === _requestGen ? (_settings = obj || {}) : stale())
    .catch(() => gen === _requestGen ? (_settings = {}) : stale())
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