const AUTH_IFRAME_ID = 'paskia-iframe'
const STYLES_ID = 'paskia-dialog'
const STYLES_TEXT = `\
body::before {
  content: '';
  position: fixed;
  inset: 0;
  z-index: 1099;
  background: transparent;
  backdrop-filter: blur(0) brightness(1);
  -webkit-backdrop-filter: blur(0) brightness(1);
  pointer-events: none;
  visibility: hidden;
  transition: all 0.2s ease-out;
}
body.paskia-backdrop::before {
  backdrop-filter: blur(.2rem) brightness(0.7);
  -webkit-backdrop-filter: blur(.2rem) brightness(0.7);
  visibility: visible;
}
body.paskia-backdrop {
  overflow: auto;
}
#${AUTH_IFRAME_ID} {
  border: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: 9999;
  color-scheme: auto;
  background: transparent;
}
#${AUTH_IFRAME_ID}.paskia-dialog {
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: min(36rem, 100%);
  height: min(42rem, 100%);
}
`

type DialogResult = 'logout' | 'back'

let authIframe: HTMLIFrameElement | null = null
let authPromise: Promise<DialogResult | undefined> | null = null
let authResolve: ((result?: DialogResult) => void) | null = null
let authReject: ((error: Error) => void) | null = null
// Auth flows reject AuthCancelledError on auth-back (callers rely on it to
// abort request retries); the profile dialog resolves 'back' instead.
let cancelAsError = true
let messageListenerInstalled = false
let backdropHolders = 0

function injectStyles(): void {
  if (document.getElementById(STYLES_ID)) return
  const style = document.createElement('style')
  style.id = STYLES_ID
  style.textContent = STYLES_TEXT
  document.head.insertBefore(style, document.head.firstChild)
}

export class AuthCancelledError extends Error {
  constructor() {
    super('Authentication cancelled')
    this.name = 'AuthCancelledError'
  }
}

export function holdGlobalBackdrop(): void {
  injectStyles()
  backdropHolders++
  document.body.classList.add('paskia-backdrop')
}

export function releaseGlobalBackdrop(): void {
  backdropHolders = Math.max(0, backdropHolders - 1)
  if (backdropHolders === 0) {
    document.body.classList.remove('paskia-backdrop')
  }
}

export function isAuthIframeOpen(): boolean {
  return !!document.getElementById(AUTH_IFRAME_ID)
}

export function hideAuthIframe(): void {
  if (authIframe) {
    authIframe.remove()
    authIframe = null
    releaseGlobalBackdrop()
  }
}

function handleAuthMessage(event: MessageEvent): void {
  const data = event.data as { type?: string }
  if (!data?.type) return

  switch (data.type) {
    case 'auth-success':
      hideAuthIframe()
      if (authResolve) {
        authResolve()
        authPromise = null
        authResolve = null
        authReject = null
      }
      break

    case 'auth-back':
      hideAuthIframe()
      if (cancelAsError && authReject) {
        authReject(new AuthCancelledError())
      } else if (authResolve) {
        authResolve('back')
      }
      authPromise = null
      authResolve = null
      authReject = null
      break

    case 'auth-logout':
      hideAuthIframe()
      if (authResolve) {
        authResolve('logout')
        authPromise = null
        authResolve = null
        authReject = null
      }
      break
  }
}

function ensureMessageListener(): void {
  if (messageListenerInstalled) return
  if (typeof window !== 'undefined') {
    window.addEventListener('message', handleAuthMessage)
    messageListenerInstalled = true
  }
}

function openIframe(iframeUrl: string, title: string, dialog: boolean, cancelError: boolean): Promise<DialogResult | undefined> {
  injectStyles()
  ensureMessageListener()

  if (authPromise) return authPromise

  cancelAsError = cancelError
  iframeUrl = withAppTheme(iframeUrl)

  if (document.getElementById(AUTH_IFRAME_ID)) {
    authPromise = new Promise((resolve, reject) => {
      authResolve = resolve
      authReject = reject
    })
    return authPromise
  }

  authPromise = new Promise((resolve, reject) => {
    authResolve = resolve
    authReject = reject
  })

  hideAuthIframe()
  holdGlobalBackdrop()

  authIframe = document.createElement('iframe')
  authIframe.id = AUTH_IFRAME_ID
  if (dialog) authIframe.classList.add('paskia-dialog')
  authIframe.title = title
  authIframe.src = iframeUrl
  document.body.appendChild(authIframe)

  return authPromise
}

// Detect the host page's own color scheme (CSS color-scheme on body) as an
// implicit app-level default. Only an unambiguous 'light' or 'dark' counts;
// 'normal', 'light dark' etc. mean the page adapts, so no override is needed.
function detectColorScheme(): string {
  if (typeof window === 'undefined' || !document.body) return ''
  const scheme = getComputedStyle(document.body).colorScheme
  return scheme === 'light' || scheme === 'dark' ? scheme : ''
}

// Apply the host page's own color scheme to the iframe URL hash — only when
// the URL has no theme parameter yet (a server-provided user theme override
// is authoritative). The restricted UI's precedence is: URL parameter (user
// override from the server, else host color scheme) > cached profile theme
// (localStorage) > browser/desktop default.
function withAppTheme(iframeUrl: string): string {
  const theme = detectColorScheme()
  if (!theme) return iframeUrl
  const hashIndex = iframeUrl.indexOf('#')
  const base = hashIndex === -1 ? iframeUrl : iframeUrl.slice(0, hashIndex)
  const params = new URLSearchParams(hashIndex === -1 ? '' : iframeUrl.slice(hashIndex + 1))
  if (params.has('theme')) return iframeUrl
  params.set('theme', theme)
  return `${base}#${params}`
}

export function showAuthIframe(iframeUrl: string, title = 'Authentication'): Promise<void> {
  return openIframe(iframeUrl, title, false, true).then(() => undefined)
}

/**
 * Show the minimal profile of the logged-in user in a compact dialog iframe.
 *
 * Unlike the auth flows, this always resolves — 'logout' when the user
 * signed out inside the frame, 'back' when they closed it without action.
 * The caller decides from context how to react to each (e.g. whether to
 * start a new login attempt with showAuthIframe).
 */
export function profile(): Promise<DialogResult> {
  return openIframe('/auth/restricted/iframe#mode=profile', 'Profile', true, false)
    .then((result) => result ?? 'back')
}

export function createAuthIframe(iframeUrl: string, title = 'Authentication'): HTMLIFrameElement {
  injectStyles()
  const existing = document.getElementById(AUTH_IFRAME_ID)
  if (existing) existing.remove()

  const iframe = document.createElement('iframe')
  iframe.id = AUTH_IFRAME_ID
  iframe.title = title
  iframe.src = iframeUrl
  document.body.appendChild(iframe)

  return iframe
}

export function removeAuthIframe(): void {
  const iframe = document.getElementById(AUTH_IFRAME_ID)
  if (iframe) iframe.remove()
}
