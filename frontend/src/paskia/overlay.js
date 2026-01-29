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
  -webkit-backdrop-filter: blur(.2rem) brightness(0.5);
  backdrop-filter: blur(.2rem) brightness(0.5);
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
`

let authIframe = null
let authPromise = null
let authResolve = null
let authReject = null
let messageListenerInstalled = false
let backdropHolders = 0

function injectStyles() {
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

export function holdGlobalBackdrop() {
  backdropHolders++
  document.body.classList.add('paskia-backdrop')
}

export function releaseGlobalBackdrop() {
  backdropHolders = Math.max(0, backdropHolders - 1)
  if (backdropHolders === 0) {
    document.body.classList.remove('paskia-backdrop')
  }
}

export function isAuthIframeOpen() {
  return !!document.getElementById(AUTH_IFRAME_ID)
}

export function hideAuthIframe() {
  if (authIframe) {
    authIframe.remove()
    authIframe = null
    releaseGlobalBackdrop()
  }
}

function handleAuthMessage(event) {
  const data = event.data
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
      if (authReject) {
        authReject(new AuthCancelledError())
        authPromise = null
        authResolve = null
        authReject = null
      }
      break
  }
}

function ensureMessageListener() {
  if (messageListenerInstalled) return
  if (typeof window !== 'undefined') {
    window.addEventListener('message', handleAuthMessage)
    messageListenerInstalled = true
  }
}

export function showAuthIframe(iframeUrl, title = 'Authentication') {
  injectStyles()
  ensureMessageListener()

  if (authPromise) return authPromise

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
  authIframe.title = title
  authIframe.src = iframeUrl
  document.body.appendChild(authIframe)

  return authPromise
}

export function createAuthIframe(iframeUrl, title = 'Authentication') {
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

export function removeAuthIframe() {
  const iframe = document.getElementById(AUTH_IFRAME_ID)
  if (iframe) iframe.remove()
}
