const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser

// Global state
let currentUser = null
let currentCredentials = []
let aaguidInfo = {}

// ========================================
// Session Management
// ========================================

async function validateStoredToken() {
  try {
    const response = await fetch('/api/validate-token', {
      method: 'GET',
      credentials: 'include'
    })
    
    const result = await response.json()
    return result.status === 'success'
  } catch (error) {
    return false
  }
}

async function setSessionCookie(sessionToken) {
  try {
    const response = await fetch('/api/set-session', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${sessionToken}`,
        'Content-Type': 'application/json'
      },
      credentials: 'include'
    })
    
    const result = await response.json()
    if (result.error) {
      throw new Error(result.error)
    }
    
    return result
  } catch (error) {
    throw new Error(`Failed to set session cookie: ${error.message}`)
  }
}

// ========================================
// View Management
// ========================================

function showView(viewId) {
  document.querySelectorAll('.view').forEach(view => view.classList.remove('active'))
  const targetView = document.getElementById(viewId)
  if (targetView) {
    targetView.classList.add('active')
  }
}

function showLoginView() {
  if (window.location.pathname !== '/auth/login') {
    window.location.href = '/auth/login'
    return
  }
  showView('loginView')
  clearStatus('loginStatus')
}

function showRegisterView() {
  if (window.location.pathname !== '/auth/register') {
    window.location.href = '/auth/register'
    return
  }
  showView('registerView')
  clearStatus('registerStatus')
}

function showDeviceAdditionView() {
  // This function is no longer needed as device addition is now a dialog
  // Redirect to profile page if someone tries to access the old route
  if (window.location.pathname === '/auth/add-device') {
    window.location.href = '/auth/profile'
    return
  }
}

function showDashboardView() {
  if (window.location.pathname !== '/auth/profile') {
    window.location.href = '/auth/profile'
    return
  }
  showView('profileView')
  clearStatus('profileStatus')
  loadUserInfo().then(() => {
    updateUserInfo()
    loadCredentials()
  }).catch(error => {
    showStatus('profileStatus', `Failed to load user info: ${error.message}`, 'error')
  })
}

// ========================================
// Status Management
// ========================================

function showStatus(elementId, message, type = 'info') {
  const statusEl = document.getElementById(elementId)
  statusEl.innerHTML = `<div class="status ${type}">${message}</div>`
}

function clearStatus(elementId) {
  document.getElementById(elementId).innerHTML = ''
}

// ========================================
// Device Addition & QR Code
// ========================================

async function copyDeviceLink() {
  try {
    if (window.currentDeviceLink) {
      await navigator.clipboard.writeText(window.currentDeviceLink)
      
      const copyButton = document.querySelector('.copy-button')
      const originalText = copyButton.textContent
      copyButton.textContent = 'Copied!'
      copyButton.style.background = '#28a745'
      
      setTimeout(() => {
        copyButton.textContent = originalText
        copyButton.style.background = '#28a745'
      }, 2000)
    }
  } catch (error) {
    console.error('Failed to copy link:', error)
    const linkText = document.getElementById('deviceLinkText')
    const range = document.createRange()
    range.selectNode(linkText)
    window.getSelection().removeAllRanges()
    window.getSelection().addRange(range)
  }
}

// ========================================
// WebAuthn Operations
// ========================================

async function register(user_name) {
  const ws = await aWebSocket('/ws/new_user_registration')
  
  ws.send(JSON.stringify({ user_name }))
  
  const optionsJSON = JSON.parse(await ws.recv())
  if (optionsJSON.error) throw new Error(optionsJSON.error)
  
  const registrationResponse = await startRegistration({ optionsJSON })
  ws.send(JSON.stringify(registrationResponse))
  
  const result = JSON.parse(await ws.recv())
  if (result.error) throw new Error(`Server: ${result.error}`)
  
  await setSessionCookie(result.session_token)
  ws.close()
}

async function authenticate() {
  const ws = await aWebSocket('/ws/authenticate')
  
  const optionsJSON = JSON.parse(await ws.recv())
  if (optionsJSON.error) throw new Error(optionsJSON.error)
  
  const authenticationResponse = await startAuthentication({ optionsJSON })
  ws.send(JSON.stringify(authenticationResponse))
  
  const result = JSON.parse(await ws.recv())
  if (result.error) throw new Error(`Server: ${result.error}`)
  
  await setSessionCookie(result.session_token)
  ws.close()
}

async function addNewCredential() {
  try {
    showStatus('dashboardStatus', 'Adding new passkey...', 'info')
    
    const ws = await aWebSocket('/ws/add_credential')
    
    const optionsJSON = JSON.parse(await ws.recv())
    if (optionsJSON.error) throw new Error(optionsJSON.error)
    
    const registrationResponse = await startRegistration({ optionsJSON })
    ws.send(JSON.stringify(registrationResponse))
    
    const result = JSON.parse(await ws.recv())
    if (result.error) throw new Error(`Server: ${result.error}`)
    
    ws.close()
    
    showStatus('dashboardStatus', 'New passkey added successfully!', 'success')
    
    setTimeout(() => {
      loadCredentials()
      clearStatus('dashboardStatus')
    }, 2000)
    
  } catch (error) {
    showStatus('dashboardStatus', `Failed to add passkey: ${error.message}`, 'error')
  }
}

// ========================================
// User Data Management
// ========================================

// User registration
async function register(user_name) {
  try {
    const ws = await aWebSocket('/ws/new_user_registration')
    ws.send(JSON.stringify({user_name}))
    
    // Registration chat
    const optionsJSON = JSON.parse(await ws.recv())
    if (optionsJSON.error) throw new Error(optionsJSON.error)
    
    showStatus('registerStatus', 'Save to your authenticator...', 'info')
    
    const registrationResponse = await startRegistration({optionsJSON})
    ws.send(JSON.stringify(registrationResponse))
    
    const result = JSON.parse(await ws.recv())
    if (result.error) throw new Error(`Server: ${result.error}`)
    
    ws.close()
    
    // Set session cookie using the JWT token
    await setSessionCookie(result.session_token)
    
    // Set current user from registration result
    currentUser = {
      user_id: result.user_id,
      user_name: user_name,
      last_seen: new Date().toISOString()
    }
    
    return result
  } catch (error) {
    throw error
  }
}

// User authentication
async function authenticate() {
  try {
    const ws = await aWebSocket('/ws/authenticate')
    const optionsJSON = JSON.parse(await ws.recv())
    if (optionsJSON.error) throw new Error(optionsJSON.error)
    
    showStatus('loginStatus', 'Please touch your authenticator...', 'info')
    
    const authResponse = await startAuthentication({optionsJSON})
    await ws.send(JSON.stringify(authResponse))
    
    const result = JSON.parse(await ws.recv())
    if (result.error) throw new Error(`Server: ${result.error}`)
    
    ws.close()
    
    // Set session cookie using the JWT token
    await setSessionCookie(result.session_token)
    
    // Authentication successful, now get user info using HTTP endpoint
    const userResponse = await fetch('/api/user-info', {
      method: 'GET',
      credentials: 'include'
    })
    
    const userInfo = await userResponse.json()
    if (userInfo.error) throw new Error(`Server: ${userInfo.error}`)
    
    currentUser = userInfo.user
    
    return result
  } catch (error) {
    throw error
  }
}

// Load user credentials
async function loadCredentials() {
  try {
    const statusElement = document.getElementById('profileStatus') ? 'profileStatus' : 'dashboardStatus'
    showStatus(statusElement, 'Loading credentials...', 'info')
    
    const response = await fetch('/api/user-credentials', {
      method: 'GET',
      credentials: 'include'
    })
    
    const result = await response.json()
    if (result.error) throw new Error(`Server: ${result.error}`)
    
    currentCredentials = result.credentials
    aaguidInfo = result.aaguid_info || {}
    updateCredentialList()
    clearStatus(statusElement)
  } catch (error) {
    const statusElement = document.getElementById('profileStatus') ? 'profileStatus' : 'dashboardStatus'
    showStatus(statusElement, `Failed to load credentials: ${error.message}`, 'error')
  }
}

// Load user info using HTTP endpoint
async function loadUserInfo() {
  try {
    const response = await fetch('/api/user-info', {
      method: 'GET',
      credentials: 'include'
    })
    
    const result = await response.json()
    if (result.error) throw new Error(`Server: ${result.error}`)
    
    currentUser = result.user
  } catch (error) {
    throw error
  }
}

// Update user info display
function updateUserInfo() {
  const userInfoEl = document.getElementById('userInfo')
  if (currentUser) {
    userInfoEl.innerHTML = `
      <h3>👤 ${currentUser.user_name}</h3>
      <p><strong>Visits:</strong> ${currentUser.visits || 0}</p>
      <p><strong>Member since:</strong> ${currentUser.created_at ? formatHumanReadableDate(currentUser.created_at) : 'N/A'}</p>
      <p><strong>Last seen:</strong> ${currentUser.last_seen ? formatHumanReadableDate(currentUser.last_seen) : 'N/A'}</p>
    `
  }
}

// Update credential list display
function updateCredentialList() {
  const credentialListEl = document.getElementById('credentialList')
  
  if (currentCredentials.length === 0) {
    credentialListEl.innerHTML = '<p>No passkeys found.</p>'
    return
  }
  
  credentialListEl.innerHTML = currentCredentials.map(cred => {
    // Get authenticator information from AAGUID
    const authInfo = aaguidInfo[cred.aaguid]
    const authName = authInfo ? authInfo.name : 'Unknown Authenticator'
    
    // Determine which icon to use based on current theme (you can implement theme detection)
    const isDarkMode = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
    const iconKey = isDarkMode ? 'icon_dark' : 'icon_light'
    const authIcon = authInfo && authInfo[iconKey] ? authInfo[iconKey] : null
    
    // Check if this is the current session credential
    const isCurrentSession = cred.is_current_session || false
    
    return `
      <div class="credential-item${isCurrentSession ? ' current-session' : ''}">
        <div class="credential-header">
          <div class="credential-icon">
            ${authIcon ? `<img src="${authIcon}" alt="${authName}" class="auth-icon" width="32" height="32">` : '<span class="auth-emoji">🔑</span>'}
          </div>
          <div class="credential-info">
            <h4>${authName}</h4>
          </div>
          <div class="credential-dates">
            <span class="date-label">Created:</span>
            <span class="date-value">${formatHumanReadableDate(cred.created_at)}</span>
            <span class="date-label">Last used:</span>
            <span class="date-value">${formatHumanReadableDate(cred.last_used)}</span>
          </div>
          <div class="credential-actions">
            <button onclick="deleteCredential('${cred.credential_id}')" 
                    class="btn-delete-credential" 
                    ${isCurrentSession ? 'disabled title="Cannot delete current session credential"' : ''}>
              🗑️
            </button>
          </div>
        </div>
      </div>
    `
  }).join('')
}

// Helper function to format dates in a human-readable way
function formatHumanReadableDate(dateString) {
  if (!dateString) return 'Never'
  
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now - date
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))
  
  if (diffHours < 1) {
    return 'Just now'
  } else if (diffHours < 24) {
    return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`
  } else if (diffDays <= 7) {
    return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`
  } else {
    // For dates older than 7 days, show just the date without time
    return date.toLocaleDateString()
  }
}

// Logout
async function logout() {
  try {
    await fetch('/api/logout', {
      method: 'POST',
      credentials: 'include'
    })
  } catch (error) {
    console.error('Logout error:', error)
  }
  
  currentUser = null
  currentCredentials = []
  aaguidInfo = {}
  window.location.href = '/auth/login'
}

// Check if user is already logged in on page load
async function checkExistingSession() {
  const isLoggedIn = await validateStoredToken()
  const path = window.location.pathname
  
  // Protected routes that require authentication
  const protectedRoutes = ['/auth/profile']
  
  if (isLoggedIn) {
    // User is logged in
    if (path === '/auth/login' || path === '/auth/register' || path === '/') {
      // Redirect to profile if accessing login/register pages while logged in
      window.location.href = '/auth/profile'
    } else if (path === '/auth/add-device') {
      // Redirect old add-device route to profile
      window.location.href = '/auth/profile'
    } else if (protectedRoutes.includes(path)) {
      // Stay on current protected page and load user data
      if (path === '/auth/profile') {
        loadUserInfo().then(() => {
          updateUserInfo()
          loadCredentials()
        }).catch(error => {
          showStatus('profileStatus', `Failed to load user info: ${error.message}`, 'error')
        })
      }
    }
  } else {
    // User is not logged in
    if (protectedRoutes.includes(path) || path === '/auth/add-device') {
      // Redirect to login if accessing protected pages without authentication
      window.location.href = '/auth/login'
    }
  }
}

// Initialize the app based on current page
function initializeApp() {
  checkExistingSession()
}

// Form event handlers
document.addEventListener('DOMContentLoaded', function() {
  // Check for existing session on page load
  initializeApp()
  
  // Registration form
  const regForm = document.getElementById('registrationForm')
  if (regForm) {
    const regSubmitBtn = regForm.querySelector('button[type="submit"]')
    
    regForm.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      regSubmitBtn.disabled = true
      clearStatus('registerStatus')
      
      const user_name = (new FormData(regForm)).get('username')
      
      try {
        showStatus('registerStatus', 'Starting registration...', 'info')
        await register(user_name)
        showStatus('registerStatus', `Registration successful for ${user_name}!`, 'success')
        
        // Auto-login after successful registration
        setTimeout(() => {
          window.location.href = '/auth/profile'
        }, 1500)
      } catch (err) {
        showStatus('registerStatus', `Registration failed: ${err.message}`, 'error')
      } finally {
        regSubmitBtn.disabled = false
      }
    })
  }

  // Authentication form
  const authForm = document.getElementById('authenticationForm')
  if (authForm) {
    const authSubmitBtn = authForm.querySelector('button[type="submit"]')
    
    authForm.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      authSubmitBtn.disabled = true
      clearStatus('loginStatus')
      
      try {
        showStatus('loginStatus', 'Starting authentication...', 'info')
        await authenticate()
        showStatus('loginStatus', 'Authentication successful!', 'success')
        
        // Navigate to profile
        setTimeout(() => {
          window.location.href = '/auth/profile'
        }, 1000)
      } catch (err) {
        showStatus('loginStatus', `Authentication failed: ${err.message}`, 'error')
      } finally {
        authSubmitBtn.disabled = false
      }
    })
  }
})
