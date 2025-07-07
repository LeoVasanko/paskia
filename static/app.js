const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser

// Global state
let currentUser = null
let currentCredentials = []
let aaguidInfo = {}

// Session management - now using HTTP-only cookies
async function validateStoredToken() {
  try {
    const response = await fetch('/api/validate-token', {
      method: 'GET',
      credentials: 'include'
    })
    
    const result = await response.json()
    
    if (result.status === 'success') {
      return true
    } else {
      return false
    }
  } catch (error) {
    return false
  }
}

// Helper function to set session cookie using JWT token
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

// View management
function showView(viewId) {
  document.querySelectorAll('.view').forEach(view => view.classList.remove('active'))
  document.getElementById(viewId).classList.add('active')
}

function showLoginView() {
  showView('loginView')
  clearStatus('loginStatus')
}

function showRegisterView() {
  showView('registerView')
  clearStatus('registerStatus')
}

// Update dashboard view to load user info
function showDashboardView() {
  showView('dashboardView')
  clearStatus('dashboardStatus')
  loadUserInfo().then(() => {
    updateUserInfo()
    loadCredentials()
  }).catch(error => {
    showStatus('dashboardStatus', `Failed to load user info: ${error.message}`, 'error')
  })
}

// Status management
function showStatus(elementId, message, type = 'info') {
  const statusEl = document.getElementById(elementId)
  statusEl.innerHTML = `<div class="status ${type}">${message}</div>`
}

function clearStatus(elementId) {
  document.getElementById(elementId).innerHTML = ''
}

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
    showStatus('dashboardStatus', 'Loading credentials...', 'info')
    
    const response = await fetch('/api/user-credentials', {
      method: 'GET',
      credentials: 'include'
    })
    
    const result = await response.json()
    if (result.error) throw new Error(`Server: ${result.error}`)
    
    currentCredentials = result.credentials
    aaguidInfo = result.aaguid_info || {}
    updateCredentialList()
    clearStatus('dashboardStatus')
  } catch (error) {
    showStatus('dashboardStatus', `Failed to load credentials: ${error.message}`, 'error')
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
  showLoginView()
}

// Check if user is already logged in on page load
async function checkExistingSession() {
  if (await validateStoredToken()) {
    showDashboardView()
  } else {
    showLoginView()
  }
}

// Add new credential for logged-in user
async function addNewCredential() {
  try {
    showStatus('dashboardStatus', 'Starting new passkey registration...', 'info')
    
    const ws = await aWebSocket('/ws/add_credential')
    
    // Registration chat - no need to send user data since we're authenticated
    const optionsJSON = JSON.parse(await ws.recv())
    if (optionsJSON.error) throw new Error(optionsJSON.error)
    
    showStatus('dashboardStatus', 'Save new passkey to your authenticator...', 'info')
    
    const registrationResponse = await startRegistration({optionsJSON})
    ws.send(JSON.stringify(registrationResponse))
    
    const result = JSON.parse(await ws.recv())
    if (result.error) throw new Error(`Server: ${result.error}`)
    
    ws.close()
    
    showStatus('dashboardStatus', 'New passkey added successfully!', 'success')
    
    // Refresh credentials list to show the new credential
    await loadCredentials()
    clearStatus('dashboardStatus')
    
  } catch (error) {
    showStatus('dashboardStatus', 'Registration cancelled', 'error')
  }
}

// Delete credential
async function deleteCredential(credentialId) {
  if (!confirm('Are you sure you want to delete this passkey? This action cannot be undone.')) {
    return
  }

  try {
    showStatus('dashboardStatus', 'Deleting passkey...', 'info')
    
    const response = await fetch('/api/delete-credential', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify({
        credential_id: credentialId
      })
    })
    
    const result = await response.json()
    
    if (result.error) {
      throw new Error(result.error)
    }
    
    showStatus('dashboardStatus', 'Passkey deleted successfully!', 'success')
    
    // Refresh credentials list
    await loadCredentials()
    clearStatus('dashboardStatus')
    
  } catch (error) {
    showStatus('dashboardStatus', `Failed to delete passkey: ${error.message}`, 'error')
  }
}

// Form event handlers
document.addEventListener('DOMContentLoaded', function() {
  // Check for existing session on page load
  checkExistingSession()
  
  // Registration form
  const regForm = document.getElementById('registrationForm')
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
        showDashboardView()
      }, 1500)
    } catch (err) {
      showStatus('registerStatus', `Registration failed: ${err.message}`, 'error')
    } finally {
      regSubmitBtn.disabled = false
    }
  })

  // Authentication form
  const authForm = document.getElementById('authenticationForm')
  const authSubmitBtn = authForm.querySelector('button[type="submit"]')
  
  authForm.addEventListener('submit', async (ev) => {
    ev.preventDefault()
    authSubmitBtn.disabled = true
    clearStatus('loginStatus')
    
    try {
      showStatus('loginStatus', 'Starting authentication...', 'info')
      await authenticate()
      showStatus('loginStatus', 'Authentication successful!', 'success')
      
      // Navigate to dashboard
      setTimeout(() => {
        showDashboardView()
      }, 1000)
    } catch (err) {
      showStatus('loginStatus', `Authentication failed: ${err.message}`, 'error')
    } finally {
      authSubmitBtn.disabled = false
    }
  })
})
