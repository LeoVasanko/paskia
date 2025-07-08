// Shared utility functions for all views

// Initialize the app based on current page
function initializeApp() {
  checkExistingSession()
}

// Show status message
function showStatus(elementId, message, type = 'info') {
  const statusEl = document.getElementById(elementId)
  if (statusEl) {
    statusEl.innerHTML = `<div class="status ${type}">${message}</div>`
  }
}

// Clear status message
function clearStatus(elementId) {
  const statusEl = document.getElementById(elementId)
  if (statusEl) {
    statusEl.innerHTML = ''
  }
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
        try {
          await loadUserInfo()
          updateUserInfo()
          await loadCredentials()
        } catch (error) {
          showStatus('profileStatus', `Failed to load user info: ${error.message}`, 'error')
        }
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

// Validate stored token
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

// Copy device link to clipboard
async function copyDeviceLink() {
  try {
    if (window.currentDeviceLink) {
      await navigator.clipboard.writeText(window.currentDeviceLink)
      
      const copyButton = document.querySelector('.copy-button')
      if (copyButton) {
        const originalText = copyButton.textContent
        copyButton.textContent = 'Copied!'
        copyButton.style.background = '#28a745'
        
        setTimeout(() => {
          copyButton.textContent = originalText
          copyButton.style.background = '#28a745'
        }, 2000)
      }
    }
  } catch (error) {
    console.error('Failed to copy link:', error)
    const linkText = document.getElementById('deviceLinkText')
    if (linkText) {
      const range = document.createRange()
      range.selectNode(linkText)
      window.getSelection().removeAllRanges()
      window.getSelection().addRange(range)
    }
  }
}
