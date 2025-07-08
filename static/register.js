// Register page specific functionality

document.addEventListener('DOMContentLoaded', function() {
  // Initialize the app
  initializeApp()
  
  // Registration form handler
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
})
