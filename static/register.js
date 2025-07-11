// Register page specific functionality

document.addEventListener('DOMContentLoaded', function() {
  // Initialize the app
  initializeApp()

  // Registration form handler
  const regForm = document.getElementById('registrationForm')
  if (regForm) {
    const regSubmitBtn = regForm.querySelector('button[type="submit"]')

    regForm.addEventListener('submit', ev => {
      ev.preventDefault()
      clearStatus('registerStatus')
      const user_name = (new FormData(regForm)).get('username')
      regSubmitBtn.disabled = true

      const ahandler = async () => {
        try {
          showStatus('registerStatus', 'Starting registration...', 'info')
          await register(user_name)
          showStatus('registerStatus', `Registration successful for ${user_name}!`, 'success')

          // Auto-login after successful registration
          setTimeout(() => {
            window.location.href = '/'
          }, 1500)
        } catch (err) {
          console.error('Registration error:', err)
          if (err.name === "NotAllowedError") {
            showStatus('registerStatus', `Registration cancelled`, 'error')
          } else {
            showStatus('registerStatus', `Registration failed: ${err.message}`, 'error')
          }
        } finally {
          regSubmitBtn.disabled = false
        }
      }
      ahandler()
    })
  }
})
