// Login page specific functionality

document.addEventListener('DOMContentLoaded', function() {
  // Initialize the app
  initializeApp();
  
  // Authentication form handler
  const authForm = document.getElementById('authenticationForm');
  if (authForm) {
    const authSubmitBtn = authForm.querySelector('button[type="submit"]');
    
    authForm.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      authSubmitBtn.disabled = true;
      clearStatus('loginStatus');
      
      try {
        showStatus('loginStatus', 'Starting authentication...', 'info');
        await authenticate();
        showStatus('loginStatus', 'Authentication successful!', 'success');
        
        // Navigate to profile
        setTimeout(() => {
          window.location.href = '/auth/profile';
        }, 1000);
      } catch (err) {
        showStatus('loginStatus', `Authentication failed: ${err.message}`, 'error');
      } finally {
        authSubmitBtn.disabled = false;
      }
    });
  }
});
