// Profile page specific functionality

document.addEventListener('DOMContentLoaded', function() {
  // Initialize the app
  initializeApp();
  
  // Setup dialog event handlers
  setupDialogHandlers();
});

// Setup dialog event handlers
function setupDialogHandlers() {
  // Close dialog when clicking outside
  const dialog = document.getElementById('deviceLinkDialog');
  if (dialog) {
    dialog.addEventListener('click', function(e) {
      if (e.target === this) {
        closeDeviceLinkDialog();
      }
    });
  }
  
  // Close dialog when pressing Escape key
  document.addEventListener('keydown', function(e) {
    const dialog = document.getElementById('deviceLinkDialog');
    if (e.key === 'Escape' && dialog && dialog.open) {
      closeDeviceLinkDialog();
    }
  });
}

// Open device link dialog
function openDeviceLinkDialog() {
  const dialog = document.getElementById('deviceLinkDialog');
  const container = document.querySelector('.container');
  const body = document.body;
  
  if (dialog && container && body) {
    // Add blur and disable effects
    container.classList.add('dialog-open');
    body.classList.add('dialog-open');
    
    dialog.showModal();
    generateDeviceLink();
  }
}

// Close device link dialog
function closeDeviceLinkDialog() {
  const dialog = document.getElementById('deviceLinkDialog');
  const container = document.querySelector('.container');
  const body = document.body;
  
  if (dialog && container && body) {
    // Remove blur and disable effects
    container.classList.remove('dialog-open');
    body.classList.remove('dialog-open');
    
    dialog.close();
  }
}

// Generate device link function
function generateDeviceLink() {
  clearStatus('deviceAdditionStatus');
  showStatus('deviceAdditionStatus', 'Generating device link...', 'info');
  
  fetch('/api/create-device-link', {
    method: 'POST',
    credentials: 'include'
  })
  .then(response => response.json())
  .then(result => {
    if (result.error) throw new Error(result.error);
    
    // Update UI with the link
    const deviceLinkText = document.getElementById('deviceLinkText');
    const deviceToken = document.getElementById('deviceToken');
    
    if (deviceLinkText) {
      deviceLinkText.textContent = result.addition_link;
    }
    
    if (deviceToken) {
      deviceToken.textContent = result.token;
    }
    
    // Store link globally for copy function
    window.currentDeviceLink = result.addition_link;
    
    // Generate QR code
    const qrCodeEl = document.getElementById('qrCode');
    if (qrCodeEl && typeof QRCode !== 'undefined') {
      qrCodeEl.innerHTML = '';
      new QRCode(qrCodeEl, {
        text: result.addition_link,
        width: 200,
        height: 200,
        colorDark: '#000000',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.M
      });
    }
    
    showStatus('deviceAdditionStatus', 'Device link generated successfully!', 'success');
  })
  .catch(error => {
    console.error('Error generating device link:', error);
    showStatus('deviceAdditionStatus', `Failed to generate device link: ${error.message}`, 'error');
  });
}

// Make functions available globally for onclick handlers
window.openDeviceLinkDialog = openDeviceLinkDialog;
window.closeDeviceLinkDialog = closeDeviceLinkDialog;
