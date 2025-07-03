const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser

async function register(username) {
  // Registration chat
  const ws = await aWebSocket('/ws/register')
  ws.send(username)
  const optionsJSON = JSON.parse(await ws.recv())
  if (optionsJSON.error) throw new Error(optionsJSON.error)
  ws.send(JSON.stringify(await startRegistration({optionsJSON})))
  const result = JSON.parse(await ws.recv())
  if (result.error) throw new Error(`Server: ${result.error}`)
}

async function authenticate() {
  // Authentication chat
  const ws = await aWebSocket('/ws/authenticate')
  ws.send('') // Send empty string to trigger authentication
  const optionsJSON = JSON.parse(await ws.recv())
  if (optionsJSON.error) throw new Error(optionsJSON.error)
  ws.send(JSON.stringify(await startAuthentication({optionsJSON})))
  const result = JSON.parse(await ws.recv())
  if (result.error) throw new Error(`Server: ${result.error}`)
  return result
}

(function() {
  const regForm = document.getElementById('registrationForm')
  const regSubmitBtn = regForm.querySelector('button[type="submit"]')  
  regForm.addEventListener('submit', ev => {
    ev.preventDefault()
    regSubmitBtn.disabled = true
    const username = (new FormData(regForm)).get('username')
    register(username).then(() => {
      alert(`Registration successful for ${username}!`)
    }).catch(err => {
      alert(`Registration failed: ${err.message}`)
    }).finally(() => {
      regSubmitBtn.disabled = false
    })
  })

  const authForm = document.getElementById('authenticationForm')
  const authSubmitBtn = authForm.querySelector('button[type="submit"]')  
  authForm.addEventListener('submit', ev => {
    ev.preventDefault()
    authSubmitBtn.disabled = true
    authenticate().then(result => {
      alert(`Authentication successful! Welcome ${result.username}`)
    }).catch(err => {
      alert(`Authentication failed: ${err.message}`)
    }).finally(() => {
      authSubmitBtn.disabled = false
    })
  })
})()
