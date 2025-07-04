const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser

async function register(user_name) {
  const ws = await aWebSocket('/ws/new_user_registration')
  ws.send(JSON.stringify({user_name}))
  // Registration chat
  const optionsJSON = JSON.parse(await ws.recv())
  if (optionsJSON.error) throw new Error(optionsJSON.error)
  ws.send(JSON.stringify(await startRegistration({optionsJSON})))
  const result = JSON.parse(await ws.recv())
  if (result.error) throw new Error(`Server: ${result.error}`)
}

async function authenticate() {
  // Authentication chat
  const ws = await aWebSocket('/ws/authenticate')
  const optionsJSON = JSON.parse(await ws.recv())
  if (optionsJSON.error) throw new Error(optionsJSON.error)
  await ws.send(JSON.stringify(await startAuthentication({optionsJSON})))
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
    const user_name = (new FormData(regForm)).get('username')
    register(user_name).then(() => {
      alert(`Registration successful for ${user_name}!`)
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
      alert(`Authentication successful!`)
    }).catch(err => {
      alert(`Authentication failed: ${err.message}`)
    }).finally(() => {
      authSubmitBtn.disabled = false
    })
  })
})()
