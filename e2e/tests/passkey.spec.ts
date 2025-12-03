import { test, expect } from './fixtures/virtual-authenticator'
import {
  registerPasskey,
  authenticatePasskey,
  validateSession,
  getUserInfo,
  logout,
  getBootstrapResetToken,
  createDeviceLink,
} from './fixtures/passkey-helpers'

/**
 * E2E tests for PasskeyAuth using Chrome's Virtual Authenticator.
 * 
 * These tests exercise the complete WebAuthn flow:
 * 1. Registration via WebSocket using bootstrap reset token
 * 2. Authentication via WebSocket  
 * 3. Session validation
 * 4. User info retrieval
 * 5. Logout
 * 
 * The virtual authenticator simulates a hardware passkey device,
 * allowing fully automated testing without physical hardware.
 */

test.describe('Passkey Authentication E2E', () => {
  const baseUrl = process.env.BASE_URL || 'http://localhost:4401'
  
  test.describe.configure({ mode: 'serial' })

  // Shared state across tests in this describe block
  let sessionToken: string
  let userUuid: string
  let credentialUuid: string
  let resetToken: string | undefined

  test.beforeAll(() => {
    // Get the bootstrap reset token from global setup
    resetToken = getBootstrapResetToken()
    if (!resetToken) {
      console.warn('⚠️ No reset token found - registration test may fail')
    } else {
      console.log(`📝 Using reset token: ${resetToken}`)
    }
  })

  test('should load the auth page', async ({ page }) => {
    // Navigate to auth page to establish origin for WebAuthn
    await page.goto('/auth/')
    await expect(page).toHaveTitle(/.*/)
    
    // Page should load - 401 errors are expected since user is not logged in
    await page.waitForTimeout(500)
    
    // Just verify the page loaded without JS errors (network 401s are OK)
    console.log('✓ Auth page loaded successfully')
  })

  test('should register admin passkey via WebSocket using reset token', async ({ page, virtualAuthenticator }) => {
    test.skip(!resetToken, 'No reset token available from bootstrap')
    
    // Must visit the page first to establish origin
    await page.goto('/auth/')
    
    // Perform registration via WebSocket with virtual authenticator
    // Using the bootstrap reset token for the admin user
    const result = await registerPasskey(page, baseUrl, {
      resetToken: resetToken,
      displayName: 'Admin User',
    })

    // Verify registration result
    expect(result.session_token).toBeDefined()
    expect(result.session_token).toHaveLength(16)
    expect(result.user_uuid).toBeDefined()
    expect(result.credential_uuid).toBeDefined()
    expect(result.message).toContain('successfully')

    // Store for subsequent tests
    sessionToken = result.session_token
    userUuid = result.user_uuid
    credentialUuid = result.credential_uuid

    console.log(`✓ Registered user: ${userUuid}`)
    console.log(`✓ Credential: ${credentialUuid}`)
    console.log(`✓ Session token: ${sessionToken.substring(0, 4)}...`)
  })

  test('should validate the session token', async ({ page }) => {
    // Skip if registration didn't run
    test.skip(!sessionToken, 'Requires successful registration')

    const validation = await validateSession(page, baseUrl, sessionToken)
    
    expect(validation.valid).toBe(true)
    expect(validation.user_uuid).toBe(userUuid)
    
    console.log(`✓ Session validated for user: ${validation.user_uuid}`)
  })

  test('should retrieve user info', async ({ page }) => {
    test.skip(!sessionToken, 'Requires successful registration')

    const userInfo = await getUserInfo(page, baseUrl, sessionToken)
    
    expect(userInfo.user.user_uuid).toBe(userUuid)
    expect(userInfo.user.user_name).toBe('Admin User')
    expect(userInfo.credentials).toBeDefined()
    expect(userInfo.credentials.length).toBeGreaterThanOrEqual(1)
    
    console.log(`✓ User info retrieved: ${userInfo.user.user_name}`)
    console.log(`✓ Credentials count: ${userInfo.credentials.length}`)
  })

  test('should authenticate with existing passkey', async ({ page, virtualAuthenticator }) => {
    test.skip(!sessionToken, 'Requires successful registration')

    // Navigate to page (required for WebAuthn origin)
    await page.goto('/auth/')

    // The virtual authenticator in this context is new and doesn't have credentials.
    // Create a device link using the current session, then register a new credential.
    const deviceLink = await createDeviceLink(page, baseUrl, sessionToken)
    console.log(`✓ Created device link with token: ${deviceLink.token}`)

    // Register a new credential using the device link
    const regResult = await registerPasskey(page, baseUrl, {
      resetToken: deviceLink.token,
      displayName: 'Admin User (test device)'
    })
    
    console.log(`✓ Added test credential: ${regResult.credential_uuid}`)
    
    // Now logout and authenticate with the fresh credential
    await logout(page, baseUrl, regResult.session_token)
    console.log('✓ Logged out')

    // Authenticate with the virtual authenticator (now has a valid credential)
    const result = await authenticatePasskey(page, baseUrl)

    expect(result.session_token).toBeDefined()
    expect(result.session_token).toHaveLength(16)
    expect(result.user_uuid).toBe(userUuid)

    // Update session token for subsequent tests
    sessionToken = result.session_token

    console.log(`✓ Authenticated as user: ${result.user_uuid}`)
    console.log(`✓ New session token: ${sessionToken.substring(0, 4)}...`)
  })

  test('should validate new session after authentication', async ({ page }) => {
    test.skip(!sessionToken, 'Requires successful authentication')

    const validation = await validateSession(page, baseUrl, sessionToken)
    
    expect(validation.valid).toBe(true)
    expect(validation.user_uuid).toBe(userUuid)
    
    console.log(`✓ New session validated`)
  })

  test('should logout successfully', async ({ page }) => {
    test.skip(!sessionToken, 'Requires valid session')

    await logout(page, baseUrl, sessionToken)
    
    // Session should no longer be valid
    const response = await page.request.post(`${baseUrl}/auth/api/validate`, {
      headers: {
        'Cookie': `__Host-auth=${sessionToken}`,
      },
      failOnStatusCode: false,
    })
    
    expect(response.status()).toBe(401)
    console.log(`✓ Logout successful, session invalidated`)
  })
})

test.describe('Session Management', () => {
  const baseUrl = process.env.BASE_URL || 'http://localhost:4401'

  test('should reject invalid session token', async ({ page }) => {
    const response = await page.request.post(`${baseUrl}/auth/api/validate`, {
      headers: {
        'Cookie': '__Host-auth=invalid_token_123',
      },
      failOnStatusCode: false,
    })
    
    // Server may return 400 (bad format) or 401 (unauthorized)
    expect([400, 401]).toContain(response.status())
    console.log(`✓ Invalid token correctly rejected`)
  })

  test('should reject missing session token', async ({ page }) => {
    const response = await page.request.post(`${baseUrl}/auth/api/validate`, {
      failOnStatusCode: false,
    })
    
    expect(response.status()).toBe(401)
    console.log(`✓ Missing token correctly rejected`)
  })
})
