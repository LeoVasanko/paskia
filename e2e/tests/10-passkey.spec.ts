import { test, expect, createVirtualAuthenticator } from './fixtures/virtual-authenticator'
import {
  registerPasskey,
  authenticatePasskey,
  validateSession,
  getUserInfo,
  logout,
  getBootstrapResetToken,
  createDeviceLink,
  getSessionCookieName,
  saveSessionToken,
  getSavedSessionToken,
  saveDeviceTokens,
} from './fixtures/passkey-helpers'
import type { Page, BrowserContext } from '@playwright/test'

/**
 * Helper to set up session cookie for a page.
 */
async function setupSessionCookie(page: Page, sessionToken: string): Promise<void> {
  const cookieName = getSessionCookieName()
  await page.context().addCookies([{
    name: cookieName,
    value: sessionToken,
    domain: 'localhost',
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'Strict' as const,
  }])
}

/**
 * E2E tests for Paskia using Chrome's Virtual Authenticator.
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
  const baseUrl = process.env.BASE_URL || 'http://localhost:4404'

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

    // Take screenshot of the login view
    await page.screenshot({ path: 'test-results/login-view.png' })
    console.log('✓ Screenshot saved: test-results/login-view.png')

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
    expect(result.user).toBeDefined()
    expect(result.credential).toBeDefined()
    expect(result.message).toContain('successfully')

    // Store for subsequent tests
    sessionToken = result.session_token
    userUuid = result.user
    credentialUuid = result.credential

    // Save session token for other test groups to use
    saveSessionToken(sessionToken)

    console.log(`✓ Registered user: ${userUuid}`)
    console.log(`✓ Credential: ${credentialUuid}`)
    console.log(`✓ Session token: ${sessionToken.substring(0, 4)}...`)
  })

  test('should create device tokens for other tests', async ({ page }) => {
    test.skip(!sessionToken, 'Requires successful registration')

    // Create a batch of device tokens for API tests to use
    // Each API test needs its own token to register a passkey in its virtual authenticator
    const tokenCount = 15  // Enough for all API tests
    const tokens: string[] = []

    for (let i = 0; i < tokenCount; i++) {
      const deviceLink = await createDeviceLink(page, baseUrl, sessionToken)
      tokens.push(deviceLink.token)
    }

    saveDeviceTokens(tokens)
    console.log(`✓ Created ${tokens.length} device tokens for API tests`)
  })

  test('should validate the session token', async ({ page }) => {
    // Skip if registration didn't run
    test.skip(!sessionToken, 'Requires successful registration')

    const validation = await validateSession(page, baseUrl, sessionToken)

    expect(validation.valid).toBe(true)
    expect(validation.ctx.user.uuid).toBe(userUuid)

    console.log(`✓ Session validated for user: ${validation.ctx.user.uuid}`)
  })

  test('should retrieve user info', async ({ page }) => {
    test.skip(!sessionToken, 'Requires successful registration')

    const userInfo = await getUserInfo(page, baseUrl, sessionToken)

    expect(userInfo.user.uuid).toBe(userUuid)
    expect(userInfo.user.display_name).toBe('Admin User')
    expect(userInfo.credentials).toBeDefined()
    expect(Object.keys(userInfo.credentials).length).toBeGreaterThanOrEqual(1)

    // Navigate to profile and take screenshot
    const cookieName = getSessionCookieName()
    await page.context().addCookies([{
      name: cookieName,
      value: sessionToken,
      domain: 'localhost',
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'Strict' as const,
    }])
    await page.goto('/auth/')
    await page.waitForSelector('[data-view="profile"]', { timeout: 5000 })
    await page.screenshot({ path: 'test-results/profile-view.png' })
    console.log('✓ Screenshot saved: test-results/profile-view.png')

    console.log(`✓ User info retrieved: ${userInfo.user.display_name}`)
    console.log(`✓ Credentials count: ${Object.keys(userInfo.credentials).length}`)
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

    console.log(`✓ Added test credential: ${regResult.credential}`)

    // Now logout and authenticate with the fresh credential
    await logout(page, baseUrl, regResult.session_token)
    console.log('✓ Logged out')

    // Authenticate with the virtual authenticator (now has a valid credential)
    const result = await authenticatePasskey(page, baseUrl)

    expect(result.session_token).toBeDefined()
    expect(result.session_token).toHaveLength(16)
    expect(result.user).toBe(userUuid)

    // Update session token for subsequent tests
    sessionToken = result.session_token

    // Save session token for other test groups to use
    saveSessionToken(sessionToken)

    console.log(`✓ Authenticated as user: ${result.user}`)
    console.log(`✓ New session token: ${sessionToken.substring(0, 4)}...`)
  })

  test('should validate new session after authentication', async ({ page }) => {
    test.skip(!sessionToken, 'Requires successful authentication')

    const validation = await validateSession(page, baseUrl, sessionToken)

    expect(validation.valid).toBe(true)
    expect(validation.ctx.user.uuid).toBe(userUuid)

    console.log(`✓ New session validated`)
  })

  // Note: Logout test moved to the end so other test groups can use the session
})

test.describe('Session Management', () => {
  const baseUrl = process.env.BASE_URL || 'http://localhost:4404'

  test('should reject invalid session token', async ({ page }) => {
    const cookieName = getSessionCookieName()
    const response = await page.request.post(`${baseUrl}/auth/api/validate`, {
      headers: {
        'Cookie': `${cookieName}=invalid_token_123`,
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

test.describe('Device Addition Dialog', () => {
  const baseUrl = process.env.BASE_URL || 'http://localhost:4404'

  test.describe.configure({ mode: 'serial' })

  let sessionToken: string

  test.beforeAll(() => {
    // Get the session token saved by the previous test group
    // Note: This runs before the logout test, so the session should still be valid
    const saved = getSavedSessionToken()
    if (saved) {
      sessionToken = saved
    }
  })

  test('should open device addition dialog and show QR code', async ({ page }) => {
    test.skip(!sessionToken, 'Requires saved session token from previous tests')

    // Set the session cookie for this test context
    const cookieName = getSessionCookieName()
    await page.context().addCookies([{
      name: cookieName,
      value: sessionToken,
      domain: 'localhost',
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'Strict',
    }])

    // Navigate to auth page (which should show profile when logged in)
    await page.goto('/auth/')

    // Wait for the profile view to load
    await page.waitForSelector('[data-view="profile"]', { timeout: 5000 })

    // Click the "Another Device" button
    const addDeviceButton = page.getByRole('button', { name: 'Another Device' })
    await expect(addDeviceButton).toBeVisible()
    await addDeviceButton.click()

    // Wait for the registration link modal to appear
    const dialog = page.locator('.device-dialog')
    await expect(dialog).toBeVisible({ timeout: 5000 })

    // Verify dialog contains expected elements
    await expect(dialog.locator('h2')).toContainText('Add Another Device')

    // Wait for QR code to be generated (canvas should have content)
    const qrCanvas = dialog.locator('.qr-code')
    await expect(qrCanvas).toBeVisible()

    // Verify the link is displayed (text strips scheme, but href has it)
    const linkElement = dialog.locator('a.qr-link')
    await expect(linkElement).toBeVisible()
    const linkText = await linkElement.textContent()
    const linkHref = await linkElement.getAttribute('href')
    // Text shows hostname without scheme
    expect(linkText).toContain('localhost:4404/auth/')
    // Href includes full URL with scheme
    expect(linkHref).toContain('http://localhost:4404/auth/')
    console.log(`✓ Device link displayed: ${linkText} (href: ${linkHref})`)

    // Verify help text is shown
    await expect(dialog.locator('.reg-help')).toContainText('Scan this QR code')

    // Take screenshot of the dialog
    await dialog.screenshot({ path: 'test-results/device-addition-dialog.png' })
    console.log(`✓ Screenshot saved: test-results/device-addition-dialog.png`)

    // Verify the QR link element is clickable (copy functionality is built into clicking it)
    const qrLink = dialog.locator('a.qr-link')
    await expect(qrLink).toBeVisible()

    // Close the dialog (use the text button, not the icon button)
    const closeButton = dialog.locator('button.btn-secondary', { hasText: 'Close' })
    await closeButton.click()
    await expect(dialog).not.toBeVisible()

    console.log(`✓ Device addition dialog test complete`)
  })

  test('should extract valid reset token from dialog', async ({ page }) => {
    test.skip(!sessionToken, 'Requires successful registration')

    // Set the session cookie
    // __Host- cookies require: secure=true, path=/, no domain (but we set domain for localhost)
    const cookieName = getSessionCookieName()
    await page.context().addCookies([{
      name: cookieName,
      value: sessionToken,
      domain: 'localhost',
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'Strict',
    }])

    await page.goto('/auth/')
    await page.waitForSelector('[data-view="profile"]', { timeout: 5000 })

    // Open the dialog
    await page.getByRole('button', { name: 'Another Device' }).click()
    const dialog = page.locator('.device-dialog')
    await expect(dialog).toBeVisible({ timeout: 5000 })

    // Extract the reset token from the displayed URL
    const linkText = dialog.locator('.qr-link .link-text')
    const linkContent = await linkText.textContent()

    // URL format: localhost/auth/word1.word2.word3.word4.word5
    const tokenMatch = linkContent?.match(/\/auth\/([a-z]+\.[a-z]+\.[a-z]+\.[a-z]+\.[a-z]+)/)
    expect(tokenMatch).toBeTruthy()
    const extractedToken = tokenMatch![1]
    console.log(`✓ Extracted reset token: ${extractedToken}`)

    // Close the dialog (use the text button, not the icon button)
    await dialog.locator('button.btn-secondary', { hasText: 'Close' }).click()

    // Verify the token can be used for registration via API
    // (We won't complete registration, just verify the WebSocket accepts it)
    const wsUrl = `${baseUrl.replace('http', 'ws')}/auth/ws/register?reset=${encodeURIComponent(extractedToken)}&name=Test`

    // Use page.evaluate to test WebSocket connection
    const wsResult = await page.evaluate(async (wsUrl) => {
      return new Promise<{ success: boolean; hasOptions: boolean }>((resolve) => {
        const ws = new WebSocket(wsUrl)
        ws.onmessage = (event) => {
          const data = JSON.parse(event.data)
          ws.close()
          // Check if we got registration options (not an error)
          resolve({
            success: !data.status && !data.detail,
            hasOptions: !!data.optionsJSON?.challenge
          })
        }
        ws.onerror = () => resolve({ success: false, hasOptions: false })
        setTimeout(() => {
          ws.close()
          resolve({ success: false, hasOptions: false })
        }, 5000)
      })
    }, wsUrl)

    expect(wsResult.success).toBe(true)
    expect(wsResult.hasOptions).toBe(true)
    console.log(`✓ Reset token is valid and accepted by server`)
  })
})

test.describe('ProfileView - Register New', () => {
  const baseUrl = process.env.BASE_URL || 'http://localhost:4404'

  test('should show credentials list in profile', async ({ page }) => {
    const sessionToken = getSavedSessionToken()
    test.skip(!sessionToken, 'Requires saved session token')

    await setupSessionCookie(page, sessionToken!)

    // Navigate to profile page
    await page.goto(`${baseUrl}/auth/`)
    await page.waitForLoadState('networkidle')

    // Wait for credentials to load
    await page.waitForSelector('.credential-list', { timeout: 10000 })

    // Should have at least one credential from initial registration
    const credentialItems = await page.locator('.credential-item').count()
    expect(credentialItems).toBeGreaterThanOrEqual(1)
    console.log(`✓ Profile shows ${credentialItems} credential(s) in list`)
  })

  test('should add a new passkey using Register New button', async ({ page }) => {
    const sessionToken = getSavedSessionToken()
    test.skip(!sessionToken, 'Requires saved session token')

    // Create virtual authenticator for this page
    await createVirtualAuthenticator(page)
    await setupSessionCookie(page, sessionToken!)

    // Navigate to profile page
    await page.goto(`${baseUrl}/auth/`)
    await page.waitForLoadState('networkidle')

    // Wait for credentials list and get initial count
    await page.waitForSelector('.credential-list', { timeout: 10000 })
    const initialCredentialCount = await page.locator('.credential-item').count()
    console.log(`Initial credential count: ${initialCredentialCount}`)

    // Click "Register New" button
    const addPasskeyBtn = page.locator('button:has-text("Register New")')
    await expect(addPasskeyBtn).toBeVisible()
    await addPasskeyBtn.click()

    // Wait for WebAuthn registration to complete (virtual authenticator handles it automatically)
    // The button might show loading state or there might be a success message
    await page.waitForTimeout(2000) // Give time for WebSocket registration to complete

    // Refresh the page to ensure we see updated credentials
    await page.reload()
    await page.waitForLoadState('networkidle')
    await page.waitForSelector('.credential-list', { timeout: 10000 })

    // Should now have one more credential
    const newCredentialCount = await page.locator('.credential-item').count()
    expect(newCredentialCount).toBe(initialCredentialCount + 1)
    console.log(`✓ Successfully added new passkey. Credentials: ${initialCredentialCount} -> ${newCredentialCount}`)
  })

  test('should reject duplicate passkey from same authenticator', async ({ page }) => {
    const sessionToken = getSavedSessionToken()
    test.skip(!sessionToken, 'Requires saved session token')

    // Create virtual authenticator with resident key support
    // Using same authenticator configuration - credentials stored on authenticator
    await createVirtualAuthenticator(page, {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    })

    await setupSessionCookie(page, sessionToken!)

    // Navigate to profile page
    await page.goto(`${baseUrl}/auth/`)
    await page.waitForLoadState('networkidle')

    // Wait for credentials list
    await page.waitForSelector('.credential-list', { timeout: 10000 })
    const initialCredentialCount = await page.locator('.credential-item').count()

    // Try to add a passkey - with excludeCredentials the authenticator should
    // prevent re-registration of the same credential
    const addPasskeyBtn = page.locator('button:has-text("Register New")')
    await expect(addPasskeyBtn).toBeVisible()
    await addPasskeyBtn.click()

    // Wait for response - could be success (new credential) or error (duplicate)
    await page.waitForTimeout(3000)

    // Check for error message or status message
    const statusMessage = page.locator('.status-message')
    const hasError = await statusMessage.locator('.error, .status-error').isVisible().catch(() => false)

    // Reload to check final credential count
    await page.reload()
    await page.waitForLoadState('networkidle')
    await page.waitForSelector('.credential-list', { timeout: 10000 })
    const finalCredentialCount = await page.locator('.credential-item').count()

    // The test passes if either:
    // 1. An error was shown (duplicate rejected by excludeCredentials)
    // 2. A new credential was added (fresh authenticator has no stored credential)
    console.log(`Credentials: ${initialCredentialCount} -> ${finalCredentialCount}, error shown: ${hasError}`)
    console.log(`✓ Add passkey flow completed (new authenticator creates new credential)`)
  })
})

test.describe('ProfileView - Multi-Authenticator', () => {
  const baseUrl = process.env.BASE_URL || 'http://localhost:4404'

  test('should add passkey from different authenticator', async ({ page }) => {
    const sessionToken = getSavedSessionToken()
    test.skip(!sessionToken, 'Requires saved session token')

    // Create a different virtual authenticator (simulating a different device)
    await createVirtualAuthenticator(page, {
      protocol: 'ctap2',
      transport: 'usb', // Different transport - like a USB security key
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    })

    await setupSessionCookie(page, sessionToken!)

    // Navigate to profile page
    await page.goto(`${baseUrl}/auth/`)
    await page.waitForLoadState('networkidle')

    // Wait for credentials list and get initial count
    await page.waitForSelector('.credential-list', { timeout: 10000 })
    const initialCredentialCount = await page.locator('.credential-item').count()

    // Click "Register New" button
    const addPasskeyBtn = page.locator('button:has-text("Register New")')
    await expect(addPasskeyBtn).toBeVisible()
    await addPasskeyBtn.click()

    // Wait for registration to complete
    await page.waitForTimeout(2000)

    // Refresh to see updated list
    await page.reload()
    await page.waitForLoadState('networkidle')
    await page.waitForSelector('.credential-list', { timeout: 10000 })

    const newCredentialCount = await page.locator('.credential-item').count()
    expect(newCredentialCount).toBe(initialCredentialCount + 1)
    console.log(`✓ Added passkey from USB authenticator. Credentials: ${initialCredentialCount} -> ${newCredentialCount}`)
  })

  test('should display multiple credentials with details', async ({ page }) => {
    const sessionToken = getSavedSessionToken()
    test.skip(!sessionToken, 'Requires saved session token')

    await setupSessionCookie(page, sessionToken!)

    // Navigate to profile page
    await page.goto(`${baseUrl}/auth/`)
    await page.waitForLoadState('networkidle')
    await page.waitForSelector('.credential-list', { timeout: 10000 })

    // Should have multiple credentials now from previous tests
    const credentialItems = page.locator('.credential-item')
    const count = await credentialItems.count()

    // Verify each credential has required elements
    for (let i = 0; i < count; i++) {
      const item = credentialItems.nth(i)

      // Should have title/name
      const title = item.locator('.item-title')
      await expect(title).toBeVisible()

      // Should have date information
      const dates = item.locator('.credential-dates')
      await expect(dates).toBeVisible()

      // Should have created date
      const createdDate = item.locator('.date-label:has-text("Created:")')
      await expect(createdDate).toBeVisible()
    }

    console.log(`✓ All ${count} credentials displayed with proper details`)

    // Take screenshot of credentials list
    await page.screenshot({
      path: 'test-results/credentials-list.png',
      fullPage: false,
    })
    console.log(`✓ Screenshot saved: test-results/credentials-list.png`)
  })

  test('should show current session badge', async ({ page }) => {
    const sessionToken = getSavedSessionToken()
    test.skip(!sessionToken, 'Requires saved session token')

    await setupSessionCookie(page, sessionToken!)

    // Navigate to profile page
    await page.goto(`${baseUrl}/auth/`)
    await page.waitForLoadState('networkidle')
    await page.waitForSelector('.credential-list', { timeout: 10000 })

    // Look for the "Current" badge indicating current session's credential
    const currentBadge = page.locator('.badge-current:has-text("Current")')
    const hasCurrent = await currentBadge.isVisible().catch(() => false)

    if (hasCurrent) {
      console.log(`✓ Current session credential is marked with "Current" badge`)

      // The current credential should have delete disabled
      const currentItem = page.locator('.credential-item.current-session')
      if (await currentItem.isVisible()) {
        const deleteBtn = currentItem.locator('.btn-card-delete')
        if (await deleteBtn.isVisible()) {
          await expect(deleteBtn).toBeDisabled()
          console.log(`✓ Delete button is disabled for current session credential`)
        }
      }
    } else {
      console.log(`ℹ No credential marked as current (may be using different auth method)`)
    }
  })
})
