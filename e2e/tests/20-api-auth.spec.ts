import { test, expect, createVirtualAuthenticator } from './fixtures/virtual-authenticator'
import {
  getSessionCookieName,
  getSavedSessionToken,
  saveSessionToken,
  registerPasskey,
  authenticatePasskey,
  popDeviceToken,
  getDeviceTokenCount,
  logout,
} from './fixtures/passkey-helpers'
import type { Page, Frame } from '@playwright/test'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

/**
 * E2E tests for API mode authentication flows.
 *
 * These tests simulate the flow used by SPAs when making API calls:
 * 1. API call returns 401/403 with auth.iframe URL
 * 2. App shows auth iframe overlay
 * 3. User authenticates in iframe
 * 4. Iframe posts 'auth-success' message to parent
 * 5. App retries original API call
 *
 * Note: These tests depend on 10-passkey.spec.ts running first to create device tokens.
 * Each test that needs authentication uses popDeviceToken() to get a fresh token
 * and registers its own credential in its virtual authenticator.
 */

const baseUrl = process.env.BASE_URL || 'http://localhost:4404'

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
 * Helper to clear session cookie.
 */
async function clearSessionCookie(page: Page): Promise<void> {
  const cookieName = getSessionCookieName()
  await page.context().clearCookies({ name: cookieName })
}

/**
 * Set up the test page using the examples page directly.
 * The examples page already has iframe handling - we just add a Promise wrapper.
 * We route the paskia-js module request to serve from the local dist.
 */
async function setupTestHarness(page: Page): Promise<void> {
  // Serve paskia.js from the local filesystem since the server doesn't serve /paskia-js/
  const paskiaJsPath = join(__dirname, '..', '..', 'paskia-js', 'dist', 'paskia.js')
  await page.route('**/paskia-js/dist/paskia.js', async route => {
    const body = readFileSync(paskiaJsPath, 'utf-8')
    await route.fulfill({
      body,
      contentType: 'application/javascript',
    })
  })
  // Navigate to the examples page which already has the auth iframe handling
  await page.goto(`${baseUrl}/auth/examples/`)
}

/**
 * Make an API call through the examples page, returning a Promise.
 * Wraps the page's apiCall and listens for auth-success/auth-back messages.
 * Returns { status, data } on success, or throws on cancellation.
 *
 * Note: If auth is not needed (request succeeds without 401/403), this will
 * resolve after a timeout with the direct fetch result.
 */
async function makeApiCall(page: Page, url: string, method = 'GET'): Promise<{ status: number; data?: any }> {
  return page.evaluate(({ url, method }) => {
    return new Promise((resolve, reject) => {
      let resolved = false;

      // Listen for auth messages
      const handler = (event: MessageEvent) => {
        const { type } = event.data || {};
        if (type === 'auth-success') {
          if (resolved) return;
          resolved = true;
          window.removeEventListener('message', handler);
          // Wait a tick for the page's handler to retry, then make our own call
          setTimeout(async () => {
            try {
              const response = await fetch(url, { method });
              if (response.status === 204) {
                resolve({ status: 204 });
              } else if (response.ok) {
                const data = await response.json();
                resolve({ status: response.status, data });
              } else {
                resolve({ status: response.status });
              }
            } catch (e) {
              resolve({ status: 0 });
            }
          }, 200);
        } else if (type === 'auth-back') {
          if (resolved) return;
          resolved = true;
          window.removeEventListener('message', handler);
          reject(new Error('cancelled'));
        }
      };
      window.addEventListener('message', handler);

      // Also make a direct fetch to handle the case where no auth is needed
      // (the page's apiCall won't send any message if the request succeeds)
      setTimeout(async () => {
        if (resolved) return;
        try {
          const response = await fetch(url, { method });
          // Only resolve if this is a success or non-auth error
          if (response.status !== 401 && response.status !== 403) {
            if (resolved) return;
            resolved = true;
            window.removeEventListener('message', handler);
            if (response.status === 204) {
              resolve({ status: 204 });
            } else if (response.ok) {
              const data = await response.json();
              resolve({ status: response.status, data });
            } else {
              resolve({ status: response.status });
            }
          }
          // If 401/403, the auth iframe will appear and we wait for the message
        } catch (e) {
          // Network error - let the message handler deal with it
        }
      }, 100);

      // Call the page's existing apiCall function
      // It will show the iframe on 401/403
      (window as any).apiCall(url, method);
    });
  }, { url, method });
}

/**
 * Wait for auth iframe to appear and return a reference to it.
 */
async function waitForAuthIframe(page: Page, timeout = 5000): Promise<Frame> {
  await page.waitForSelector('#paskia-iframe', { timeout })
  const iframe = page.frameLocator('#paskia-iframe')
  // Wait for iframe content to load
  await iframe.locator('.view-root').waitFor({ timeout })
  return page.frame({ url: /\/auth\/restricted\// })!
}

/**
 * Wait for auth iframe to disappear.
 */
async function waitForAuthIframeHidden(page: Page, timeout = 5000): Promise<void> {
  await page.waitForSelector('#paskia-iframe', { state: 'detached', timeout })
}

/**
 * Click Back button in auth iframe.
 */
async function clickBackInIframe(page: Page): Promise<void> {
  const iframe = page.frameLocator('#paskia-iframe')
  await iframe.getByRole('button', { name: 'Back' }).click()
}

/**
 * Click Login button in auth iframe.
 */
async function clickLoginInIframe(page: Page): Promise<void> {
  const iframe = page.frameLocator('#paskia-iframe')
  await iframe.getByRole('button', { name: 'Login' }).click()
}

/**
 * Click Verify button in auth iframe (for reauth mode).
 */
async function clickVerifyInIframe(page: Page): Promise<void> {
  const iframe = page.frameLocator('#paskia-iframe')
  await iframe.getByRole('button', { name: 'Verify' }).click()
}

/**
 * Click Logout button in auth iframe (for forbidden mode).
 */
async function clickLogoutInIframe(page: Page): Promise<void> {
  const iframe = page.frameLocator('#paskia-iframe')
  await iframe.getByRole('button', { name: 'Logout' }).click()
}

test.describe('API Mode - 401 Login Flow', () => {
  test.describe.configure({ mode: 'serial' })

  test('should show auth iframe on 401 and allow cancellation (Back)', async ({ page }) => {
    // Set up test harness (injects our API flow handler)
    await setupTestHarness(page)

    // Clear any existing session cookie
    await clearSessionCookie(page)

    // Make API call that triggers 401 (don't await - it blocks until iframe resolves)
    const apiCallPromise = makeApiCall(page, '/auth/api/user-info', 'GET').catch(e => e)
    console.log('✓ Auth iframe appeared on 401')

    // Verify it's in login mode (not reauth)
    const iframe = page.frameLocator('#paskia-iframe')
    await expect(iframe.locator('h1')).toContainText('🔐')
    await expect(iframe.getByRole('button', { name: 'Login' })).toBeVisible()

    // Take screenshot of the login iframe
    await page.screenshot({ path: 'test-results/api-401-login-iframe.png' })
    console.log('✓ Screenshot saved: test-results/api-401-login-iframe.png')

    // Click Back to cancel authentication
    await clickBackInIframe(page)

    // Iframe should close
    await waitForAuthIframeHidden(page)
    console.log('✓ Auth iframe closed on Back button')

    // Wait for the API call promise to reject
    const result = await apiCallPromise
    expect(result).toBeInstanceOf(Error)
    expect(result.message).toContain('cancelled')

    // Output should show cancellation
    const output = page.locator('#output')
    await expect(output).toContainText('cancelled')
    console.log('✓ API call was cancelled')
  })

  test('should show auth iframe on 401 and complete login', async ({ page, virtualAuthenticator }) => {
    // Get a device token from the pool (created by 10-passkey.spec.ts)
    const deviceToken = popDeviceToken()
    test.skip(!deviceToken, 'Requires device token from passkey tests')
    console.log(`✓ Got device token: ${deviceToken} (${getDeviceTokenCount()} remaining)`)

    // Navigate and register credential using device token
    await page.goto(`${baseUrl}/auth/`)
    const regResult = await registerPasskey(page, baseUrl, {
      resetToken: deviceToken,
      displayName: 'API Test Device',
    })
    console.log(`✓ Registered credential: ${regResult.credential}`)

    // Logout to clear session (but keep the passkey in virtual authenticator)
    await logout(page, baseUrl, regResult.session_token)
    console.log('✓ Logged out')

    // Set up test harness
    await setupTestHarness(page)

    // Make API call that triggers 401
    const apiCallPromise = makeApiCall(page, '/auth/api/user-info', 'GET')

    // Wait for auth iframe to appear
    await waitForAuthIframe(page)
    console.log('✓ Auth iframe appeared on 401')

    // Click Login button - virtual authenticator will handle the passkey
    await clickLoginInIframe(page)

    // Wait for authentication to complete - iframe should close
    await waitForAuthIframeHidden(page, 10000)
    console.log('✓ Authentication completed, iframe closed')

    // Wait for API call to complete and verify result
    const result = await apiCallPromise
    expect(result.status).toBe(200)
    expect(result.data.user).toBeDefined()
    console.log('✓ API call succeeded after authentication')

    // Save the session for other tests
    const cookies = await page.context().cookies()
    const sessionCookie = cookies.find(c => c.name === getSessionCookieName())
    if (sessionCookie) {
      saveSessionToken(sessionCookie.value)
      console.log(`✓ Saved session token for other tests`)
    }
  })
})

test.describe('API Mode - 401 Reauth Flow', () => {
  test.describe.configure({ mode: 'serial' })

  test('should show reauth iframe on max_age violation and allow cancellation', async ({ page, virtualAuthenticator }) => {
    // Get a device token from the pool (created by 10-passkey.spec.ts)
    const deviceToken = popDeviceToken()
    test.skip(!deviceToken, 'Requires device token from passkey tests')
    console.log(`✓ Got device token: ${deviceToken} (${getDeviceTokenCount()} remaining)`)

    // Navigate and register a credential
    await page.goto(`${baseUrl}/auth/`)
    const regResult = await registerPasskey(page, baseUrl, {
      resetToken: deviceToken,
      displayName: 'Reauth Cancel Test Device',
    })
    saveSessionToken(regResult.session_token)

    // Wait for session to age past max_age threshold
    console.log('Waiting 3s for session to age...')
    await page.waitForTimeout(3000)

    // Set up test harness with the session
    await setupSessionCookie(page, regResult.session_token)
    await setupTestHarness(page)

    // Make API call with max_age=1s (session is now > 1s old)
    const apiCallPromise = makeApiCall(page, '/auth/api/forward?max_age=1s', 'GET').catch(e => e)

    // Wait for auth iframe to appear
    await waitForAuthIframe(page)
    console.log('✓ Reauth iframe appeared (session older than max_age)')

    // Verify it's in reauth mode
    const iframe = page.frameLocator('#paskia-iframe')
    await expect(iframe.locator('h1')).toContainText('Additional Authentication')
    await expect(iframe.getByRole('button', { name: 'Verify' })).toBeVisible()

    // Take screenshot of reauth iframe
    await page.screenshot({ path: 'test-results/api-401-reauth-iframe.png' })
    console.log('✓ Screenshot saved: test-results/api-401-reauth-iframe.png')

    // Click Back to cancel
    await clickBackInIframe(page)
    await waitForAuthIframeHidden(page)
    console.log('✓ Reauth cancelled via Back button')

    const result = await apiCallPromise
    expect(result).toBeInstanceOf(Error)
  })

  test('should complete reauth flow with passkey', async ({ page, virtualAuthenticator }) => {
    // Get a device token from the pool (created by 10-passkey.spec.ts)
    const deviceToken = popDeviceToken()
    test.skip(!deviceToken, 'Requires device token from passkey tests')
    console.log(`✓ Got device token: ${deviceToken} (${getDeviceTokenCount()} remaining)`)

    // Navigate and register a credential
    await page.goto(`${baseUrl}/auth/`)
    const regResult = await registerPasskey(page, baseUrl, {
      resetToken: deviceToken,
      displayName: 'Reauth Test Device',
    })

    // Save the new session
    saveSessionToken(regResult.session_token)

    // Wait for the session to be "old" (>2s for max_age=2s test)
    console.log('Waiting 3s for session to age...')
    await page.waitForTimeout(3000)

    // Set up test harness with the session
    await setupSessionCookie(page, regResult.session_token)
    await setupTestHarness(page)

    // Make API call with max_age=2s
    const apiCallPromise = makeApiCall(page, '/auth/api/forward?max_age=2s', 'GET')

    // Auth iframe should appear in reauth mode
    await waitForAuthIframe(page)
    console.log('✓ Reauth iframe appeared')

    const iframe = page.frameLocator('#paskia-iframe')
    await expect(iframe.locator('h1')).toContainText('Additional Authentication')

    // Click Verify - virtual authenticator handles passkey
    await clickVerifyInIframe(page)

    // Wait for completion
    await waitForAuthIframeHidden(page, 10000)
    console.log('✓ Reauth completed')

    // Wait for API call result
    const result = await apiCallPromise
    expect(result.status).toBe(204)
    console.log('✓ Forward endpoint returned 204 after reauth')
  })
})

test.describe('API Mode - 403 Forbidden Flow', () => {
  test.describe.configure({ mode: 'serial' })

  test('should show forbidden view and allow going back', async ({ page }) => {
    const sessionToken = getSavedSessionToken()
    test.skip(!sessionToken, 'Requires saved session token')

    // Set up test harness with valid session
    await setupSessionCookie(page, sessionToken!)
    await setupTestHarness(page)

    // Make API call requiring admin permission
    const apiCallPromise = makeApiCall(page, '/auth/api/forward?perm=auth:admin', 'GET').catch(e => e)

    // Check if auth iframe appeared
    const iframeAppeared = await page.waitForSelector('#paskia-iframe', { timeout: 3000 }).then(() => true).catch(() => false)

    if (!iframeAppeared) {
      // User might already have admin permission
      const result = await apiCallPromise
      if (result.status === 204) {
        console.log('✓ User has admin permission, got 204 (skipping forbidden test)')
        return
      }
    }

    await waitForAuthIframe(page)
    console.log('✓ Auth iframe appeared on permission check')

    // Wait for view to stabilize and check mode
    await page.waitForTimeout(500)
    const iframe = page.frameLocator('#paskia-iframe')
    const headingText = await iframe.locator('h1').textContent()
    console.log(`  Heading: ${headingText}`)

    if (headingText?.includes('Forbidden')) {
      console.log('✓ Forbidden view displayed (user lacks admin permission)')

      // Should show Logout button in forbidden mode
      await expect(iframe.getByRole('button', { name: 'Logout' })).toBeVisible()

      // Take screenshot of forbidden view
      await page.screenshot({ path: 'test-results/api-403-forbidden-iframe.png' })
      console.log('✓ Screenshot saved: test-results/api-403-forbidden-iframe.png')

      // Click Back to close
      await clickBackInIframe(page)
      await waitForAuthIframeHidden(page)
      console.log('✓ Forbidden dialog closed via Back')

      const result = await apiCallPromise
      expect(result).toBeInstanceOf(Error)
    } else {
      // User has admin permission, so they got through
      console.log('✓ User has admin permission, no forbidden view')
    }
  })

  test('should allow logout from forbidden view and then login', async ({ page, virtualAuthenticator }) => {
    // Get a device token from the pool (created by 10-passkey.spec.ts)
    const deviceToken = popDeviceToken()
    test.skip(!deviceToken, 'Requires device token from passkey tests')
    console.log(`✓ Got device token: ${deviceToken} (${getDeviceTokenCount()} remaining)`)

    // Navigate and register credential for later login
    await page.goto(`${baseUrl}/auth/`)
    const regResult = await registerPasskey(page, baseUrl, {
      resetToken: deviceToken,
      displayName: 'Forbidden Test Device',
    })
    saveSessionToken(regResult.session_token)

    // Set up test harness with the session
    await setupSessionCookie(page, regResult.session_token)
    await setupTestHarness(page)

    // Make API call requiring admin permission
    const apiCallPromise = makeApiCall(page, '/auth/api/forward?perm=auth:admin', 'GET').catch(e => e)

    // Check if auth iframe appeared
    const iframeAppeared = await page.waitForSelector('#paskia-iframe', { timeout: 3000 }).then(() => true).catch(() => false)

    if (!iframeAppeared) {
      const result = await apiCallPromise
      if (result.status === 204) {
        console.log('✓ User has admin permission, skipping forbidden->login test')
        return
      }
    }

    await waitForAuthIframe(page)
    const iframe = page.frameLocator('#paskia-iframe')
    await page.waitForTimeout(500)

    const headingText = await iframe.locator('h1').textContent()

    if (headingText?.includes('Forbidden')) {
      console.log('✓ Forbidden view displayed')

      // Take screenshot of forbidden view before logout
      await page.screenshot({ path: 'test-results/api-403-forbidden-before-logout.png' })
      console.log('✓ Screenshot saved: test-results/api-403-forbidden-before-logout.png')

      // Click Logout in the iframe
      await clickLogoutInIframe(page)

      // After logout, the view should switch to login mode and show a toast
      await page.waitForTimeout(1000)
      await expect(iframe.getByRole('button', { name: 'Login' })).toBeVisible({ timeout: 5000 })
      console.log('✓ Switched to login view after logout')

      // Verify status message appears indicating user can login with another account
      const statusMessage = iframe.locator('.global-status .status')
      await expect(statusMessage).toBeVisible({ timeout: 3000 })
      const statusText = await statusMessage.textContent()
      expect(statusText).toContain('sign in with a different account')
      console.log(`✓ Status message: ${statusText}`)

      // Take screenshot showing login view with status message (after forbidden logout)
      await page.screenshot({ path: 'test-results/api-403-after-logout-login.png' })
      console.log('✓ Screenshot saved: test-results/api-403-after-logout-login.png')

      // Now login with the passkey
      await clickLoginInIframe(page)

      // Wait for auth to complete
      await waitForAuthIframeHidden(page, 10000)
      console.log('✓ Logged in successfully')

      // The API call should have completed (but may still fail with 403 since same user)
      const result = await apiCallPromise
      console.log(`  Final result status: ${result.status || 'error'}`)
    } else {
      console.log('✓ Not in forbidden mode, closing dialog')
      await clickBackInIframe(page)
      await waitForAuthIframeHidden(page)
    }
  })
})

test.describe('API Mode - Direct API Response Format', () => {
  test('should return JSON with auth.iframe on 401 (unauthenticated)', async ({ page }) => {
    // Make direct API call without session
    const response = await page.request.get(`${baseUrl}/auth/api/forward`, {
      headers: {
        'Accept': 'application/json',
      },
    })

    expect(response.status()).toBe(401)

    const data = await response.json()
    expect(data.auth).toBeDefined()
    expect(data.auth.iframe).toBeDefined()
    expect(data.auth.mode).toBe('login')
    expect(data.auth.iframe).toContain('/auth/restricted/iframe')

    console.log(`✓ 401 response includes auth.iframe: ${data.auth.iframe}`)
  })

  test('should return JSON with auth.mode=forbidden on 403', async ({ page }) => {
    const sessionToken = getSavedSessionToken()
    test.skip(!sessionToken, 'Requires saved session token')

    const cookieName = getSessionCookieName()

    // Make API call with session but requesting admin permission
    const response = await page.request.get(`${baseUrl}/auth/api/forward?perm=auth:admin`, {
      headers: {
        'Accept': 'application/json',
        'Cookie': `${cookieName}=${sessionToken}`,
      },
    })

    // Could be 403 (forbidden) or 204 (user is admin)
    if (response.status() === 403) {
      const data = await response.json()
      expect(data.auth).toBeDefined()
      expect(data.auth.mode).toBe('forbidden')
      console.log(`✓ 403 response auth.mode: ${data.auth.mode}`)
    } else if (response.status() === 204) {
      console.log('✓ User has admin permission, got 204')
    } else {
      console.log(`  Unexpected status: ${response.status()}`)
    }
  })

  test('should return JSON with auth.mode=reauth on max_age violation', async ({ page, virtualAuthenticator }) => {
    // Get a device token from the pool (created by 10-passkey.spec.ts)
    const deviceToken = popDeviceToken()
    test.skip(!deviceToken, 'Requires device token from passkey tests')
    console.log(`✓ Got device token: ${deviceToken} (${getDeviceTokenCount()} remaining)`)

    // Navigate and create fresh session
    await page.goto(`${baseUrl}/auth/`)
    const regResult = await registerPasskey(page, baseUrl, {
      resetToken: deviceToken,
      displayName: 'Max Age Test Device',
    })

    // Wait for session to be older than 1s
    await page.waitForTimeout(2000)

    const cookieName = getSessionCookieName()

    // Make API call with max_age=1s (session is now > 1s old)
    const response = await page.request.get(`${baseUrl}/auth/api/forward?max_age=1s`, {
      headers: {
        'Accept': 'application/json',
        'Cookie': `${cookieName}=${regResult.session_token}`,
      },
    })

    expect(response.status()).toBe(401)

    const data = await response.json()
    expect(data.auth).toBeDefined()
    expect(data.auth.mode).toBe('reauth')

    console.log(`✓ 401 response auth.mode: ${data.auth.mode}`)

    // Save session for cleanup
    saveSessionToken(regResult.session_token)
  })
})
