import { test, expect } from './fixtures/virtual-authenticator'
import {
  logout,
  getSessionCookieName,
  getSavedSessionToken,
} from './fixtures/passkey-helpers'

/**
 * Logout test - runs last to clean up the session.
 * The "99-" prefix ensures this runs after all other tests.
 */
test.describe('Logout', () => {
  const baseUrl = process.env.BASE_URL || 'http://localhost:4404'

  test('should logout successfully', async ({ page }) => {
    const sessionToken = getSavedSessionToken()
    test.skip(!sessionToken, 'Requires saved session token')

    await logout(page, baseUrl, sessionToken!)

    // Session should no longer be valid
    const cookieName = getSessionCookieName()
    const response = await page.request.post(`${baseUrl}/auth/api/validate`, {
      headers: {
        'Cookie': `${cookieName}=${sessionToken}`,
      },
      failOnStatusCode: false,
    })

    expect(response.status()).toBe(401)
    console.log(`✓ Logout successful, session invalidated`)
  })
})
