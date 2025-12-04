import { test as base, expect, type CDPSession, type Page } from '@playwright/test'

/**
 * Virtual Authenticator configuration for WebAuthn testing.
 * Uses Chrome DevTools Protocol to create a software authenticator.
 */
export interface VirtualAuthenticatorOptions {
  protocol?: 'ctap1/u2f' | 'ctap2'
  transport?: 'usb' | 'nfc' | 'ble' | 'internal'
  hasResidentKey?: boolean
  hasUserVerification?: boolean
  isUserVerified?: boolean
  automaticPresenceSimulation?: boolean
}

export interface VirtualAuthenticator {
  authenticatorId: string
  cdpSession: CDPSession
}

/**
 * Create a virtual authenticator using Chrome DevTools Protocol.
 * This allows fully automated passkey registration and authentication.
 */
export async function createVirtualAuthenticator(
  page: Page,
  options: VirtualAuthenticatorOptions = {}
): Promise<VirtualAuthenticator> {
  const cdpSession = await page.context().newCDPSession(page)

  // Enable WebAuthn in CDP
  await cdpSession.send('WebAuthn.enable', {
    enableUI: false, // Suppress any UI prompts
  })

  // Create the virtual authenticator with resident key support
  const { authenticatorId } = await cdpSession.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: options.protocol ?? 'ctap2',
      transport: options.transport ?? 'internal',
      hasResidentKey: options.hasResidentKey ?? true,
      hasUserVerification: options.hasUserVerification ?? true,
      isUserVerified: options.isUserVerified ?? true,
      automaticPresenceSimulation: options.automaticPresenceSimulation ?? true,
    },
  })

  return { authenticatorId, cdpSession }
}

/**
 * Remove a virtual authenticator.
 */
export async function removeVirtualAuthenticator(
  authenticator: VirtualAuthenticator
): Promise<void> {
  await authenticator.cdpSession.send('WebAuthn.removeVirtualAuthenticator', {
    authenticatorId: authenticator.authenticatorId,
  })
  await authenticator.cdpSession.send('WebAuthn.disable')
}

/**
 * Get all credentials stored in a virtual authenticator.
 */
export async function getCredentials(
  authenticator: VirtualAuthenticator
): Promise<any[]> {
  const result = await authenticator.cdpSession.send('WebAuthn.getCredentials', {
    authenticatorId: authenticator.authenticatorId,
  })
  return result.credentials
}

/**
 * Extended test fixture with virtual authenticator support.
 */
export const test = base.extend<{
  virtualAuthenticator: VirtualAuthenticator
}>({
  virtualAuthenticator: async ({ page }, use) => {
    // Create virtual authenticator before test
    const authenticator = await createVirtualAuthenticator(page)

    // Run the test
    await use(authenticator)

    // Cleanup after test
    await removeVirtualAuthenticator(authenticator)
  },
})

export { expect }
