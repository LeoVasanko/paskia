import { test as base, expect, type CDPSession, type Page } from '@playwright/test'
import { existsSync, mkdirSync, writeFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const coverageDir = join(__dirname, '..', '..', 'coverage-frontend')

// Check if frontend coverage is enabled
const COLLECT_COVERAGE = process.env.COVERAGE === '1' || process.env.COVERAGE === 'true'

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
 * Extended test fixture with virtual authenticator support and optional coverage.
 */
export const test = base.extend<{
  virtualAuthenticator: VirtualAuthenticator
}>({
  virtualAuthenticator: async ({ page }, use, testInfo) => {
    // Start coverage collection if enabled
    let coverageCdp: CDPSession | null = null
    if (COLLECT_COVERAGE) {
      try {
        coverageCdp = await page.context().newCDPSession(page)
        await coverageCdp.send('Profiler.enable')
        await coverageCdp.send('Profiler.startPreciseCoverage', {
          callCount: true,
          detailed: true,
        })
      } catch {
        coverageCdp = null
      }
    }

    // Create virtual authenticator before test
    const authenticator = await createVirtualAuthenticator(page)

    // Run the test
    await use(authenticator)

    // Cleanup after test
    await removeVirtualAuthenticator(authenticator)

    // Stop and save coverage
    if (coverageCdp) {
      try {
        const { result } = await coverageCdp.send('Profiler.takePreciseCoverage')
        await coverageCdp.send('Profiler.stopPreciseCoverage')
        await coverageCdp.send('Profiler.disable')

        // Filter to only include our app's JavaScript files
        const appCoverage = result.filter((entry: any) =>
          entry.url.includes('/auth/') &&
          entry.url.endsWith('.js') &&
          !entry.url.includes('node_modules')
        )

        if (appCoverage.length > 0) {
          if (!existsSync(coverageDir)) {
            mkdirSync(coverageDir, { recursive: true })
          }
          const safeName = testInfo.title.replace(/[^a-z0-9]/gi, '_').substring(0, 50)
          const coverageFile = join(coverageDir, `coverage-${safeName}-${Date.now()}.json`)
          writeFileSync(coverageFile, JSON.stringify(appCoverage, null, 2))
        }
      } catch {
        // Silently ignore coverage collection errors
      }
    }
  },
})

export { expect }
