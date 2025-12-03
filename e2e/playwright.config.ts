import { defineConfig, devices } from '@playwright/test'

/**
 * Playwright configuration for PasskeyAuth E2E tests.
 * Uses Chrome's Virtual Authenticator for automated passkey testing.
 * 
 * Run with: bun run test
 */

export default defineConfig({
  testDir: './tests',
  fullyParallel: false, // Run tests sequentially for passkey state consistency
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1, // Single worker for database state consistency
  reporter: [
    ['html', { open: 'never' }],
    ['list']
  ],
  
  // Global setup/teardown for test database and server
  globalSetup: './tests/global-setup.ts',
  globalTeardown: './tests/global-teardown.ts',
  
  use: {
    // Base URL for the passkey-auth server
    baseURL: process.env.BASE_URL || 'http://localhost:4401',
    
    // Collect trace on failure for debugging
    trace: 'on-first-retry',
    
    // Screenshot on failure
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // Chrome-specific settings for virtual authenticator
        launchOptions: {
          args: [
            '--enable-features=WebAuthenticationEnterpriseAttestation',
          ],
        },
      },
    },
  ],
})
