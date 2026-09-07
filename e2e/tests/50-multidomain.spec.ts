import { test, expect } from './fixtures/virtual-authenticator'
import {
  registerPasskey,
  getSessionCookieName,
  popDeviceToken,
} from './fixtures/passkey-helpers'
import {
  startRemoteAuthRequest,
  awaitRemoteAuthSession,
  permitRemoteAuth,
} from './fixtures/remote-auth'

/**
 * Multi-domain E2E tests.
 *
 * The server is bootstrapped with two domains: localhost (default) and
 * test.localhost. Chrome resolves any *.localhost hostname to loopback, so
 * both domains are reachable over real HTTP from the browser.
 *
 * Covers:
 * - Host-based domain dispatch (settings, 421 for unknown hosts)
 * - Related Origin Requests well-known endpoint + admin domain API,
 *   including HTTP dispatch to a related hostname
 * - Per-domain auth hosts: settings, UI at the site root, /auth/ redirect
 * - WebSocket cross-domain rule: rejected unless the Host is the origin
 *   domain's own auth host
 * - Cross-domain remote login: a passkey registered on localhost permits a
 *   session on test.localhost via pairing code
 * - The profile enrollment prompt on a domain where the user has no passkey
 */

test.describe('Multi-domain E2E', () => {
  test.describe.configure({ mode: 'serial' })

  const baseUrl = process.env.BASE_URL || 'http://localhost:4404'
  const domainUrl = 'http://test.localhost:4404'

  test('dispatches domains by host header', async ({ page }) => {
    // Browser navigation: Chrome maps *.localhost to loopback
    const domainResp = await page.goto(`${domainUrl}/auth/api/settings`)
    expect(domainResp?.status()).toBe(200)
    const domainSettings = await domainResp?.json()
    expect(domainSettings.rp_id).toBe('test.localhost')
    expect(domainSettings.own_auth_host).toBeNull()
    expect(domainSettings.auth_host).toBeNull()
    expect(domainSettings.ui_base_path).toBe('/auth/')

    const defaultResp = await page.goto(`${baseUrl}/auth/api/settings`)
    expect(defaultResp?.status()).toBe(200)
    const defaultSettings = await defaultResp?.json()
    expect(defaultSettings.rp_id).toBe('localhost')
    expect(defaultSettings.auth_host).toBeNull()
    expect(defaultSettings.ui_base_path).toBe('/auth/')

    // Unknown host is rejected with 421 Misdirected Request.
    // page.request is Node-side, so target loopback with an explicit Host.
    const unknownResp = await page.request.get(`${baseUrl}/auth/api/settings`, {
      headers: { Host: 'unknown.example.org' },
    })
    expect(unknownResp.status()).toBe(421)
  })

  test('well-known webauthn endpoint reflects related origins', async ({ page }) => {
    // No related origins configured initially → 404
    const before = await page.request.get(`${baseUrl}/.well-known/webauthn`)
    expect(before.status()).toBe(404)
  })

  test('master admin manages domains and related origins via API', async ({ page, virtualAuthenticator }) => {
    // Fresh session via device token (domain writes require recent auth)
    const deviceToken = popDeviceToken()
    test.skip(!deviceToken, 'No device tokens available')
    await page.goto('/auth/')
    const reg = await registerPasskey(page, baseUrl, { resetToken: deviceToken })
    expect(reg.session_token).toBeTruthy()

    const headers = { Cookie: `${getSessionCookieName()}=${reg.session_token}` }

    // List domains
    const list = await page.request.get(`${baseUrl}/auth/api/admin/domains/`, { headers })
    expect(list.ok()).toBeTruthy()
    const domains = await list.json()
    expect(domains.map((r: any) => r.rp_id).sort()).toEqual(['localhost', 'test.localhost'])
    const localhostDomain = domains.find((r: any) => r.rp_id === 'localhost')
    expect(localhostDomain.origins).toEqual({ '**.localhost': true })

    // Add a related origin (unrelated domain) to the localhost domain —
    // same origins table; classification is derived from the rp-id
    const patch = await page.request.patch(`${baseUrl}/auth/api/admin/domains/localhost`, {
      headers,
      data: { rp_name: '', origins: { '**.localhost': true, 'app.example.com': true } },
    })
    expect(patch.ok()).toBeTruthy()

    // The well-known endpoint now lists it
    const wk = await page.request.get(`${baseUrl}/.well-known/webauthn`)
    expect(wk.ok()).toBeTruthy()
    const wkJson = await wk.json()
    expect(wkJson.origins).toContain('https://app.example.com')

    // The related hostname now dispatches to the listing domain (HTTP).
    // page.request is Node-side, so target loopback with an explicit Host.
    const relResp = await page.request.get(`${baseUrl}/auth/api/settings`, {
      headers: { Host: 'app.example.com' },
    })
    expect(relResp.ok()).toBeTruthy()
    expect((await relResp.json()).rp_id).toBe('localhost')

    // Restore: back to the pristine seeded state for later tests
    const restore = await page.request.patch(`${baseUrl}/auth/api/admin/domains/localhost`, {
      headers,
      data: { rp_name: '', origins: { '**.localhost': true } },
    })
    expect(restore.ok()).toBeTruthy()
    const after = await page.request.get(`${baseUrl}/.well-known/webauthn`)
    expect(after.status()).toBe(404)

    // ...and the related hostname is unknown again
    const relGone = await page.request.get(`${baseUrl}/auth/api/settings`, {
      headers: { Host: 'app.example.com' },
    })
    expect(relGone.status()).toBe(421)
  })

  test('per-domain auth host serves the domain UI at its site root', async ({ page, virtualAuthenticator }) => {
    // Fresh session via device token (domain writes require recent auth)
    const deviceToken = popDeviceToken()
    test.skip(!deviceToken, 'No device tokens available')
    await page.goto('/auth/')
    const reg = await registerPasskey(page, baseUrl, { resetToken: deviceToken })
    expect(reg.session_token).toBeTruthy()

    const headers = { Cookie: `${getSessionCookieName()}=${reg.session_token}` }
    const authHost = 'auth.test.localhost:4404'

    try {
      // Mark an auth host on the test.localhost domain. Chrome resolves any
      // *.localhost hostname to loopback, so the auth host is reachable.
      const patch = await page.request.patch(`${baseUrl}/auth/api/admin/domains/test.localhost`, {
        headers,
        data: { rp_name: '', origins: { [`http://${authHost}`]: { auth_host: true }, '**.test.localhost': true } },
      })
      expect(patch.ok()).toBeTruthy()

      // The auth host dispatches to its domain and reports itself in settings
      const settingsResp = await page.goto(`http://${authHost}/auth/api/settings`)
      expect(settingsResp?.status()).toBe(200)
      const settings = await settingsResp?.json()
      expect(settings.rp_id).toBe('test.localhost')
      expect(settings.auth_host).toBe(authHost)
      expect(settings.own_auth_host).toBe(authHost)
      expect(settings.ui_base_path).toBe('/')

      // The UI lives at the site root on the auth host
      const rootResp = await page.goto(`http://${authHost}/`)
      expect(rootResp?.status()).toBe(200)
      expect(rootResp?.headers()['content-type']).toContain('text/html')

      // /auth/ on the auth host redirects to the root
      const redir = await page.request.get(`${baseUrl}/auth/`, {
        headers: { Host: authHost },
        maxRedirects: 0,
      })
      expect(redir.status()).toBe(307)
      expect(redir.headers()['location']).toMatch(/^http:\/\/auth\.test\.localhost(:\d+)?\/$/)
    } finally {
      // Restore: back to the pristine seeded state (later tests sign in on
      // test.localhost, and an empty table would allow nothing)
      const restore = await page.request.patch(`${baseUrl}/auth/api/admin/domains/test.localhost`, {
        headers,
        data: { rp_name: '', origins: { '**.test.localhost': true } },
      })
      expect(restore.ok()).toBeTruthy()
    }

    const after = await page.request.get(`${baseUrl}/auth/api/settings`, {
      headers: { Host: 'test.localhost:4404' },
    })
    expect((await after.json()).auth_host).toBeNull()
  })

  test('WebSocket cross-domain connections require the origin domain\'s own auth host', async ({ page }) => {
    await page.goto(`${domainUrl}/auth/`)

    // Same-domain WebSocket receives authentication options...
    const sameDomain: any = await page.evaluate(async () => {
      return new Promise((resolve) => {
        const ws = new WebSocket(`ws://${location.host}/auth/ws/authenticate`)
        const timer = setTimeout(() => { ws.close(); resolve({ message: false }) }, 5000)
        ws.onmessage = () => { clearTimeout(timer); ws.close(); resolve({ message: true }) }
        ws.onerror = () => { clearTimeout(timer); resolve({ message: false }) }
      })
    })
    expect(sameDomain.message).toBe(true)

    // ...but a cross-domain connection is closed pre-accept: test.localhost
    // has no auth host of its own, so no other host may serve its logins
    const crossDomain: any = await page.evaluate(async (host) => {
      return new Promise((resolve) => {
        const ws = new WebSocket(`ws://${host}/auth/ws/authenticate`)
        let message = false
        const timer = setTimeout(() => { ws.close(); resolve({ message, code: -1 }) }, 5000)
        ws.onmessage = () => { message = true }
        ws.onclose = (event) => {
          clearTimeout(timer)
          resolve({ message, code: event.code, wasClean: event.wasClean })
        }
      })
    }, new URL(baseUrl).host)
    expect(crossDomain.message).toBe(false)
    expect(crossDomain.wasClean).toBe(false)
  })

  test('cross-domain remote login via pairing code', async ({ page, virtualAuthenticator }) => {
    // Register a fresh passkey on localhost (this test's virtual authenticator)
    const deviceToken = popDeviceToken()
    test.skip(!deviceToken, 'No device tokens available')
    await page.goto('/auth/')
    const reg = await registerPasskey(page, baseUrl, { resetToken: deviceToken })
    expect(reg.session_token).toBeTruthy()

    // Requester page on the other domain (no session there)
    const reqPage = await page.context().newPage()
    await reqPage.goto(`${domainUrl}/auth/`)

    const pairingCode = await startRemoteAuthRequest(reqPage)
    expect(pairingCode.split('.')).toHaveLength(3)

    // Approver permits with the localhost passkey; the "found" message names
    // the requesting domain
    const found = await permitRemoteAuth(page, pairingCode)
    expect(found.rp_id).toBe('test.localhost')

    // The requester redeems the exchange code on its own domain and the
    // session validates there for the same user
    const validation = await awaitRemoteAuthSession(reqPage)
    expect(validation.ctx.user.uuid).toBe(reg.user)

    // The session is recorded with the requesting host
    const userInfo = await reqPage.evaluate(async () => {
      const resp = await fetch('/auth/api/user-info')
      if (!resp.ok) throw new Error(`user-info failed: ${resp.status}`)
      return resp.json()
    })
    const current = Object.values(userInfo.sessions as any[]).find((s: any) => s.is_current) as any
    expect(current.host).toContain('test.localhost')

    // The profile on test.localhost prompts adding a passkey for this domain,
    // and the existing localhost passkey carries a domain badge
    await reqPage.goto(`${domainUrl}/auth/`)
    const notice = reqPage.locator('.domain-enroll-notice')
    await expect(notice).toBeVisible({ timeout: 15000 })
    await expect(notice).toContainText('test.localhost')
    await expect(reqPage.locator('.badge-domain').first()).toHaveText('localhost')

    await reqPage.close()
  })
})
