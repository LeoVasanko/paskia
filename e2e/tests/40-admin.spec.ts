import { test, expect, type Page, type Locator } from '@playwright/test'
import { getSavedSessionToken, getSessionCookieName } from './fixtures/passkey-helpers'

const baseUrl = process.env.BASE_URL || 'http://localhost:4404'

async function openAdmin(page: Page) {
  const sessionToken = getSavedSessionToken()
  test.skip(!sessionToken, 'Requires the saved master-admin session')
  await page.context().addCookies([{
    name: getSessionCookieName(),
    value: sessionToken!,
    domain: 'localhost',
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'Strict',
  }])
  await page.goto(`${baseUrl}/auth/admin/`)
  await expect(page.getByRole('heading', { name: 'Organizations', exact: true })).toBeVisible()
}

async function apiResponse(page: Page, method: string, path: string, action: () => Promise<void>) {
  const pending = page.waitForResponse(response =>
    response.request().method() === method && new URL(response.url()).pathname === path
  )
  await action()
  const response = await pending
  expect(response.status(), `${method} ${path}`).toBe(200)
}

function dialog(page: Page, title: string | RegExp) {
  return page.locator('.modal-panel').filter({ has: page.locator('.modal-title', { hasText: title }) })
}

async function createPermission(page: Page, scope: string, displayName: string) {
  await page.getByRole('button', { name: '+ Create Permission' }).click()
  const form = dialog(page, 'Create Permission')
  await form.getByLabel('Display Name').fill(displayName)
  await form.getByLabel('Permission Scope').fill(scope)
  await apiResponse(page, 'POST', '/auth/api/admin/permissions/', () => form.getByRole('button', { name: 'Save' }).click())
  await expect(permissionRow(page, scope)).toBeVisible()
}

async function seedPermission(page: Page, scope: string, displayName: string) {
  const response = await page.request.post(`${baseUrl}/auth/api/admin/permissions/`, {
    headers: { Cookie: `${getSessionCookieName()}=${getSavedSessionToken()}` },
    data: { scope, display_name: displayName },
  })
  expect(response.status()).toBe(200)
  await page.reload()
  await expect(permissionRow(page, scope)).toBeVisible()
}

function permissionRow(page: Page, scope: string) {
  return page.locator('.permissions-section').filter({ has: page.getByRole('heading', { name: 'Permissions', exact: true }) })
    .locator('tbody tr').filter({ has: page.locator('.id-text', { hasText: scope }) })
}

async function permissionUuid(page: Page, scope: string) {
  const uuid = await page.evaluate(async (scope) => {
    const response = await fetch('/auth/api/admin/info')
    const data = await response.json()
    return Object.entries(data.permissions).find(([, permission]: any) => permission.scope === scope)?.[0]
  }, scope)
  expect(uuid).toBeTruthy()
  return uuid as string
}

async function fillAndSave(form: Locator, label: string, value: string) {
  await form.getByLabel(label, { exact: true }).fill(value)
  await form.getByRole('button', { name: 'Save' }).click()
}

test.describe('Admin application E2E', () => {
  test.describe.configure({ mode: 'serial' })

  test('creates a permission through the UI', async ({ page }) => {
    await openAdmin(page)
    await createPermission(page, 'e2e:create', 'E2E Create')
  })

  test('creates and edits a permission through the UI', async ({ page }) => {
    await openAdmin(page)
    await seedPermission(page, 'e2e:edit', 'E2E Edit')
    const uuid = await permissionUuid(page, 'e2e:edit')
    const row = permissionRow(page, 'e2e:edit')
    await row.getByRole('button', { name: 'Edit permission' }).click()
    const form = dialog(page, 'Edit Permission')
    await form.getByLabel('Display Name').fill('E2E Edited')
    await form.getByLabel('Permission Scope').fill('e2e:edited')
    await apiResponse(page, 'PATCH', `/auth/api/admin/permissions/${uuid}`, () => form.getByRole('button', { name: 'Save' }).click())
    await expect(permissionRow(page, 'e2e:edited')).toContainText('E2E Edited')
  })

  test('deletes a permission through the UI', async ({ page }) => {
    await openAdmin(page)
    await seedPermission(page, 'e2e:delete', 'E2E Delete')
    const uuid = await permissionUuid(page, 'e2e:delete')
    const row = permissionRow(page, 'e2e:delete')
    await apiResponse(page, 'DELETE', `/auth/api/admin/permissions/${uuid}`, () => row.getByRole('button', { name: 'Delete permission' }).click())
    await expect(permissionRow(page, 'e2e:delete')).toHaveCount(0)
  })

  test('manages organizations, roles, users, and grant matrices', async ({ page }) => {
    await openAdmin(page)
    await createPermission(page, 'e2e:grant', 'E2E Grant')

    await page.getByRole('button', { name: '+ Create Org' }).click()
    await fillAndSave(dialog(page, 'Create Organization'), 'Name', 'E2E Org')
    const orgLink = page.getByRole('link', { name: 'E2E Org', exact: true })
    await expect(orgLink).toBeVisible()

    let orgRow = page.locator('.org-table tbody tr').filter({ has: orgLink })
    await orgRow.getByRole('button', { name: 'Rename organization' }).click()
    await fillAndSave(dialog(page, 'Rename Organization'), 'Organization Name', 'E2E Organization')
    await expect(page.getByRole('link', { name: 'E2E Organization', exact: true })).toBeVisible()

    const orgIndex = await page.locator('.permissions-section .perm-matrix-grid').first().locator('.org-head').evaluateAll(
      (heads: Element[]) => heads.findIndex(head => head.textContent === 'E2E Organization')
    )
    expect(orgIndex).toBeGreaterThanOrEqual(0)
    const orgMatrix = page.locator('.permissions-section .perm-matrix-grid').first()
    const orgPermissionCell = orgMatrix.locator('.perm-name[title="e2e:grant"]')
      .locator('xpath=following-sibling::div[contains(@class,"matrix-cell")]').nth(orgIndex)
    await orgPermissionCell.locator('input').check()
    await expect(orgPermissionCell.locator('input')).toBeChecked()

    await page.getByRole('link', { name: 'E2E Organization', exact: true }).click()
    await expect(page.locator('.org-title')).toContainText('E2E Organization')
    await page.locator('.add-role-head').click()
    await fillAndSave(dialog(page, 'Create Role'), 'Role Name', 'E2E Role')
    const roleColumn = page.locator('.role-column').filter({ hasText: 'E2E Role' })
    await expect(roleColumn).toBeVisible()

    await roleColumn.getByRole('button', { name: 'Edit role' }).click()
    await fillAndSave(dialog(page, 'Edit Role'), 'Role Name', 'E2E Members')
    const membersColumn = page.locator('.role-column').filter({ hasText: 'E2E Members' })
    await expect(membersColumn).toBeVisible()

    const roleIndex = await page.locator('.org-title + .matrix-wrapper .role-head').evaluateAll(
      (heads: Element[]) => heads.findIndex(head => head.textContent === 'E2E Members')
    )
    expect(roleIndex).toBeGreaterThanOrEqual(0)
    const rolePermissionCell = page.locator('.org-title + .matrix-wrapper .perm-name[title="e2e:grant"]')
      .locator('xpath=following-sibling::div[contains(@class,"matrix-cell")]').nth(roleIndex)
    await rolePermissionCell.locator('input').check()
    await expect(rolePermissionCell.locator('input')).toBeChecked()

    await membersColumn.getByRole('button', { name: 'Add user' }).click()
    await fillAndSave(dialog(page, 'Add User To Role'), 'Display Name', 'E2E User')
    const userChip = membersColumn.locator('.user-chip').filter({ hasText: 'E2E User' })
    await expect(userChip).toBeVisible()
    await userChip.click()
    await expect(page.locator('.user-detail')).toBeVisible()

    await page.getByTitle('Edit profile').click()
    await fillAndSave(dialog(page, 'Edit User Name'), 'Display Name', 'E2E Renamed User')
    await expect(page.locator('.user-detail .display-name')).toHaveText('E2E Renamed User')

    await page.getByRole('button', { name: 'Registration Link' }).click()
    const registration = page.locator('.device-dialog')
    await expect(registration).toBeVisible()
    await expect(registration.locator('a.qr-link')).toHaveAttribute('href', /\/auth\//)
    await registration.locator('button.btn-secondary', { hasText: 'Close' }).click()
    await page.getByRole('button', { name: 'Delete User' }).click()
    await expect(page.locator('.org-title')).toContainText('E2E Organization')
    await expect(page.locator('.user-chip').filter({ hasText: 'E2E Renamed User' })).toHaveCount(0)

    await membersColumn.getByRole('button', { name: 'Delete role' }).click()
    await expect(membersColumn).toHaveCount(0)
    await page.getByRole('link', { name: 'Admin', exact: true }).click()
    orgRow = page.locator('.org-table tbody tr').filter({ hasText: 'E2E Organization' })
    await orgRow.getByRole('button', { name: 'Delete organization' }).click()
    await expect(orgRow).toHaveCount(0)
  })

  test('manages OIDC clients, secrets, redirect URIs, and groups', async ({ page }) => {
    await openAdmin(page)
    await page.getByRole('button', { name: '+ Add Site' }).click()
    const newClient = page.locator('.oidc-form')
    await newClient.getByLabel('Client Name').fill('E2E OIDC')
    await newClient.getByLabel('Redirect URIs').fill('https://client.example.com/callback')
    await newClient.getByRole('button', { name: 'Save' }).click()
    const clientLink = page.getByRole('link', { name: 'E2E OIDC', exact: true })
    await expect(clientLink).toBeVisible()
    await clientLink.click()

    const existing = page.locator('.oidc-form')
    await existing.getByLabel('Client Name').fill('E2E OIDC Updated')
    await existing.getByTitle('Revoke and re-generate secret').click()
    await existing.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByRole('link', { name: 'E2E OIDC Updated', exact: true })).toBeVisible()
    await page.getByRole('link', { name: 'E2E OIDC Updated', exact: true }).click()

    await page.getByTitle('Add permission scoped to this client').click()
    const group = dialog(page, 'Create Permission')
    await group.getByLabel('Display Name').fill('E2E Group')
    await group.getByLabel('Permission Scope').fill('e2e:oidc:group')
    await group.getByRole('button', { name: 'Save' }).click()
    await expect(page.locator('.oidc-group')).toHaveText('e2e:oidc:group')

    await page.getByRole('button', { name: 'Delete Client' }).click()
    await dialog(page, 'Confirm').getByRole('button', { name: 'OK' }).click()
    await expect(page.getByRole('link', { name: 'E2E OIDC Updated', exact: true })).toHaveCount(0)
  })

  test('creates, edits, and deletes a domain through the UI', async ({ page }) => {
    await openAdmin(page)
    await page.getByRole('button', { name: '+ Add Domain', exact: true }).click()
    const form = dialog(page, 'Add Domain')
    await form.getByLabel('Domain (rp-id)').fill('e2e.localhost')
    await form.getByLabel('Display Name (rp-name)').fill('E2E Domain')
    await form.getByRole('button', { name: 'Save' }).click()
    const domainLink = page.getByRole('link', { name: 'E2E Domain', exact: true })
    await expect(domainLink).toBeVisible()
    await domainLink.click()

    const edit = dialog(page, 'Edit Domain: e2e.localhost')
    await edit.getByLabel('Display Name (rp-name)').fill('E2E Domain Updated')
    await edit.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByRole('link', { name: 'E2E Domain Updated', exact: true })).toBeVisible()
    const row = page.locator('.domains-section tbody tr').filter({ hasText: 'e2e.localhost' })
    await row.getByRole('button', { name: 'Delete domain' }).click()
    await dialog(page, 'Confirm').getByRole('button', { name: 'OK' }).click()
    await expect(row).toHaveCount(0)
  })

  test('validates uplink registration input through the satellites panel', async ({ page }) => {
    await openAdmin(page)
    await expect(page.getByRole('heading', { name: 'Satellites', exact: true })).toBeVisible()
    await expect(page.getByText('No satellites registered.')).toBeVisible()
    await page.getByRole('button', { name: '+ Add uplink' }).click()
    const form = dialog(page, 'Add uplink')
    await form.getByLabel('Link URL').fill('wss://invalid@127.0.0.1:1')
    await form.getByRole('button', { name: 'Register' }).click()
    await expect(form.locator('.error')).toBeVisible()
    await form.getByRole('button', { name: 'Cancel' }).click()
  })
})
