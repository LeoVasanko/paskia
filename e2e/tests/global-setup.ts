import { execFileSync, spawn, spawnSync } from 'child_process'
import { join, dirname } from 'path'
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'fs'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const testDataDir = join(__dirname, '..', 'test-data')
const stateFile = join(testDataDir, 'test-state.json')
const projectRoot = join(__dirname, '..', '..')

// Check if coverage is enabled
const COLLECT_COVERAGE = process.env.COVERAGE === '1' || process.env.COVERAGE === 'true'

interface TestState {
  resetToken?: string
  serverPid?: number
  sessionCookie?: string
}

/**
 * Global setup for E2E tests.
 *
 * Bootstraps a fresh combined database (paskia.kantadb) with two domains —
 * localhost (default) and test.localhost — then starts the server with the
 * test data directory as its working directory. Captures the bootstrap reset
 * token from 'paskia init' output for initial user registration.
 */
export default async function globalSetup() {
  console.log('\n🔧 Setting up E2E test environment...\n')

  // Start from a clean slate: the test data directory doubles as the server
  // working directory, so paskia.kantadb and paskia.data/ are created here
  rmSync(testDataDir, { recursive: true, force: true })
  mkdirSync(testDataDir, { recursive: true })

  // Build the package first
  console.log('  Building package with uv build...')
  execFileSync('uv', ['build'], { cwd: projectRoot, stdio: 'inherit' })
  console.log('  ✅ Build complete\n')

  if (COLLECT_COVERAGE) {
    console.log('  📊 Coverage collection enabled for Python backend')
  }

  const state: TestState = {}

  // Bootstrap the database: two domains, localhost and test.localhost
  console.log('  Bootstrapping database with paskia init...')
  const initResult = spawnSync(
    'uv',
    [
      'run', '--project', projectRoot,
      'paskia', 'init', '-l', 'localhost:4404', 'localhost',
    ],
    { cwd: testDataDir, encoding: 'utf-8' }
  )
  const initOutput = `${initResult.stdout}${initResult.stderr}`
  process.stdout.write(initOutput)
  if (initResult.status !== 0) {
    throw new Error(`paskia init failed with exit code ${initResult.status}`)
  }
  const addResult = spawnSync(
    'uv',
    ['run', '--project', projectRoot, 'paskia', 'init', 'test.localhost'],
    { cwd: testDataDir, encoding: 'utf-8' }
  )
  process.stdout.write(`${addResult.stdout}${addResult.stderr}`)
  if (addResult.status !== 0) {
    throw new Error(`paskia init test.localhost failed with exit code ${addResult.status}`)
  }

  // Parse the reset token from init output
  // Format: http://localhost:4404/auth/{token} where token is dot-separated words
  const match = initOutput.match(/https?:\/\/localhost(?::\d+)?\/auth\/([a-z]+(?:\.[a-z]+)+)/)
  if (!match) {
    throw new Error('Failed to capture reset token from paskia init output')
  }
  state.resetToken = match[1]
  console.log(`\n  ✅ Captured reset token: ${state.resetToken}\n`)

  // Start the server (serve mode: all configuration comes from the database)
  console.log('  Starting server...')
  const serverArgs = COLLECT_COVERAGE
    ? [
        'run', '--project', projectRoot,
        'coverage', 'run', '--parallel-mode',
        '-m', 'paskia', '-l', 'localhost:4404'
      ]
    : [
        'run', '--project', projectRoot,
        'paskia', '-l', 'localhost:4404'
      ]

  const serverProcess = spawn('uv', serverArgs, {
    cwd: testDataDir,
    env: {
      ...process.env,
      COVERAGE_FILE: join(projectRoot, '.coverage'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  state.serverPid = serverProcess.pid

  serverProcess.stdout?.on('data', (data: Buffer) => process.stdout.write(data))
  serverProcess.stderr?.on('data', (data: Buffer) => process.stderr.write(data))

  serverProcess.on('exit', (code) => {
    if (code !== 0 && code !== null) {
      console.error(`Server exited unexpectedly with code ${code}`)
    }
  })

  // Wait for the server to become ready and fetch the session cookie name
  console.log('  Waiting for server readiness...')
  const deadline = Date.now() + 30000
  let settings: any = null
  while (Date.now() < deadline) {
    try {
      const response = await fetch('http://localhost:4404/auth/api/settings')
      if (response.ok) {
        settings = await response.json()
        break
      }
    } catch {
      // Not up yet
    }
    await new Promise(r => setTimeout(r, 250))
  }
  if (!settings) {
    serverProcess.kill()
    throw new Error('Server did not become ready in time (30s)')
  }
  state.sessionCookie = settings.session_cookie
  console.log(`  ✅ Session cookie name: ${state.sessionCookie}`)
  console.log(`  ✅ Domain: ${settings.rp_id} (${settings.rp_name})\n`)

  // Save state for tests
  writeFileSync(stateFile, JSON.stringify(state, null, 2))

  console.log('  ✅ E2E test environment ready\n')
}
