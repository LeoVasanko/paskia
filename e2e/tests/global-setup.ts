import { spawn } from 'child_process'
import { join, dirname } from 'path'
import { existsSync, mkdirSync, writeFileSync } from 'fs'
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
 * Uses in-memory SQLite database for fast, isolated tests.
 * Captures the bootstrap reset token for initial user registration.
 */
export default async function globalSetup() {
  console.log('\n🔧 Setting up E2E test environment...\n')

  // Create test data directory for state file
  if (!existsSync(testDataDir)) {
    mkdirSync(testDataDir, { recursive: true })
  }

  console.log('  Starting server with in-memory database...')
  if (COLLECT_COVERAGE) {
    console.log('  📊 Coverage collection enabled for Python backend')
  }

  const state: TestState = {}

  // Build server command - with or without coverage
  const serverArgs = COLLECT_COVERAGE
    ? [
        'run', 'coverage', 'run', '--parallel-mode',
        '-m', 'paskia', '-l', 'localhost:4404',
        '--rp-id', 'localhost'
      ]
    : [
        'run', 'paskia', '-l', 'localhost:4404',
        '--rp-id', 'localhost'
      ]

  // Use a fresh database file for tests
  const testDbFile = join(testDataDir, 'test.paskiadb')

  // Start the server using Node's spawn
  const serverProcess = spawn('uv', serverArgs, {
    cwd: projectRoot,
    env: {
      ...process.env,
      PASKIA_DB: testDbFile,
      COVERAGE_FILE: join(projectRoot, '.coverage'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  state.serverPid = serverProcess.pid

  // Capture output to find reset token
  const resetTokenPromise = new Promise<string>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Timed out waiting for server bootstrap (30s)'))
    }, 30000)

    let output = ''

    const handleData = (data: Buffer) => {
      const text = data.toString()
      output += text
      process.stdout.write(text) // Echo to console

      // Look for the reset token URL in the output
      // Format: https://localhost/auth/{token} or http://localhost:4404/auth/{token}
      // where token is word.word.word.word.word (dot separated)
      const match = output.match(/https?:\/\/localhost(?::\d+)?\/auth\/([a-z]+(?:\.[a-z]+)+)/)
      if (match) {
        clearTimeout(timeout)
        // Wait a bit for server to fully start
        setTimeout(() => resolve(match[1]), 1000)
      }
    }

    serverProcess.stdout?.on('data', handleData)
    serverProcess.stderr?.on('data', handleData)

    serverProcess.on('error', (err) => {
      clearTimeout(timeout)
      reject(err)
    })

    serverProcess.on('exit', (code) => {
      if (code !== 0 && code !== null) {
        clearTimeout(timeout)
        reject(new Error(`Server exited with code ${code}`))
      }
    })
  })

  try {
    state.resetToken = await resetTokenPromise
    console.log(`\n  ✅ Captured reset token: ${state.resetToken}\n`)
  } catch (err) {
    console.error('Failed to capture reset token:', err)
    serverProcess.kill()
    throw err
  }

  // Fetch session cookie name from server settings
  try {
    const response = await fetch('http://localhost:4404/auth/api/settings')
    const settings = await response.json()
    state.sessionCookie = settings.session_cookie
    console.log(`  ✅ Session cookie name: ${state.sessionCookie}\n`)
  } catch (err) {
    console.error('Failed to fetch settings:', err)
    serverProcess.kill()
    throw err
  }

  // Save state for tests
  writeFileSync(stateFile, JSON.stringify(state, null, 2))

  console.log('  ✅ E2E test environment ready\n')
}
