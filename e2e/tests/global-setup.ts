import { spawn } from 'child_process'
import { join, dirname } from 'path'
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'fs'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const testDataDir = join(__dirname, '..', 'test-data')
const stateFile = join(testDataDir, 'test-state.json')
const dbPath = join(testDataDir, 'test.sqlite')

interface TestState {
  resetToken?: string
  serverPid?: number
}

/**
 * Global setup for E2E tests.
 *
 * This creates a fresh test database and starts the server,
 * capturing the bootstrap reset token for initial user registration.
 */
export default async function globalSetup() {
  console.log('\n🔧 Setting up E2E test environment...\n')

  // Create test data directory
  if (!existsSync(testDataDir)) {
    mkdirSync(testDataDir, { recursive: true })
  }

  // Remove old database for clean state
  if (existsSync(dbPath)) {
    console.log('  Removing old test database...')
    rmSync(dbPath)
  }

  // Remove any wal/shm files too
  for (const ext of ['-wal', '-shm']) {
    const file = dbPath + ext
    if (existsSync(file)) rmSync(file)
  }

  console.log('  Starting server with fresh database...')

  const state: TestState = {}

  // Start the server using Node's spawn
  const serverProcess = spawn('uv', [
    'run', 'passkey-auth', 'serve', ':4401',
    '--rp-id', 'localhost',
    '--origin', 'http://localhost:4401'
  ], {
    cwd: testDataDir, // Run from test-data so DB is created there
    env: {
      ...process.env,
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
      // Format: http://localhost:4401/auth/{token} where token is word.word.word.word.word (dot separated)
      const match = output.match(/http:\/\/localhost:\d+\/auth\/([a-z]+(?:\.[a-z]+)+)/)
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

  // Save state for tests
  writeFileSync(stateFile, JSON.stringify(state, null, 2))

  console.log('  ✅ E2E test environment ready\n')
}
