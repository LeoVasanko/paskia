import { join, dirname } from 'path'
import { existsSync, rmSync, readFileSync } from 'fs'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const testDataDir = join(__dirname, '..', 'test-data')
const stateFile = join(testDataDir, 'test-state.json')

interface TestState {
  resetToken?: string
  serverPid?: number
}

/**
 * Global teardown for E2E tests.
 * 
 * This cleans up the test server and optionally removes the test database.
 */
export default async function globalTeardown() {
  console.log('\n🧹 Cleaning up E2E test environment...\n')
  
  // Read state file to get server PID
  if (existsSync(stateFile)) {
    try {
      const state: TestState = JSON.parse(readFileSync(stateFile, 'utf-8'))
      
      if (state.serverPid) {
        console.log(`  Stopping server (PID: ${state.serverPid})...`)
        try {
          process.kill(state.serverPid, 'SIGTERM')
          // Wait a moment for graceful shutdown
          await new Promise(r => setTimeout(r, 500))
        } catch (err: any) {
          // Process may already be dead
          if (err.code !== 'ESRCH') {
            console.warn(`  Warning: Could not kill server: ${err.message}`)
          }
        }
      }
    } catch (err) {
      console.warn('  Warning: Could not read state file')
    }
    
    // Clean up state file
    rmSync(stateFile, { force: true })
  }
  
  // Optionally clean up test database (keep it for debugging by default)
  if (process.env.CLEANUP_TEST_DB === 'true') {
    const dbPath = join(testDataDir, 'test.sqlite')
    if (existsSync(dbPath)) {
      console.log('  Removing test database...')
      rmSync(dbPath)
    }
    // Remove wal/shm files too
    for (const ext of ['-wal', '-shm']) {
      const file = dbPath + ext
      if (existsSync(file)) rmSync(file)
    }
  }
  
  console.log('  ✅ Cleanup complete\n')
}
