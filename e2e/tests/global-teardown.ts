import { join, dirname } from 'path'
import { existsSync, rmSync, readFileSync, readdirSync, writeFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { execSync } from 'child_process'

const __dirname = dirname(fileURLToPath(import.meta.url))
const testDataDir = join(__dirname, '..', 'test-data')
const stateFile = join(testDataDir, 'test-state.json')
const projectRoot = join(__dirname, '..', '..')
const coverageDir = join(__dirname, '..', 'coverage-frontend')

// Check if coverage is enabled
const COLLECT_COVERAGE = process.env.COVERAGE === '1' || process.env.COVERAGE === 'true'

interface TestState {
  resetToken?: string
  serverPid?: number
}

interface CoverageEntry {
  url: string
  functions: Array<{
    functionName: string
    ranges: Array<{ count: number }>
  }>
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
          // Wait longer for graceful shutdown and coverage data flush
          await new Promise(r => setTimeout(r, COLLECT_COVERAGE ? 2000 : 500))
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

  // Clean up test database
  const testDbFile = join(testDataDir, 'test.paskiadb')
  if (existsSync(testDbFile)) {
    console.log('  Removing test database...')
    rmSync(testDbFile)
  }

  // Generate Python coverage report if coverage was collected
  if (COLLECT_COVERAGE) {
    console.log('  📊 Generating Python coverage report...')
    try {
      // Combine parallel coverage data and generate reports
      execSync('uv run coverage combine', { cwd: projectRoot, stdio: 'inherit' })
      execSync('uv run coverage report', { cwd: projectRoot, stdio: 'inherit' })
      execSync('uv run coverage html', { cwd: projectRoot, stdio: 'inherit' })
      console.log(`  ✅ Python coverage report: ${join(projectRoot, 'coverage-html', 'index.html')}\n`)
    } catch (err: any) {
      console.warn(`  Warning: Failed to generate coverage report: ${err.message}`)
    }

    // Merge and report frontend coverage
    if (existsSync(coverageDir)) {
      try {
        const files = readdirSync(coverageDir).filter(f => f.startsWith('coverage-') && f.endsWith('.json') && f !== 'coverage-merged.json')

        if (files.length > 0) {
          const merged: Map<string, CoverageEntry> = new Map()

          for (const file of files) {
            const data: CoverageEntry[] = JSON.parse(readFileSync(join(coverageDir, file), 'utf-8'))
            for (const entry of data) {
              const existing = merged.get(entry.url)
              if (!existing) {
                merged.set(entry.url, entry)
              } else {
                // Merge function coverage counts
                for (const func of entry.functions) {
                  const existingFunc = existing.functions.find(f => f.functionName === func.functionName)
                  if (existingFunc) {
                    for (let i = 0; i < func.ranges.length && i < existingFunc.ranges.length; i++) {
                      existingFunc.ranges[i].count += func.ranges[i].count
                    }
                  } else {
                    existing.functions.push(func)
                  }
                }
              }
            }
          }

          // Write merged coverage
          writeFileSync(
            join(coverageDir, 'coverage-merged.json'),
            JSON.stringify(Array.from(merged.values()), null, 2)
          )

          // Generate simple coverage summary
          let totalFunctions = 0
          let coveredFunctions = 0

          for (const entry of merged.values()) {
            for (const func of entry.functions) {
              totalFunctions++
              const hasCoverage = func.ranges.some(r => r.count > 0)
              if (hasCoverage) coveredFunctions++
            }
          }

          const percentage = totalFunctions > 0 ? Math.round((coveredFunctions / totalFunctions) * 100) : 0
          console.log(`  📊 Frontend JS Coverage: ${coveredFunctions}/${totalFunctions} functions (${percentage}%)`)
          console.log(`  ✅ Frontend coverage data: ${coverageDir}/coverage-merged.json\n`)
        }
      } catch (err: any) {
        console.warn(`  Warning: Failed to merge frontend coverage: ${err.message}`)
      }
    }
  }

  console.log('  ✅ Cleanup complete\n')
}
