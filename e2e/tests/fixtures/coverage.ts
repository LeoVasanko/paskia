import { test as base, type Page, type CDPSession } from '@playwright/test'
import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const coverageDir = join(__dirname, '..', '..', 'coverage-frontend')

// Check if frontend coverage is enabled
const COLLECT_COVERAGE = process.env.COVERAGE === '1' || process.env.COVERAGE === 'true'

interface CoverageEntry {
  url: string
  scriptId: string
  source?: string
  functions: Array<{
    functionName: string
    ranges: Array<{
      startOffset: number
      endOffset: number
      count: number
    }>
    isBlockCoverage: boolean
  }>
}

/**
 * Collect V8 JavaScript coverage from the page.
 */
async function startCoverage(page: Page): Promise<CDPSession | null> {
  if (!COLLECT_COVERAGE) return null

  try {
    const cdp = await page.context().newCDPSession(page)
    await cdp.send('Profiler.enable')
    await cdp.send('Profiler.startPreciseCoverage', {
      callCount: true,
      detailed: true,
    })
    return cdp
  } catch {
    return null
  }
}

async function stopCoverage(cdp: CDPSession | null, testName: string): Promise<void> {
  if (!cdp) return

  try {
    const { result } = await cdp.send('Profiler.takePreciseCoverage')
    await cdp.send('Profiler.stopPreciseCoverage')
    await cdp.send('Profiler.disable')

    // Filter to only include our app's JavaScript files
    const appCoverage = result.filter((entry: CoverageEntry) =>
      entry.url.includes('/auth/') &&
      entry.url.endsWith('.js') &&
      !entry.url.includes('node_modules')
    )

    if (appCoverage.length > 0) {
      // Ensure coverage directory exists
      if (!existsSync(coverageDir)) {
        mkdirSync(coverageDir, { recursive: true })
      }

      // Save coverage data for this test
      const safeName = testName.replace(/[^a-z0-9]/gi, '_').substring(0, 50)
      const coverageFile = join(coverageDir, `coverage-${safeName}-${Date.now()}.json`)
      writeFileSync(coverageFile, JSON.stringify(appCoverage, null, 2))
    }
  } catch (err) {
    // Silently ignore coverage collection errors
  }
}

/**
 * Merge all coverage files into a single summary.
 */
export async function mergeCoverage(): Promise<void> {
  if (!COLLECT_COVERAGE || !existsSync(coverageDir)) return

  const files = require('fs').readdirSync(coverageDir).filter((f: string) => f.startsWith('coverage-') && f.endsWith('.json'))
  if (files.length === 0) return

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
            for (let i = 0; i < func.ranges.length; i++) {
              if (existingFunc.ranges[i]) {
                existingFunc.ranges[i].count += func.ranges[i].count
              }
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
  console.log(`\n  📊 Frontend JS Coverage: ${coveredFunctions}/${totalFunctions} functions (${percentage}%)`)
  console.log(`  ✅ Frontend coverage data: ${coverageDir}/coverage-merged.json\n`)
}

/**
 * Extended test with coverage collection.
 * This wraps each test to collect V8 coverage data.
 */
export const testWithCoverage = base.extend<{
  coverageSession: CDPSession | null
}>({
  coverageSession: async ({ page }, use, testInfo) => {
    const cdp = await startCoverage(page)
    await use(cdp)
    await stopCoverage(cdp, testInfo.title)
  },
})
