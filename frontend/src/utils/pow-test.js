import { solvePoW, verifyPoW } from './pow.js'

const TRIALS = 5
const WORK = 10

async function test() {
  console.log(`Running ${TRIALS} trials with ${WORK} work units...\n`)

  const times = []

  for (let trial = 1; trial <= TRIALS; trial++) {
    const challenge = crypto.getRandomValues(new Uint8Array(8))

    const start = performance.now()
    const solution = await solvePoW(challenge, WORK)
    const elapsed = performance.now() - start

    const valid = await verifyPoW(challenge, solution, WORK)

    times.push(elapsed)

    console.log(`Trial ${trial.toString().padStart(2)}: ${(elapsed / 1000).toFixed(3)}s, valid=${valid}`)
  }

  const avgTime = times.reduce((a, b) => a + b, 0) / times.length
  const minTime = Math.min(...times)
  const maxTime = Math.max(...times)

  console.log('\n--- Summary ---')
  console.log(`Trials: ${TRIALS}`)
  console.log(`Work units: ${WORK}`)
  console.log(`Avg time: ${(avgTime / 1000).toFixed(3)}s`)
  console.log(`Min time: ${(minTime / 1000).toFixed(3)}s`)
  console.log(`Max time: ${(maxTime / 1000).toFixed(3)}s`)
}

test()
