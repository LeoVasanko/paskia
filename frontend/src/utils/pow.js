/**
 * Proof of Work utility using PBKDF2-SHA512
 *
 * The PoW requires finding nonces where PBKDF2(challenge, nonce) produces
 * output with a zero first byte. Each work unit requires finding one such nonce.
 * All valid nonces are concatenated into a solution for server verification.
 */

/**
 * Solve a Proof of Work challenge
 *
 * @param {Uint8Array|ArrayBuffer} challenge - 8-byte server-provided challenge
 * @param {number} work - Number of PBKDF2 work units required
 * @param {object} [options] - Optional parameters
 * @param {AbortSignal} [options.signal] - AbortSignal to cancel the operation
 * @returns {Promise<Uint8Array>} Solution: concatenated 8-byte nonces (8 * work bytes)
 * @throws {Error} If challenge is invalid or operation is aborted
 */
export async function solvePoW(challenge, work, options = {}) {
  const { signal } = options
  const startTime = performance.now()

  // Validate inputs
  const challengeBytes = challenge instanceof ArrayBuffer
    ? new Uint8Array(challenge)
    : challenge

  if (!(challengeBytes instanceof Uint8Array) || challengeBytes.length !== 8) {
    throw new Error('Challenge must be exactly 8 bytes')
  }

  // Import challenge as PBKDF2 key material
  const baseKey = await crypto.subtle.importKey('raw', challengeBytes, 'PBKDF2', false, ['deriveBits'])

  // Build solution from found nonces
  const solution = new Uint8Array(8 * work)
  let totalIterations = 0
  const mask = 0x7FF  // The client must work 2048x harder than the server

  // Sequential nonce starting at zero (little-endian, using Uint32Array for efficient increment)
  const nonce = new Uint32Array(2)

  for (let i = 0; i < work; i++) {
    if (signal?.aborted) {
      throw new DOMException('PoW operation aborted', 'AbortError')
    }

    // Find a nonce where PBKDF2 output passes the mask check
    let result
    do {
      totalIterations++
      if (++nonce[0] === 0x100000000) ++nonce[1]  // Increment 64-bit little-endian nonce
      result = new Uint32Array(await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: nonce, iterations: 128, hash: 'SHA-512'},
        baseKey,
        32
      ))
    } while (result[0] & mask)
    solution.set(new Uint8Array(nonce.buffer), i * 8)
  }

  const elapsed = (performance.now() - startTime) / 1000
  const expectedIterations = work * (mask + 1)
  const luckRatio = (totalIterations / expectedIterations).toFixed(1)
  const bench = totalIterations / ((mask + 1) * elapsed)
  console.log(`PoW work=${work} solved in ${elapsed.toFixed(2)}s (${luckRatio}x expected ${bench.toFixed(1)} work/s)`)
  return solution
}
