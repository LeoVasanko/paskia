/**
 * URL-safe Base64 encoding/decoding utilities.
 *
 * These functions handle base64url format (RFC 4648) which uses:
 * - '-' instead of '+'
 * - '_' instead of '/'
 * - No padding '=' characters
 */

/**
 * Decode a base64url string to Uint8Array.
 * Handles both standard base64 and URL-safe base64 (with or without padding).
 * @param {string} str - Base64url encoded string
 * @returns {Uint8Array} - Decoded bytes
 */
export function b64dec(str) {
  // Convert URL-safe characters to standard base64
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  // Add padding if needed
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4)
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0))
}

/**
 * Encode a Uint8Array to base64url string.
 * @param {Uint8Array} bytes - Bytes to encode
 * @returns {string} - Base64url encoded string (no padding)
 */
export function b64enc(bytes) {
  const base64 = btoa(String.fromCharCode(...bytes))
  // Convert to URL-safe and remove padding
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
