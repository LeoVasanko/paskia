// Cache for auth iframe URL by mode
const authIframeUrlCache = {}

/**
 * Get the auth iframe URL for a given mode.
 * Fetches from /auth/api/forward which returns URL in the auth.iframe field.
 * Results are cached per mode.
 * @param {string} mode - The auth mode ('login', 'reauth', 'forbidden')
 * @returns {Promise<string>} - The URL for the iframe
 */
export async function getAuthIframeUrl(mode = 'login') {
  if (authIframeUrlCache[mode]) {
    return authIframeUrlCache[mode]
  }

  // Fetch from forward endpoint - it returns URL in auth.iframe on 401/403
  const response = await fetch('/auth/api/forward')
  if (response.status === 401 || response.status === 403) {
    const data = await response.json()
    if (data.auth?.iframe) {
      // The iframe field now contains a URL with hash fragment
      // If mode differs, update the hash param
      let url = data.auth.iframe
      if (mode !== data.auth.mode) {
        url = url.replace(/mode=[^&]*/, `mode=${mode}`)
      }
      authIframeUrlCache[mode] = url
      return url
    }
  }
  throw new Error('Unable to fetch auth iframe URL')
}
