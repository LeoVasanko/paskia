// Utility functions

export function formatDate(dateString) {
  if (!dateString) return 'Never'

  const date = new Date(dateString)
  const now = new Date()
  const diffMs = date - now  // Changed to date - now for future/past
  const isFuture = diffMs > 0
  const absDiffMs = Math.abs(diffMs)
  const diffMinutes = Math.round(absDiffMs / (1000 * 60))
  const diffHours = Math.round(absDiffMs / (1000 * 60 * 60))
  const diffDays = Math.round(absDiffMs / (1000 * 60 * 60 * 24))

  if (absDiffMs < 1000 * 60) return 'Now'
  if (diffMinutes <= 60) return isFuture ? `In ${diffMinutes} minute${diffMinutes === 1 ? '' : 's'}` : diffMinutes === 1 ? 'a minute ago' : `${diffMinutes} minutes ago`
  if (diffHours <= 24) return isFuture ? `In ${diffHours} hour${diffHours === 1 ? '' : 's'}` : diffHours === 1 ? 'an hour ago' : `${diffHours} hours ago`
  if (diffDays <= 14) return isFuture ? `In ${diffDays} day${diffDays === 1 ? '' : 's'}` : diffDays === 1 ? 'a day ago' : `${diffDays} days ago`
  return date.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' })
}

export function getCookie(name) {
  const value = `; ${document.cookie}`
  const parts = value.split(`; ${name}=`)
  if (parts.length === 2) return parts.pop().split(';').shift()
}

export const goBack = () => history.back() || window.close()
