// Utility functions

export function formatDate(dateString) {
  if (!dateString) return 'Never'

  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now - date
  const diffMinutes = Math.floor(diffMs / (1000 * 60))
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))

  if (diffMs < 0 || diffDays > 7) return date.toLocaleDateString()
  if (diffMinutes === 0) return 'Just now'
  if (diffMinutes < 60) return diffMinutes === 1 ? 'a minute ago' : `${diffMinutes} minutes ago`
  if (diffHours < 24) return diffHours === 1 ? 'an hour ago' : `${diffHours} hours ago`
  return diffDays === 1 ? 'a day ago' : `${diffDays} days ago`
}

export function getCookie(name) {
  const value = `; ${document.cookie}`
  const parts = value.split(`; ${name}=`)
  if (parts.length === 2) return parts.pop().split(';').shift()
}
