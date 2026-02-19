from datetime import timedelta

# Shared configuration constants for session management.
SESSION_LIFETIME = timedelta(hours=24)

# Lifetime for reset links created by admins
RESET_LIFETIME = timedelta(days=14)
