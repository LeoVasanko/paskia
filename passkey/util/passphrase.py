import secrets

from .wordlist import words


def generate(n=4, sep="."):
    """Generate a password of random words without repeating any word."""
    wl = list(words)
    return sep.join(wl.pop(secrets.randbelow(len(wl))) for i in range(n))
