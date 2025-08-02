import secrets

from .wordlist import words

N_WORDS = 5

wset = set(words)


def generate(n=N_WORDS, sep="."):
    """Generate a password of random words without repeating any word."""
    wl = words.copy()
    return sep.join(wl.pop(secrets.randbelow(len(wl))) for i in range(n))


def is_well_formed(passphrase: str, n=N_WORDS, sep=".") -> bool:
    """Check if the passphrase is well-formed according to the regex pattern."""
    p = passphrase.split(sep)
    return len(p) == n and all(w in wset for w in passphrase.split("."))
