"""Tests for startup box sign-in summaries (paskia/util/startupbox.py).

Pruning must mirror the actual origin matching in sansio._allowlisted:
wildcards cover https origins (any port) under their base, except under
localhost where any scheme and any port match.
"""

from paskia.util.startupbox import _signin_summary


def test_auth_host_pruned_under_full_wildcard():
    """'**.vasanko.com' already covers auth.vasanko.com."""
    keys = ["**.vasanko.com", "auth.vasanko.com"]
    assert _signin_summary(keys, "vasanko.com") == "all subdomains"


def test_http_origin_not_covered_by_https_wildcard():
    """Plain http outside localhost is not wildcard-covered; stays listed."""
    keys = ["**.example.com", "http://app.example.com"]
    summary = _signin_summary(keys, "example.com")
    assert summary == "all subdomains, http://app.example.com"


def test_localhost_wildcard_covers_any_scheme_and_port():
    keys = ["**.localhost", "http://localhost:3000", "localhost:8080"]
    assert _signin_summary(keys, "localhost") == "all subdomains"


def test_https_port_key_covered_by_wildcard():
    """Wildcards match https origins at any port, so 'host:8443' is redundant."""
    keys = ["**.example.com", "app.example.com:8443"]
    assert _signin_summary(keys, "example.com") == "all subdomains"


def test_single_level_wildcard_pruning():
    """'*.example.com' covers one subdomain level only."""
    keys = ["*.example.com", "app.example.com", "deep.app.example.com"]
    summary = _signin_summary(keys, "example.com")
    assert summary == "subdomains, deep.app.example.com"


def test_no_wildcard_keeps_all_entries():
    keys = ["auth.example.com", "app.example.com"]
    summary = _signin_summary(keys, "example.com")
    assert summary == "app.example.com, auth.example.com"


def test_entries_outside_wildcard_base_kept():
    keys = ["**.app.example.com", "auth.example.com"]
    summary = _signin_summary(keys, "example.com")
    assert summary == "all subdomains of app.example.com, auth.example.com"
