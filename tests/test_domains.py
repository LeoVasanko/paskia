"""Tests for the multi-domain machinery: registry resolution, config
validation, ASGI dispatch, domain binding of auth codes, legacy database
conversion, log censoring and bootstrap caveats.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from uuid import UUID

import httpx
import pytest
from kanta import Kanta

from paskia import authcode, domains
from paskia.bootstrap import check_admin_credentials
from paskia.db import create_credential
from paskia.db.legacy import (
    LegacyConfig,
    LegacyCredential,
    LegacyDB,
    LegacySession,
    convert_legacy_database,
)
from paskia.db.lifecycle import format_log_uuid
from paskia.db.operations import DB
from paskia.db.structs import (
    OIDC,
    Client,
    Config,
    Credential,
    DomainConfig,
    OriginEntry,
    Session,
)
from paskia.fastapi.dispatch import DispatchMiddleware
from paskia.sansio import Passkey
from paskia.util.crypto import hash_secret

# -------------------------------------------------------------------------
# Registry construction helpers
# -------------------------------------------------------------------------


def build_registry(configs: dict[str, DomainConfig]) -> domains.DomainRegistry:
    """Build and install a registry from domain configs (listen unset)."""
    domains.configure(listen=None)
    return domains.init_registry(Config(domains=configs))


ROR_CONFIG = Config(
    domains={
        "company.com": DomainConfig(
            rp_name="Company",
            origins={
                "auth.company.com": OriginEntry(auth_host=True),
                "app.com": True,  # related origin (outside the rp-id domain)
            },
        ),
        "pro.com": DomainConfig(rp_name="Pro", origins={"**.pro.com": True}),
    }
)


class StubApp:
    """ASGI app recording the scope it was called with."""

    def __init__(self):
        self.scope = None

    async def __call__(self, scope, receive, send):
        self.scope = scope


async def drive_ws(middleware: DispatchMiddleware, headers: list[tuple[bytes, bytes]]):
    """Run a websocket scope through the middleware, capturing sent messages."""

    async def receive():
        return {"type": "websocket.connect"}

    sent = []

    async def send(message):
        sent.append(message)

    stub = middleware.app
    await middleware(
        {"type": "websocket", "headers": headers, "path": "/"}, receive, send
    )
    return stub, sent


async def drive_http(
    middleware: DispatchMiddleware, headers: list[tuple[bytes, bytes]]
):
    """Run an http scope through the middleware, capturing sent messages."""

    async def receive():
        return {"type": "http.request", "body": b""}

    sent = []

    async def send(message):
        sent.append(message)

    stub = middleware.app
    await middleware(
        {
            "type": "http",
            "headers": headers,
            "method": "GET",
            "path": "/",
            "query_string": b"",
        },
        receive,
        send,
    )
    return stub, sent


# -------------------------------------------------------------------------
# Host resolution
# -------------------------------------------------------------------------


class TestResolve:
    def test_exact_rp_id(self):
        reg = build_registry(ROR_CONFIG.domains)
        assert reg.resolve("pro.com").rp_id == "pro.com"
        assert reg.resolve("company.com").rp_id == "company.com"

    def test_auth_host_and_related_origin(self):
        reg = build_registry(ROR_CONFIG.domains)
        assert reg.resolve("auth.company.com").rp_id == "company.com"
        assert reg.resolve("app.com").rp_id == "company.com"

    def test_subdomain_suffix_longest_match(self):
        reg = build_registry(
            {"example.com": DomainConfig(), "sub.example.com": DomainConfig()}
        )
        assert reg.resolve("www.example.com").rp_id == "example.com"
        assert reg.resolve("api.sub.example.com").rp_id == "sub.example.com"

    def test_port_and_trailing_dot_normalized(self):
        reg = build_registry(ROR_CONFIG.domains)
        assert reg.resolve("pro.com:8443").rp_id == "pro.com"
        assert reg.resolve("app.com.").rp_id == "company.com"

    def test_unknown_host(self):
        reg = build_registry(ROR_CONFIG.domains)
        assert reg.resolve("evil.com") is None
        assert reg.resolve("") is None
        assert reg.resolve(None) is None

    def test_auth_host_is_per_domain_no_fallback(self):
        reg = build_registry(ROR_CONFIG.domains)
        assert reg.get("company.com").own_auth_host == "auth.company.com"
        # pro.com has no own auth host and there is no cross-domain fallback
        assert reg.get("pro.com").own_auth_host is None

    def test_shared_auth_host_resolves_best_suffix(self):
        """Domains may share an auth host (nested rp-ids); the longest
        rp-id suffix match wins, first configured as tiebreak."""
        reg = build_registry(
            {
                "com": DomainConfig(
                    origins={"auth.company.com": OriginEntry(auth_host=True)}
                ),
                "company.com": DomainConfig(
                    origins={"auth.company.com": OriginEntry(auth_host=True)}
                ),
            }
        )
        assert reg.resolve("auth.company.com").rp_id == "company.com"


# -------------------------------------------------------------------------
# Cross-domain configuration validation
# -------------------------------------------------------------------------


class TestValidateConfig:
    def test_valid(self):
        domains.validate_config(ROR_CONFIG)

    def test_empty_origins_table_is_valid(self):
        """No origins at all: nothing of the domain is allowed, but the
        configuration itself is legal (e.g. a related-only domain)."""
        domains.validate_config(Config(domains={"a.com": DomainConfig()}))
        domains.validate_config(
            Config(domains={"a.com": DomainConfig(origins={"b.com": True})})
        )

    def test_related_origin_cap(self):
        domains.validate_config(
            Config(
                domains={
                    "company.com": DomainConfig(
                        origins={f"app{i}.com": True for i in range(5)}
                    )
                }
            )
        )
        with pytest.raises(ValueError, match="related origins"):
            domains.validate_config(
                Config(
                    domains={
                        "company.com": DomainConfig(
                            origins={f"app{i}.com": True for i in range(6)}
                        )
                    }
                )
            )

    def test_star_origin_rejected(self):
        """Plain '*' suggests 'anything goes' — the wildcard must be
        explicit and under the rp-id."""
        with pytest.raises(ValueError, match="not allowed"):
            domains.validate_config(
                Config(domains={"a.com": DomainConfig(origins={"*": True})})
            )

    def test_malformed_origin_hostname_rejected(self):
        """No empty hostname labels — leading, trailing and double dots
        are invalid, in concrete entries and wildcard bases alike."""
        for key in (".a.com", "a..com", "a.com.", "http://.a.com:8080"):
            with pytest.raises(ValueError, match="Invalid origin"):
                domains.validate_config(
                    Config(domains={"a.com": DomainConfig(origins={key: True})})
                )
        for key in ("*..a.com", "**..a.com"):
            with pytest.raises(ValueError, match="Invalid wildcard origin"):
                domains.validate_config(
                    Config(domains={"a.com": DomainConfig(origins={key: True})})
                )

    def test_subdomain_entry_is_in_domain(self):
        """An entry within the rp-id domain is an ordinary in-domain
        sign-in site, never a related origin."""
        config = Config(domains={"a.com": DomainConfig(origins={"app.a.com": True})})
        domains.validate_config(config)
        reg = build_registry(config.domains)
        assert reg.get("a.com").related_origins == []

    def test_wildcard_outside_rp_id_rejected(self):
        """Related origins are individual hosts; wildcards must stay within
        the rp-id domain. Both wildcard forms are accepted in-domain."""
        domains.validate_config(
            Config(domains={"a.com": DomainConfig(origins={"*.a.com": True})})
        )
        domains.validate_config(
            Config(domains={"a.com": DomainConfig(origins={"**.a.com": True})})
        )
        with pytest.raises(ValueError, match="wildcard outside the rp-id"):
            domains.validate_config(
                Config(domains={"a.com": DomainConfig(origins={"**.b.com": True})})
            )

    def test_wildcard_auth_host_rejected(self):
        with pytest.raises(ValueError, match="cannot be the auth host"):
            domains.validate_config(
                Config(
                    domains={
                        "a.com": DomainConfig(
                            origins={"*.a.com": OriginEntry(auth_host=True)}
                        )
                    }
                )
            )

    def test_related_auth_host_rejected(self):
        """The auth host is always in-domain; a related origin cannot
        carry the mark."""
        with pytest.raises(ValueError, match="cannot be the auth host"):
            domains.validate_config(
                Config(
                    domains={
                        "a.com": DomainConfig(
                            origins={"auth.b.com": OriginEntry(auth_host=True)}
                        )
                    }
                )
            )

    def test_several_auth_hosts_rejected(self):
        with pytest.raises(ValueError, match="several origins as the auth host"):
            domains.validate_config(
                Config(
                    domains={
                        "a.com": DomainConfig(
                            origins={
                                "auth.a.com": OriginEntry(auth_host=True),
                                "login.a.com": OriginEntry(auth_host=True),
                            }
                        )
                    }
                )
            )

    def test_auth_host_collision(self):
        with pytest.raises(ValueError, match="collides with a related origin"):
            domains.validate_config(
                Config(
                    domains={
                        "a.com": DomainConfig(
                            origins={"auth.a.com": OriginEntry(auth_host=True)}
                        ),
                        "b.com": DomainConfig(origins={"auth.a.com": True}),
                    }
                )
            )

    def test_related_origin_may_fall_inside_other_domain(self):
        """A related origin at/inside another domain's rp-id is allowed.
        The related listing wins dispatch over suffix matching (a host that
        *is* a configured rp-id always serves its own domain)."""
        config = Config(
            domains={
                "a.com": DomainConfig(origins={"app.b.com": True}),
                "b.com": DomainConfig(),
            }
        )
        domains.validate_config(config)
        reg = build_registry(config.domains)
        assert reg.resolve("app.b.com").rp_id == "a.com"
        assert reg.resolve("b.com").rp_id == "b.com"

    def test_related_origin_shared_when_covered_by_rp_id(self):
        """Two domains may list the same related host when it falls inside
        a configured rp-id; otherwise the collision is rejected."""
        domains.validate_config(
            Config(
                domains={
                    "a.com": DomainConfig(origins={"app.b.com": True}),
                    "c.com": DomainConfig(origins={"app.b.com": True}),
                    "b.com": DomainConfig(),
                }
            )
        )
        with pytest.raises(ValueError, match="configured for both"):
            domains.validate_config(
                Config(
                    domains={
                        "a.com": DomainConfig(origins={"shared.com": True}),
                        "c.com": DomainConfig(origins={"shared.com": True}),
                    }
                )
            )

    def test_auth_host_must_not_collide_with_rp_id(self):
        with pytest.raises(ValueError, match="collides with an rp-id"):
            domains.validate_config(
                Config(
                    domains={
                        "a.com": DomainConfig(
                            origins={"b.a.com": OriginEntry(auth_host=True)}
                        ),
                        "b.a.com": DomainConfig(),
                    }
                )
            )


# -------------------------------------------------------------------------
# Best-effort serving: stored config sanitization
# -------------------------------------------------------------------------


class TestSanitizeConfig:
    """Serving never fails on stored config problems; it degrades + warns."""

    def test_cross_domain_origin_stays_as_related(self):
        """An out-of-domain entry simply IS a related origin — no repair
        needed, no warning."""
        config, warnings = domains.sanitize_config(
            Config(domains={"localhost": DomainConfig(origins={"example.com": True})})
        )
        assert config.domains["localhost"].origins == {"example.com": True}
        assert not warnings
        domains.validate_config(config)  # sanitized config is strict-clean

    def test_star_origin_rewritten_explicit(self):
        """Branch-era '*' shorthand is rewritten to '**.{rp-id}'; an auth
        mark on it is cleared."""
        config, warnings = domains.sanitize_config(
            Config(domains={"a.com": DomainConfig(origins={"*": True})})
        )
        assert config.domains["a.com"].origins == {"**.a.com": True}
        assert any("**." in w for w in warnings)
        domains.validate_config(config)

        config, warnings = domains.sanitize_config(
            Config(
                domains={
                    "a.com": DomainConfig(origins={"*": OriginEntry(auth_host=True)})
                }
            )
        )
        assert config.domains["a.com"].origins == {"**.a.com": True}
        assert any("mark cleared" in w for w in warnings)
        domains.validate_config(config)

    def test_malformed_origin_dropped(self):
        config, warnings = domains.sanitize_config(
            Config(domains={"a.com": DomainConfig(origins={"https://": True})})
        )
        assert config.domains["a.com"].origins == {}
        assert warnings

    def test_malformed_hostname_dropped(self):
        """Empty hostname labels (leading/trailing/double dots) are dropped,
        from concrete entries and wildcard bases alike."""
        config, warnings = domains.sanitize_config(
            Config(
                domains={
                    "a.com": DomainConfig(
                        origins={
                            ".a.com": True,
                            "a.com.": True,
                            "**.a..com": True,
                            "ok.a.com": True,
                        }
                    )
                }
            )
        )
        assert list(config.domains["a.com"].origins) == ["ok.a.com"]
        assert len(warnings) == 3
        domains.validate_config(config)  # sanitized config is strict-clean

    def test_invalid_rp_id_domain_dropped(self):
        config, warnings = domains.sanitize_config(
            Config(domains={"not a domain!": DomainConfig(), "ok.com": DomainConfig()})
        )
        assert list(config.domains) == ["ok.com"]
        assert any("dropped" in w for w in warnings)

    def test_wildcard_outside_rp_id_dropped(self):
        config, warnings = domains.sanitize_config(
            Config(domains={"a.com": DomainConfig(origins={"*.b.com": True})})
        )
        assert config.domains["a.com"].origins == {}
        assert any("wildcard" in w for w in warnings)
        domains.validate_config(config)  # sanitized config is strict-clean

    def test_cap_exceeded_truncated(self):
        config, warnings = domains.sanitize_config(
            Config(
                domains={
                    "a.com": DomainConfig(
                        origins={f"app{i}.com": True for i in range(6)}
                    )
                }
            )
        )
        assert len(config.domains["a.com"].origins) == 5
        assert any("maximum" in w for w in warnings)
        domains.validate_config(config)

    def test_related_auth_host_mark_cleared(self):
        """An auth mark on a related (out-of-domain) origin is cleared."""
        config, warnings = domains.sanitize_config(
            Config(
                domains={
                    "a.com": DomainConfig(
                        origins={"auth.b.com": OriginEntry(auth_host=True)}
                    )
                }
            )
        )
        assert config.domains["a.com"].origins == {"auth.b.com": True}
        assert any("cannot be the auth host" in w for w in warnings)
        domains.validate_config(config)

    def test_auth_host_colliding_with_rp_id_cleared(self):
        config, warnings = domains.sanitize_config(
            Config(
                domains={
                    "a.com": DomainConfig(
                        origins={"auth.a.com": OriginEntry(auth_host=True)}
                    ),
                    "auth.a.com": DomainConfig(),
                }
            )
        )
        assert config.domains["a.com"].origins == {"auth.a.com": True}
        assert any("collides" in w for w in warnings)

    def test_related_inside_other_domain_kept(self):
        """A related origin falling inside another domain's rp-id is kept."""
        config, _ = domains.sanitize_config(
            Config(
                domains={
                    "a.com": DomainConfig(origins={"app.b.com": True}),
                    "b.com": DomainConfig(),
                }
            )
        )
        assert config.domains["a.com"].origins == {"app.b.com": True}

    def test_related_claimed_twice_first_wins(self):
        """Two non-owner domains claiming one related host: first wins."""
        config, warnings = domains.sanitize_config(
            Config(
                domains={
                    "a.com": DomainConfig(origins={"shared.com": True}),
                    "b.com": DomainConfig(origins={"shared.com": True}),
                }
            )
        )
        assert config.domains["a.com"].origins == {"shared.com": True}
        assert config.domains["b.com"].origins == {}
        assert any("first domain wins" in w for w in warnings)

    def test_no_domains_is_fatal(self):
        with pytest.raises(ValueError, match="No servable domain"):
            domains.sanitize_config(Config(domains={}))
        with pytest.raises(ValueError, match="No servable domain"):
            domains.sanitize_config(Config(domains={"not a domain!": DomainConfig()}))

    def test_build_serves_related_origin(self):
        reg = build_registry({"localhost": DomainConfig(origins={"example.com": True})})
        domain = reg.get("localhost")
        assert domain.related_origins == ["https://example.com"]
        domain.passkey.validate_origin("https://example.com")


# -------------------------------------------------------------------------
# Origin validation semantics (Passkey)
# -------------------------------------------------------------------------


class TestOriginValidation:
    """The allow-list is explicit: empty allows nothing, wildcards cover
    subtrees, related origins are additive exact matches."""

    def test_empty_allow_list_denies_all(self):
        p = Passkey(rp_id="example.com")
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://example.com")
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://app.example.com")

    def test_allow_list_restricts_subtree(self):
        p = Passkey(rp_id="example.com", origins=["https://app.example.com"])
        assert p.validate_origin("https://app.example.com")
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://www.example.com")
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://example.com")

    def test_related_origins_are_additive(self):
        p = Passkey(rp_id="example.com", related_origins=["https://app2.com"])
        assert p.validate_origin("https://app2.com")
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://app.example.com")  # nothing in-domain listed
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://other.com")

    def test_double_star_matches_apex_and_any_depth(self):
        """'**.example.com' covers the apex and subdomains at any depth
        (the shell-glob convention)."""
        p = Passkey(rp_id="example.com", origins=["**.example.com"])
        assert p.validate_origin("https://example.com")  # apex
        assert p.validate_origin("https://app.example.com")  # one level
        assert p.validate_origin("https://a.b.c.example.com")  # any depth
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://anotherexample.com")
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://other.com")

    def test_single_star_matches_exactly_one_level(self):
        """'*.example.com' covers exactly one subdomain level — neither the
        apex nor deeper levels."""
        p = Passkey(rp_id="example.com", origins=["*.example.com"])
        assert p.validate_origin("https://app.example.com")
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://example.com")  # apex excluded
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://a.b.example.com")  # too deep

    def test_wildcard_is_https_only(self):
        """A '**.example.com' entry does not fall back to other schemes."""
        p = Passkey(rp_id="example.com", origins=["**.example.com"])
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("http://example.com")
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("http://app.example.com:8080")

    def test_star_entry_rejected(self):
        with pytest.raises(ValueError, match="Invalid origin"):
            Passkey(rp_id="example.com", origins=["*"])

    def test_malformed_hostname_rejected(self):
        """Leading/trailing/double dots are invalid in any entry form."""
        with pytest.raises(ValueError, match="malformed hostname"):
            Passkey(rp_id="example.com", origins=["https://.example.com"])
        with pytest.raises(ValueError, match="malformed hostname"):
            Passkey(rp_id="example.com", origins=["**.a..example.com"])
        with pytest.raises(ValueError, match="malformed hostname"):
            Passkey(rp_id="example.com", related_origins=["https://other..com"])

    def test_localhost_wildcard_matches_any_scheme_and_port(self):
        """Under localhost, wildcards match any scheme and any port."""
        p = Passkey(rp_id="localhost", origins=["**.localhost"])
        assert p.validate_origin("http://localhost:8080")
        assert p.validate_origin("http://app.localhost:3000")
        assert p.validate_origin("http://a.b.localhost:3000")
        assert p.validate_origin("https://localhost")

    def test_exact_entry_matches_scheme_and_port(self):
        p = Passkey(rp_id="localhost", origins=["http://localhost:4403"])
        assert p.validate_origin("http://localhost:4403")
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://localhost:4403")
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("http://localhost:4404")

    def test_sub_wildcard_matches_only_its_subtree(self):
        p = Passkey(rp_id="example.com", origins=["**.app.example.com"])
        assert p.validate_origin("https://app.example.com")
        assert p.validate_origin("https://www.app.example.com")
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://example.com")
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://other.example.com")

    def test_wildcard_related_origin_rejected(self):
        with pytest.raises(ValueError, match="wildcard"):
            Passkey(rp_id="example.com", related_origins=["*.other.com"])

    def test_related_origins_combined_with_allow_list(self):
        p = Passkey(
            rp_id="example.com",
            origins=["https://app.example.com"],
            related_origins=["https://app2.com"],
        )
        assert p.validate_origin("https://app.example.com")
        assert p.validate_origin("https://app2.com")
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://www.example.com")

    def test_constructor_rejects_mixed_up_fields(self):
        with pytest.raises(ValueError, match="related origin"):
            Passkey(rp_id="example.com", origins=["https://app2.com"])
        with pytest.raises(ValueError, match="within the rp-id domain"):
            Passkey(rp_id="example.com", related_origins=["https://app.example.com"])

    def test_domain_wires_both_lists(self):
        reg = build_registry(ROR_CONFIG.domains)
        p = reg.get("company.com").passkey
        assert p.validate_origin("https://app.com")  # related origin
        assert p.validate_origin("https://auth.company.com")  # allow-listed
        with pytest.raises(ValueError, match="not allowed"):
            p.validate_origin("https://www.company.com")  # not allow-listed


# -------------------------------------------------------------------------
# ASGI dispatch
# -------------------------------------------------------------------------


class TestDispatchMiddleware:
    @pytest.mark.asyncio
    async def test_http_unknown_host_421(self):
        build_registry(ROR_CONFIG.domains)
        stub, sent = await drive_http(
            DispatchMiddleware(StubApp()), [(b"host", b"evil.com")]
        )
        assert stub.scope is None  # Inner app not called
        assert sent[0]["type"] == "http.response.start"
        assert sent[0]["status"] == 421

    @pytest.mark.asyncio
    async def test_http_dispatches_domain(self):
        build_registry(ROR_CONFIG.domains)
        stub, _sent = await drive_http(
            DispatchMiddleware(StubApp()), [(b"host", b"app.com.")]
        )
        assert stub.scope is not None
        assert stub.scope["state"]["domain"].rp_id == "company.com"

    @pytest.mark.asyncio
    async def test_http_current_domain_set_inside_request(self):
        build_registry(ROR_CONFIG.domains)
        seen = {}

        async def app(scope, receive, send):
            seen["domain"] = domains.current_domain()

        await drive_http(DispatchMiddleware(app), [(b"host", b"pro.com")])
        assert seen["domain"].rp_id == "pro.com"
        # Contextvar is reset after the request; with several domains there
        # is no implicit current domain outside a request context.
        with pytest.raises(RuntimeError, match="request context"):
            domains.current_domain()

    @pytest.mark.asyncio
    async def test_ws_unknown_host_closed(self):
        build_registry(ROR_CONFIG.domains)
        stub, sent = await drive_ws(
            DispatchMiddleware(StubApp()), [(b"host", b"evil.com")]
        )
        assert stub.scope is None
        assert sent == [{"type": "websocket.close", "code": 1008}]

    @pytest.mark.asyncio
    async def test_ws_same_domain_origin(self):
        build_registry(ROR_CONFIG.domains)
        stub, sent = await drive_ws(
            DispatchMiddleware(StubApp()),
            [(b"host", b"auth.company.com"), (b"origin", b"https://app.com")],
        )
        assert sent == []
        assert stub.scope["state"]["domain"].rp_id == "company.com"

    @pytest.mark.asyncio
    async def test_ws_cross_domain_requires_origin_own_auth_host(self):
        build_registry(ROR_CONFIG.domains)
        # pro.com has no own auth host: its page may only connect to pro.com
        # hosts — the company.com auth host does not serve foreign domains
        stub, sent = await drive_ws(
            DispatchMiddleware(StubApp()),
            [(b"host", b"auth.company.com"), (b"origin", b"https://pro.com")],
        )
        assert stub.scope is None
        assert sent == [{"type": "websocket.close", "code": 1008}]

        # pro.com page connecting to some other host: closed pre-accept
        stub, sent = await drive_ws(
            DispatchMiddleware(StubApp()),
            [(b"host", b"company.com"), (b"origin", b"https://pro.com")],
        )
        assert stub.scope is None
        assert sent == [{"type": "websocket.close", "code": 1008}]

    @pytest.mark.asyncio
    async def test_ws_cross_domain_via_own_auth_host(self):
        """On a shared auth host (nested rp-ids), the WS Origin selects the
        domain: plain HTTP resolves to the longest-suffix claimant, but a
        WebSocket from another claimant's page is dispatched by Origin."""
        build_registry(
            {
                "com": DomainConfig(
                    origins={"auth.company.com": OriginEntry(auth_host=True)}
                ),
                "company.com": DomainConfig(
                    origins={"auth.company.com": OriginEntry(auth_host=True)}
                ),
            }
        )
        # Host alone resolves to company.com (longest suffix)
        stub, sent = await drive_ws(
            DispatchMiddleware(StubApp()), [(b"host", b"auth.company.com")]
        )
        assert stub.scope["state"]["domain"].rp_id == "company.com"
        # A page on com (the other claimant) is accepted: the Host is its
        # own auth host, and the Origin selects its domain
        stub, sent = await drive_ws(
            DispatchMiddleware(StubApp()),
            [(b"host", b"auth.company.com"), (b"origin", b"https://com")],
        )
        assert sent == []
        assert stub.scope["state"]["domain"].rp_id == "com"

    @pytest.mark.asyncio
    async def test_ws_unknown_origin_uses_host_domain(self):
        build_registry(ROR_CONFIG.domains)
        # Missing origin
        stub, _ = await drive_ws(DispatchMiddleware(StubApp()), [(b"host", b"pro.com")])
        assert stub.scope["state"]["domain"].rp_id == "pro.com"
        # Unknown origin: host domain applies (endpoint-side validation decides)
        stub, _ = await drive_ws(
            DispatchMiddleware(StubApp()),
            [(b"host", b"pro.com"), (b"origin", b"https://evil.com")],
        )
        assert stub.scope["state"]["domain"].rp_id == "pro.com"


# -------------------------------------------------------------------------
# Domain binding of auth codes
# -------------------------------------------------------------------------


class TestAuthCodeDomainBinding:
    @pytest.mark.asyncio
    async def test_cookie_code_rejected_on_other_domain(
        self, client: httpx.AsyncClient, session_token: str
    ):
        code = authcode.store_cookie(
            authcode.CookieCode(
                session_key=session_token,
                created=datetime.now(UTC),
                rp_id="other.com",
            )
        )
        response = await client.post(
            "/auth/api/set-session",
            headers={
                "Authorization": f"Bearer {code}",
                "Host": "localhost:4401",
            },
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_oidc_code_is_host_independent(
        self, client: httpx.AsyncClient, test_db: DB, test_user, test_credential
    ):
        """OIDC codes carry no domain binding: the provider is
        instance-global, so a code is redeemable at any host."""
        oidc_client, secret = Client.create(
            name="Test Client",
            redirect_uris=["https://client.example/callback"],
            client_secret="topsecret",
        )
        token = "doesnotmatter1234"
        session = Session.create(
            user=test_user.uuid,
            credential=test_credential.uuid,
            key=hash_secret("oidc", token),
            host="other.com",
            ip="127.0.0.1",
            user_agent="pytest",
            validated=datetime.now(UTC),
            client=oidc_client.uuid,
            rp_id="other.com",
            issuer="https://other.com",
        )
        store = test_db._store
        with store.transaction("seed_oidc_session"):
            test_db.oidc.clients[oidc_client.uuid] = oidc_client
            test_db.sessions[session.key] = session

        code = authcode.store_oidc(
            authcode.OIDCCode(
                session_key=token,
                created=datetime.now(UTC),
                redirect_uri="https://client.example/callback",
                scope="openid",
            )
        )
        response = await client.post(
            "/auth/oidc/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://client.example/callback",
                "client_id": str(oidc_client.uuid),
                "client_secret": secret,
            },
            headers={"Host": "localhost:4401"},
        )
        assert response.status_code == 200
        assert response.json()["access_token"]


# -------------------------------------------------------------------------
# Legacy database conversion
# -------------------------------------------------------------------------


def _read_db(path) -> DB:
    async def _read() -> DB:
        new_db = DB()
        kanta = Kanta(str(path), new_db)
        await kanta.open(readonly=True)
        return kanta.data

    return asyncio.run(_read())


async def _write_legacy(src_file, config: LegacyConfig) -> None:
    kanta = Kanta(str(src_file), LegacyDB())
    await kanta.open()
    with kanta.transaction("test:seed"):
        kanta.data.config = config
    await kanta.close()


class TestLegacyConversion:
    def test_convert_stamps_domain_everywhere(self, tmp_path):
        src = tmp_path / "example.com.paskiadb"
        src.mkdir()
        src_file = src / "main.db"

        cred_uuid = UUID("019c6831-84cf-7b88-b66c-c8165890b7c5")
        user_uuid = UUID("019c6831-84cf-7b88-b66c-c8165890b7c6")

        async def _write() -> None:
            kanta = Kanta(str(src_file), LegacyDB())
            await kanta.open()
            with kanta.transaction("test:seed"):
                kanta.data.config = LegacyConfig(
                    rp_id="example.com",
                    rp_name="Example",
                    origins=["https://app.example.com", "*.example.com"],
                )
                kanta.data.credentials[cred_uuid] = LegacyCredential(
                    credential_id=b"credential-id",
                    user_uuid=user_uuid,
                    aaguid=UUID(int=0),
                    public_key=b"public-key",
                    sign_count=3,
                    created_at=datetime.now(UTC),
                )
                kanta.data.sessions["session-key"] = LegacySession(
                    user_uuid=user_uuid,
                    credential_uuid=cred_uuid,
                    host="example.com",
                    ip="127.0.0.1",
                    user_agent="pytest",
                    validated=datetime.now(UTC),
                )
                kanta.data.oidc = OIDC(key=b"legacy-signing-key")
            await kanta.close()

        asyncio.run(_write())

        config = convert_legacy_database(src_file, tmp_path / "paskia.kantadb")
        domain = config.domains["example.com"]
        assert domain.rp_name == "Example"
        # Legacy wildcard origins convert as-is (https-only outside localhost)
        assert domain.origins == {"app.example.com": True, "*.example.com": True}

        converted = _read_db(tmp_path / "paskia.kantadb")
        assert converted.credentials[cred_uuid].rp_id == "example.com"
        assert converted.sessions["session-key"].rp_id == "example.com"
        # The legacy OIDC provider carries over as the instance-global one
        assert converted.oidc.key == b"legacy-signing-key"

    def test_convert_empty_origins_seeds_wildcard(self, tmp_path):
        """Legacy 'no origins' meant the whole rp-id domain; the new format
        makes that explicit as '**.{rp-id}'."""
        src_file = tmp_path / "main.db"
        asyncio.run(
            _write_legacy(src_file, LegacyConfig(rp_id="example.com", rp_name="Ex"))
        )
        config = convert_legacy_database(src_file, tmp_path / "paskia.kantadb")
        assert config.domains["example.com"].origins == {"**.example.com": True}

    def test_convert_auth_host_with_empty_origins_keeps_wildcard(self, tmp_path):
        """A dedicated auth host with no configured origins still allowed
        the whole rp-id domain in the legacy format — the auth host must
        not become the only allowed origin."""
        src_file = tmp_path / "main.db"
        asyncio.run(
            _write_legacy(
                src_file,
                LegacyConfig(rp_id="example.com", auth_host="auth.example.com"),
            )
        )
        config = convert_legacy_database(src_file, tmp_path / "paskia.kantadb")
        origins = config.domains["example.com"].origins
        assert origins["**.example.com"] is True
        assert origins["auth.example.com"] == OriginEntry(auth_host=True)


# -------------------------------------------------------------------------
# Transaction log censoring
# -------------------------------------------------------------------------


class TestLogCensoring:
    def test_oidc_key_values_hidden(self):
        assert format_log_uuid(b"raw-key-material", "oidc.key") == "<hidden>"

    def test_oidc_key_path_component_visible(self):
        # The path component itself must stay visible ("oidc.key = <hidden>")
        assert format_log_uuid("key", "oidc.key") is None

    def test_other_paths_unaffected(self):
        assert format_log_uuid("not-a-uuid", "oidc.clients") is None
        assert format_log_uuid("not-a-uuid", "config.domains") is None


# -------------------------------------------------------------------------
# Bootstrap caveat: admin credential is checked on the configured domains
# -------------------------------------------------------------------------


class TestBootstrapCaveat:
    @pytest.mark.asyncio
    async def test_admin_without_credentials_gets_link(
        self, test_db: DB, domain_registry
    ):
        assert await check_admin_credentials() is True

    @pytest.mark.asyncio
    async def test_admin_with_domain_credential_ok(
        self, test_db: DB, domain_registry, test_user, test_credential
    ):
        assert await check_admin_credentials() is False

    @pytest.mark.asyncio
    async def test_admin_with_only_unconfigured_domain_credential_gets_link(
        self, test_db: DB, domain_registry, test_user
    ):
        """A passkey under an rp-id outside the config does not satisfy the check."""
        cred = Credential.create(
            credential_id=os.urandom(32),
            user=test_user.uuid,
            aaguid=UUID(int=0),
            public_key=os.urandom(64),
            sign_count=0,
            rp_id="example.com",
        )
        create_credential(cred)
        assert await check_admin_credentials() is True
