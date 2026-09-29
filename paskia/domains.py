"""Domain registry: per-rp-id runtime state and host resolution.

A **domain** is one rp-id with its associated hosts and origins. The
registry is built from the stored combined ``Config`` at startup and
rebuilt on admin domain changes; request dispatch resolves hosts to
domains through it. The database itself is global — only the *current
domain* (passkey, site URLs) varies per request, tracked via a
contextvar set by the dispatch middleware.

Each domain's ``origins`` table holds both in-domain sign-in sites and
related origins (ROR), classified by the rp-id: entries within the rp-id
domain are in-domain, entries outside it are related.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import os

from fastapi_vue.hostutil import parse_endpoints

from paskia.db.structs import Config, DomainConfig, OriginEntry, RemoteConfig
from paskia.sansio import Passkey
from paskia.util import hostutil
from paskia.util.constants import DEFAULT_PORT

logger = logging.getLogger(__name__)

# Maximum number of related (non-subdomain) origins per domain. WebAuthn
# Related Origin Requests require browsers to support at least 5 labels.
DEFAULT_RELATED_ORIGIN_CAP = 5


def origin_url(key: str) -> str:
    """URL form of an origins-table key (https:// is implied); wildcards
    pass through unchanged."""
    if hostutil.is_wildcard_pattern(key) or "://" in key:
        return key
    return f"https://{key}"


def origin_key(origin: str) -> str:
    """Origins-table key for a full origin URL (https:// omitted).

    Keys are canonicalized: lowercased, and bare hosts/wildcards lose any
    trailing dot.
    """
    key = origin.removeprefix("https://").rstrip("/")
    if hostutil.is_wildcard_pattern(key):
        prefix = "**." if key.startswith("**.") else "*."
        return prefix + key[len(prefix) :].rstrip(".").lower()
    if "://" not in key:
        key = key.rstrip(".")
    return key.lower()


def is_related_key(rp_id: str, key: str) -> bool:
    """Whether an origins-table key lies outside the rp-id domain (a
    related origin). Wildcards are never related."""
    if hostutil.is_wildcard_pattern(key):
        return False
    hn = hostutil.origin_hostname(origin_url(key))
    return bool(hn) and not hostutil.is_subdomain(hn, rp_id)


def partition_origins(
    rp_id: str, origins: dict[str, bool | OriginEntry]
) -> tuple[list[str], list[str]]:
    """Split an origins table into (in-domain keys, related keys)."""
    in_domain = [k for k in origins if not is_related_key(rp_id, k)]
    related = [k for k in origins if is_related_key(rp_id, k)]
    return in_domain, related


def auth_host_url(domain: DomainConfig) -> str | None:
    """Full URL of the domain's auth host origin, if one is marked."""
    for key, props in domain.origins.items():
        if isinstance(props, OriginEntry) and props.auth_host:
            return origin_url(key)
    return None


class Domain:
    """Runtime view of one domain: stored config plus derived values."""

    def __init__(self, rp_id: str, config: DomainConfig, site_url: str, site_path: str):
        in_domain, related = partition_origins(rp_id, config.origins)
        self.rp_id = rp_id
        self.config = config
        self.site_url = site_url
        self.site_path = site_path
        self.passkey = Passkey(
            rp_id=rp_id,
            rp_name=config.rp_name,
            origins=[origin_url(k) for k in in_domain],
            related_origins=[origin_url(k) for k in related],
        )

    @property
    def rp_name(self) -> str:
        return self.passkey.rp_name

    @property
    def remote(self) -> RemoteConfig | None:
        """Upstream config when this domain is served as a satellite."""
        return self.config.remote

    @property
    def own_auth_host(self) -> str | None:
        """This domain's own auth host as host[:port], if configured."""
        url = auth_host_url(self.config)
        return hostutil.auth_host_netloc(url) if url else None

    @property
    def related_origins(self) -> list[str]:
        """Related (cross-domain) origins for ROR, as URLs."""
        return sorted(self.passkey.related_origins)

    @property
    def ui_base_path(self) -> str:
        """UI base path: site root on an own auth host, /auth/ elsewhere."""
        return "/" if auth_host_url(self.config) is not None else "/auth/"

    @property
    def auth_site_url(self) -> str:
        """Base URL of this domain's auth site UI."""
        return self.site_url + self.site_path

    def api_url(self, path: str = "") -> str:
        """Return an absolute URL under the canonical /auth/api/ prefix."""
        if not path:
            return f"{self.site_url}/auth/api/"
        return f"{self.site_url}/auth/api/{path.lstrip('/')}"

    def reset_link_url(self, token: str) -> str:
        """Generate a reset link URL for the given token on this domain."""
        return f"{self.auth_site_url}{token}"


class DomainRegistry:
    """Resolved domains and host lookup tables."""

    def __init__(self, domains: list[Domain]):
        self._by_rp_id = {d.rp_id: d for d in domains}
        self._auth_hosts: dict[str, list[Domain]] = {}
        self._related_hosts: dict[str, Domain] = {}
        self.warnings: list[str] = []
        for domain in domains:
            if own := domain.own_auth_host:
                key = hostutil.normalize_host(own) or own
                self._auth_hosts.setdefault(key, []).append(domain)
            for origin in domain.related_origins:
                if hostname := hostutil.origin_hostname(origin):
                    # First claimant wins (config order); a related host that
                    # is another domain's rp-id never reaches this map in
                    # resolve() — the owning domain is matched first.
                    self._related_hosts.setdefault(hostname, domain)

    @property
    def domains(self) -> list[Domain]:
        """All domains (unordered — ordering is a display-time affair)."""
        return list(self._by_rp_id.values())

    def get(self, rp_id: str) -> Domain | None:
        return self._by_rp_id.get(rp_id)

    def resolve(self, host: str | None) -> Domain | None:
        """Resolve a request Host header to a domain.

        Order: exact rp-id → auth host → exact related-origin hostname →
        longest-suffix rp-id. Unknown hosts return None. When several
        domains share an auth host, the best suffix match (longest rp-id
        the host falls under) wins, first configured as tiebreak — so
        ``auth.company.com`` shared by ``company.com`` and ``app2.com``
        serves ``company.com`` for plain HTTP; WebSocket logins still
        follow the Origin header to the right domain.
        """
        h = hostutil.normalize_host(host)
        if not h:
            return None
        if domain := self._by_rp_id.get(h):
            return domain
        if claimants := self._auth_hosts.get(h):
            best = None
            for candidate in claimants:
                if h.endswith(f".{candidate.rp_id}") and (
                    best is None or len(candidate.rp_id) > len(best.rp_id)
                ):
                    best = candidate
            return best or claimants[0]
        if domain := self._related_hosts.get(h):
            return domain
        best = None
        for rp_id, domain in self._by_rp_id.items():
            if h.endswith(f".{rp_id}") and (
                best is None or len(rp_id) > len(best.rp_id)
            ):
                best = domain
        return best


def validate_config(
    config: Config, *, related_origin_cap: int = DEFAULT_RELATED_ORIGIN_CAP
) -> None:
    """Validate a combined configuration cross-domain. Raises ValueError."""
    if not config.domains:
        raise ValueError("At least one domain (rp-id) is required")

    auth_hosts: dict[str, str] = {}  # normalized host -> owning rp_id
    related_hosts: dict[str, str] = {}  # hostname -> owning rp_id

    for rp_id, domain in config.domains.items():
        hostutil.validate_rp_id(rp_id)
        if domain.remote is not None and not domain.remote.url.startswith(
            ("https://", "http://")
        ):
            raise ValueError(f"Domain '{rp_id}': remote URL must be an http(s) URL")

        domain_auth_host: str | None = None
        related_count = 0
        for key, props in domain.origins.items():
            is_auth = isinstance(props, OriginEntry) and props.auth_host
            if key == "*":
                raise ValueError(
                    f"Origin '*' is not allowed — list '**.{rp_id}' explicitly"
                )
            if hostutil.is_wildcard_pattern(key):
                base = hostutil.wildcard_base(key)
                if not base or not hostutil.is_valid_hostname(base):
                    raise ValueError(f"Invalid wildcard origin: '{key}'")
                if not hostutil.is_subdomain(base, rp_id):
                    raise ValueError(
                        f"Origin '{key}' is a wildcard outside the rp-id "
                        f"domain '{rp_id}' — related origins must be "
                        "individual hosts"
                    )
                if is_auth:
                    raise ValueError(f"Wildcard origin '{key}' cannot be the auth host")
                continue
            hn = hostutil.origin_hostname(origin_url(key))
            if not hn or not hostutil.is_valid_hostname(hn):
                raise ValueError(f"Invalid origin: '{key}'")
            if hostutil.is_subdomain(hn, rp_id):
                if is_auth:
                    if domain_auth_host is not None:
                        raise ValueError(
                            f"Domain '{rp_id}' marks several origins as the auth "
                            f"host ('{domain_auth_host}' and '{key}') — only one allowed"
                        )
                    domain_auth_host = key
                    ah = hostutil.normalize_host(
                        hostutil.auth_host_netloc(origin_url(key)) or ""
                    )
                    # Several domains may share an auth host to consolidate
                    # logins; resolution picks the best suffix match.
                    auth_hosts.setdefault(ah, rp_id)
                continue
            # Related origin (outside the rp-id domain)
            if is_auth:
                raise ValueError(
                    f"Related origin '{key}' cannot be the auth host — the "
                    "auth host must be within the rp-id domain"
                )
            related_count += 1
            # A related host may be (or fall inside) another domain's
            # rp-id: a host that *is* a configured rp-id always serves its
            # own domain; otherwise the related listing wins dispatch over
            # suffix matching, so ROR logins from the listed host keep
            # working.
            covered_by_rp_id = any(
                hostutil.is_subdomain(hn, other) for other in config.domains
            )
            if hn in related_hosts and not covered_by_rp_id:
                raise ValueError(
                    f"Related origin host '{hn}' is configured for both "
                    f"'{related_hosts[hn]}' and '{rp_id}'"
                )
            related_hosts[hn] = rp_id
        if related_count > related_origin_cap:
            raise ValueError(
                f"Domain '{rp_id}' has {related_count} related origins "
                f"(maximum {related_origin_cap})"
            )
        if domain.remote is not None and domain_auth_host is None:
            raise ValueError(
                f"Domain '{rp_id}' is remote — it must mark an auth host "
                "(profile, admin and sign-in pages live there)"
            )

    rp_ids = set(config.domains)
    for hn, owner in auth_hosts.items():
        if hn in rp_ids:
            raise ValueError(f"auth-host '{hn}' collides with an rp-id")
        if hn in related_hosts and related_hosts[hn] != owner:
            raise ValueError(
                f"auth-host '{hn}' collides with a related origin of "
                f"domain '{related_hosts[hn]}'"
            )

    # Several domains may share one remote instance (and its replica), but
    # then its settings must be identical — a conflict would otherwise be
    # resolved silently and arbitrarily.
    remotes: dict[str, tuple[str, RemoteConfig]] = {}
    for rp_id, domain in config.domains.items():
        if domain.remote is None:
            continue
        prior = remotes.setdefault(domain.remote.url, (rp_id, domain.remote))
        if prior[1] != domain.remote:
            raise ValueError(
                f"Domains '{prior[0]}' and '{rp_id}' share remote "
                f"'{domain.remote.url}' with conflicting settings — a shared "
                "remote must have one configuration"
            )


def sanitize_config(
    config: Config, *, related_origin_cap: int = DEFAULT_RELATED_ORIGIN_CAP
) -> tuple[Config, list[str]]:
    """Best-effort repair of a stored configuration for serving.

    Serving must never fail because of stored domain config: fixing it is
    the admin's job via the admin UI, which is reachable only on a running
    server. Returns a sanitized copy (the stored config is left untouched)
    plus a warning for every degradation made. The result always passes
    ``validate_config``.
    """
    warnings: list[str] = []

    def warn(msg: str) -> None:
        warnings.append(msg)

    domains: dict[str, DomainConfig] = {}
    remotes_seen: dict[str, RemoteConfig] = {}
    for rp_id, domain in config.domains.items():
        try:
            hostutil.validate_rp_id(rp_id)
        except ValueError as e:
            warn(f"Domain dropped: {e}")
            continue

        origins: dict[str, bool | OriginEntry] = {}
        auth_seen = False
        for key, props in domain.origins.items():
            is_auth = isinstance(props, OriginEntry) and props.auth_host
            if not is_auth:
                props = True  # canonicalize junk/empty entries to presence-only
            if key == "*":
                warn(
                    f"Domain '{rp_id}': origin '*' rewritten as '**.{rp_id}'"
                    + (" — auth host mark cleared" if is_auth else "")
                )
                origins[f"**.{rp_id}"] = True
                continue
            if hostutil.is_wildcard_pattern(key):
                base = hostutil.wildcard_base(key)
                if not base or not hostutil.is_valid_hostname(base):
                    warn(f"Domain '{rp_id}': invalid wildcard origin '{key}' dropped")
                    continue
                if not hostutil.is_subdomain(base, rp_id):
                    warn(
                        f"Domain '{rp_id}': origin '{key}' is a wildcard "
                        "outside the rp-id domain — dropped (related origins "
                        "must be individual hosts)"
                    )
                    continue
                if is_auth:
                    warn(
                        f"Domain '{rp_id}': wildcard '{key}' cannot be the "
                        "auth host — mark cleared"
                    )
                    props = True
                origins[key] = props
                continue
            hn = hostutil.origin_hostname(origin_url(key))
            if not hn or not hostutil.is_valid_hostname(hn):
                warn(f"Domain '{rp_id}': invalid origin '{key}' dropped")
                continue
            if is_auth:
                if not hostutil.is_subdomain(hn, rp_id):
                    warn(
                        f"Domain '{rp_id}': related origin '{key}' cannot be "
                        "the auth host — mark cleared"
                    )
                    props = True
                elif auth_seen:
                    warn(
                        f"Domain '{rp_id}': several origins marked as "
                        f"auth host — extra mark on '{key}' cleared"
                    )
                    props = True
                else:
                    auth_seen = True
            origins[key] = props

        if domain.remote is not None:
            if not domain.remote.url.startswith(("https://", "http://")):
                warn(f"Domain '{rp_id}': invalid remote URL — remote dropped")
                remote = None
            else:
                remote = domain.remote
                prior = remotes_seen.setdefault(remote.url, remote)
                if prior != remote:
                    warn(
                        f"Domain '{rp_id}': remote '{remote.url}' settings "
                        "conflict with another domain's — aligned to the "
                        "first configuration"
                    )
                    remote = prior
                if not auth_seen:
                    warn(
                        f"Domain '{rp_id}': remote domain without an auth host — "
                        "profile, admin and sign-in pages have nowhere to live"
                    )
        else:
            remote = None

        related = sorted(k for k in origins if is_related_key(rp_id, k))
        if len(related) > related_origin_cap:
            warn(
                f"Domain '{rp_id}': {len(related)} related origins exceed "
                f"the maximum of {related_origin_cap} — extras dropped"
            )
            for key in related[related_origin_cap:]:
                del origins[key]

        domains[rp_id] = DomainConfig(
            rp_name=domain.rp_name, origins=origins, remote=remote
        )

    if not domains:
        raise ValueError("No servable domain in the stored configuration")

    # Cross-domain conflicts: an auth host equal to an rp-id is dead config
    # (the rp-id always wins dispatch) — clear the mark. Sharing one auth
    # host between domains is allowed (login consolidation); resolution
    # picks the best suffix match. Related origins may point at or inside
    # other domains' rp-ids: a host that *is* a configured rp-id serves its
    # own domain; otherwise the related listing wins dispatch over suffix
    # matching.
    rp_ids = set(domains)
    seen_auth_hosts: dict[str, str] = {}
    for rp_id, domain in domains.items():
        for key, props in domain.origins.items():
            if not isinstance(props, OriginEntry) or not props.auth_host:
                continue
            hn = hostutil.normalize_host(
                hostutil.auth_host_netloc(origin_url(key)) or ""
            )
            if hn in rp_ids:
                warn(
                    f"Domain '{rp_id}': auth host '{hn}' collides with "
                    "an rp-id — mark cleared"
                )
                domain.origins[key] = True
            elif hn:
                seen_auth_hosts.setdefault(hn, rp_id)

    seen_related: dict[str, str] = {}
    for rp_id, domain in domains.items():
        drop = []
        for key in domain.origins:
            if not is_related_key(rp_id, key):
                continue
            hn = hostutil.origin_hostname(origin_url(key))
            if any(hostutil.is_subdomain(hn, o) for o in rp_ids):
                continue  # covered by a configured rp-id
            if hn in seen_auth_hosts:
                warn(
                    f"Domain '{rp_id}': related origin '{key}' is the "
                    f"auth host of '{seen_auth_hosts[hn]}' — dropped"
                )
                drop.append(key)
            elif hn in seen_related:
                warn(
                    f"Domain '{rp_id}': related origin '{key}' is also "
                    f"used by '{seen_related[hn]}' — dropped (first domain wins)"
                )
                drop.append(key)
            else:
                seen_related[hn] = rp_id
        for key in drop:
            del domain.origins[key]

    return Config(domains=domains, listen=config.listen), warnings


def _derive_site(
    rp_id: str, domain: DomainConfig, *, listen_port: int | None, vite_url: str | None
) -> tuple[str, str]:
    """Compute a domain's site_url and site_path.

    Priority: auth host > exact rp-id origin key > first concrete in-domain
    origin key (sorted) > PASKIA_VITE_URL (localhost domain only) >
    http://localhost:port (localhost domain) > https://rp-id.
    """
    if auth := auth_host_url(domain):
        return auth, "/"
    if rp_id in domain.origins:
        return origin_url(rp_id), "/auth/"
    concrete = sorted(
        k
        for k in domain.origins
        if not hostutil.is_wildcard_pattern(k) and not is_related_key(rp_id, k)
    )
    if concrete:
        return origin_url(concrete[0]), "/auth/"
    if rp_id == "localhost":
        if vite_url:
            return vite_url.rstrip("/"), "/auth/"
        if listen_port:
            return f"http://localhost:{listen_port}", "/auth/"
    return f"https://{rp_id}", "/auth/"


_registry: DomainRegistry | None = None
_listen: list[str] | None = None
_rebuild_listeners: list = []
_rebuild_tasks: set[asyncio.Task] = set()


def add_rebuild_listener(fn) -> None:
    """Register fn(registry), called after every init_registry rebuild."""
    _rebuild_listeners.append(fn)


def remove_rebuild_listener(fn) -> None:
    if fn in _rebuild_listeners:
        _rebuild_listeners.remove(fn)


def _rebuild_done(task: asyncio.Task) -> None:
    _rebuild_tasks.discard(task)
    if not task.cancelled() and (exc := task.exception()) is not None:
        logger.error("Registry rebuild listener failed: %s", exc)


def _notify_rebuild(reg: DomainRegistry) -> None:
    """Run rebuild listeners; schedule coroutines on the running loop.

    Every serving context (lifespan, admin rebuild, tests) runs a loop.
    Task references are held until completion so listeners are neither
    garbage-collected mid-run nor silently failing.
    """
    for fn in _rebuild_listeners:
        result = fn(reg)
        if not asyncio.iscoroutine(result):
            continue
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            result.close()
            logger.warning("Rebuild listener %r skipped: no running event loop", fn)
            continue
        task = loop.create_task(result)
        _rebuild_tasks.add(task)
        task.add_done_callback(_rebuild_done)


def configure(*, listen: list[str] | None = None) -> None:
    """Record process-global serve parameters for site URL derivation."""
    global _listen
    _listen = listen


def build(config: Config) -> DomainRegistry:
    """Build a registry from a stored configuration.

    The config is sanitized best-effort (serving must not fail on stored
    config problems — the admin UI fixes them on a running server);
    warnings are logged and exposed on the registry.
    """
    config, warnings = sanitize_config(config)
    validate_config(config)  # sanitize guarantees this; a raise means a bug
    endpoint = next(iter(parse_endpoints(_listen, DEFAULT_PORT)), {})
    vite_url = os.environ.get("PASKIA_VITE_URL")
    domains = [
        Domain(
            rp_id,
            dc,
            *_derive_site(
                rp_id, dc, listen_port=endpoint.get("port"), vite_url=vite_url
            ),
        )
        for rp_id, dc in config.domains.items()
    ]
    registry = DomainRegistry(domains)
    registry.warnings = warnings
    for warning in warnings:
        logger.warning("Config: %s", warning)
    return registry


def init_registry(config: Config) -> DomainRegistry:
    """Build and install the global registry from a combined configuration."""
    global _registry
    _registry = build(config)
    _notify_rebuild(_registry)
    return _registry


def registry() -> DomainRegistry:
    """Return the global registry (must be initialized)."""
    if _registry is None:
        raise RuntimeError("Domain registry is not initialized")
    return _registry


_current_domain: contextvars.ContextVar[Domain | None] = contextvars.ContextVar(
    "paskia_current_domain", default=None
)


def set_current_domain(domain: Domain | None) -> contextvars.Token:
    return _current_domain.set(domain)


def reset_current_domain(token: contextvars.Token) -> None:
    _current_domain.reset(token)


def current_domain() -> Domain:
    """Return the request's domain.

    Without request context (background jobs, CLI), the single configured
    domain is returned; with several domains a request context is required.
    """
    domain = _current_domain.get()
    if domain is not None:
        return domain
    reg = registry()
    if len(reg.domains) == 1:
        return reg.domains[0]
    raise RuntimeError("No current domain: request context required")
