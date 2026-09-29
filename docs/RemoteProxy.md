# Remote Proxy / Satellite

Paskia can serve a configured domain (rp-id) from a **remote** paskia
instance instead of the local database, so latency-sensitive checks
(`/auth/api/forward`, `/auth/api/validate`) answer in ~1 ms even when the
auth server is on another continent. Example: `app2.example.com` runs on
our local host and needs fast local checks, while `app1.example.com` and
`auth.example.com` run far away — all sharing `example.com` as rp-id.

Client applications that used `https://auth.example.com` as their auth
backend (forward-auth checks) only repoint to the local satellite
(`http://127.0.0.1:4401`); both remain usable interchangeably, and the
satellite ultimately uses `auth.example.com`.

Status: **implemented**. The feature lives in `paskia/satellite.py`
(satellite side: replica, sync client, host dispatch, forwarding) and
`paskia/syncfeed.py` + `paskia/fastapi/sync.py` (remote side: change
feed and sync WebSocket). The design review comparing the rejected
alternatives is at the end of this document.

## Configuration

A domain becomes remote in the admin domains UI (master admin, on the
primary server's auth host — this configuration itself never touches a
remote): enable *Remote instance* and set the remote URL and sync token.
In the stored config (`DomainConfig.remote`):

```json
"remote": {
  "url": "https://auth.example.com",
  "token": "<sync token>",
  "cache_ttl": 60,
  "refresh_interval": 300
}
```

- `url` — the remote instance's base URL. The satellite connects to
  `{url}/auth/api/sync/ws`; the connection is server-to-server and not
  host-dispatched, so internal addresses work. The admin dialog probes
  `{url}/auth/api/settings` as you type: it must be reachable, serve this
  very rp-id, and not be a satellite for it itself (nested satellites are
  not supported — always point at the authoritative instance). Probe
  findings are warnings; the server-side validation is authoritative.
- `token` — bearer token for the sync channel. The **remote accepts tokens
  via its `PASKIA_SYNC_TOKENS` environment variable** (comma-separated);
  nothing is stored in the remote's database, and with the variable unset
  the sync endpoint stays closed. The token is write-only over the admin
  API (an empty field keeps the stored one).
- `cache_ttl` — seconds the replica remains trusted after the sync channel
  goes down; then checks fail closed (503). Set it large (up to the 24 h
  session lifetime) for fail-open behavior. Minimum 1.
- `refresh_interval` — seconds between reconnects; every connect starts
  from a full snapshot, which reconciles any drift. Minimum 30.

Several domains may share one remote (they share a single replica); their
remote settings must then be identical — conflicting configurations are
rejected at validation and aligned with a warning at load.

A remote domain **must mark an auth host** (validated cross-domain and in
the UI): the profile, admin and sign-in pages live there, so browsers and
WebSockets go directly to the remote. Other domains on the same satellite
remain fully local — the multi-domain config mixes both kinds freely.

## How it works

**Dispatch is keyed by host, and only this module knows about stores.**
`satellite.store_for_host(host)` returns the local DB or the replica of
the remote backing the host's domain (raising 503 `HTTPException` when
the replica is unavailable). The session read path (`session_ctx`,
`authz.verify`, `build_user_info`, `/check`) just passes the host it
already has; writes dispatch likewise (`satellite.refresh_session` —
write-behind for remote, `db.update_session` for local;
`satellite.evict_session` on logout). `satellite.forward_request(request)`
returns the proxied response for remote domains or `None` for local ones.

**The replica** is a plain `DB` struct instance in RAM, never persisted.
On connect the remote sends a snapshot of the replicated tables
(permissions, orgs, roles, users, credentials, sessions), then live
upsert/delete events emitted from the struct `store()`/`delete()` hooks
(which also cover cascade deletes) and field-mutating operations. A
single ordered WebSocket cannot gap; a slow subscriber is dropped and
resyncs. The feed carries no usable secrets: sessions are keyed by
`hash_secret` output, credentials carry public keys only, and the OIDC
signing key is never replicated.

## Endpoint behavior for remote domains

| Endpoint | Handling |
|---|---|
| `GET /auth/api/forward`, `GET /check`, `GET /user-info`, `GET /settings` | served from the replica (sub-ms) |
| `POST /auth/api/validate` | verified from the replica; the throttled refresh updates the replica and is written back over the sync channel; cookie renewed locally |
| `POST /auth/api/logout` | proxied to the remote (original Host preserved) and evicted from the replica immediately |
| `POST /auth/api/set-session`, `GET /token-info` | proxied (the exchange code/reset token lives on the remote); the session arrives via sync event |
| `/auth/oidc/*` | proxied (signing key and OIDC sessions stay on the remote) |
| `/auth/ws/*`, `/auth/remote-auth/*`, admin, profile | not served — the auth host requirement means these are reached on the remote directly |

Proxied calls answer 503 when the remote is unreachable. `/auth/api/settings`
reports `remote: true` for a satellite-served domain (this is what the admin
dialog's uplink probe checks). Should a remote domain's auth host be
misrouted to the satellite anyway, profile/avatar requests
(`/auth/api/user/*`) are forwarded to the remote rather than answered from
local storage — the satellite never takes writes for a remote domain.

Freshness hierarchy:

1. Changes made **through** the satellite: immediate (write-behind,
   optimistic eviction).
2. Changes made **directly on the remote**: a sync event, ~1 network RTT.
3. Channel down: the replica stays authoritative until `cache_ttl` past
   the disconnect (dead-peer detection is bounded by the ~10 s keepalive),
   then 503. Every reconnect starts from a fresh snapshot.

## The remote side

Strictly additive and RAM-only: `syncfeed` (a subscriber set fed by the
commit hooks) and the token-gated `/auth/api/sync/ws` endpoint serving
snapshot + live events and accepting `session_refresh` write-backs. With
no satellites connected, the hooks are a no-op.

## Trust and caveats

- The satellite host holds a full copy of the remote's auth data in RAM
  (minus the OIDC key) — treat it as trusted as the remote.
- Avatars are stored on the remote's disk; `user-info` from a replica
  reports no avatar URL.
- OIDC sessions in a replica-backed `user-info` show the client UUID
  rather than its name (OIDC clients are not replicated).

---

# Design review (the rejected alternatives)

## Option A — caching HTTP reverse proxy

A thin proxy caching `/auth/api/forward`, `/check`, `/user-info`,
`/settings` responses keyed by `(Host, cookie, query)` with
`TTL = min(configured TTL, Remote-Session-Expires − now)`; everything
else forwarded verbatim, WebSockets tunneled, `/logout` intercepted for
eviction. **Option B** adds a remote change feed so eviction happens
within one RTT instead of at TTL.

- Remote changes: none for A; one additive endpoint for B.
- The proxy needs no credentials — requests are authenticated by the end
  user's cookie, forwarded on a miss.

## What the read-only local state buys over the HTTP cache

- **Full `SessionContext` locally.** A replays the byte-response it once
  saw; the satellite *computes* the answer. Query combinations never seen
  before (new `perm`/`max_age`/`public` shapes) are served locally but
  miss A's cache. The replica holds the *domain model*, so derived
  answers (effective permissions per host, `max_age` against
  `credential.last_used`, `Remote-*` composition) are correct without
  having been witnessed.
- **One invalidation model.** A hand-builds invalidation rules per
  endpoint (query-key mapping, cookie re-keying on renew, 401 variants).
  Events mutate the replica (upsert/delete by table+key) and every
  endpoint becomes consistent at once — including future ones.
- **Degradation behaves like a real instance.** With the remote down, the
  satellite serves a coherent auth service from the replica (expiry
  enforced locally, bounded by `cache_ttl`); A serves unrelated cached
  responses with gaps wherever the cache was cold.
- **Multi-domain uniformity.** Remote backing is a property of a domain
  in the existing registry; local and remote rp-ids coexist in one
  instance. A is a separate component bolted in front of specific URLs.
- **User simplicity.** Configured once in domain config; A needs
  deployment and cache-key discipline per frontend application.

## What it costs

- The read path must be honest about which DB it reads: `DB.session_ctx`
  and `/check` were rewritten to use their own tables instead of struct
  convenience properties that reach the global database. (A first draft's
  contextvar-dependent `db.data()` was rejected: a global accessor whose
  meaning shifts under the caller. Dispatch is instead keyed explicitly
  by the request host.)
- A sync protocol (snapshot + live events + reconnect reconciliation).
- A trusted satellite host (full data copy in RAM).
- Additive remote code (sync endpoint + commit hooks), where A needs
  none.
- Replica housekeeping (expiry sweeper, write-behind, optimistic
  eviction).

## Summary

A(+B) is the right tool to "make forward-auth fast in front of an
untouched server". The satellite — implemented here — is the right tool
when it should *be* a paskia instance for its remote domains: one
consistency model, correct answers for un-cached query shapes, graceful
degradation, and per-domain mixing with local rp-ids, at the price of the
read-path cleanup, the sync protocol, and a trusted satellite host.
