# Remote Proxy / Satellite

Paskia can serve configured domains (rp-ids) from a **remote** paskia
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
(satellite side: uplinks, replicas, host dispatch, forwarding) and
`paskia/syncfeed.py` + `paskia/fastapi/sync.py` (upstream side: change
feed, registration handshake, sync WebSocket). The design review comparing
the rejected alternatives is at the end of this document.

## Configuration

Setup is a single copy-paste of a **link URL**, and everything else flows
from it. On the **upstream** (the authoritative instance), open the admin
*Satellites* panel and use *New satellite link*, choosing the domains the
satellite will serve. That mints a registration offer and shows one URL:

```
wss://auth.example.com#<five.word.registration.secret>
```

The `wss://` scheme is deliberate: the URL is meant only for a satellite
to connect to, and browsers refuse to open it. The initial key is held in
the upstream's RAM only, expires in 10 minutes, and is single-use — losing
or leaking it just means minting a new one. The permanent credentials are
created during registration (see *How it works*).

On the **satellite**, either:

- paste the URL in its admin *Satellites* panel under *Uplinks → Add
  uplink* — registration runs immediately and reports failures inline; or
- run `paskia satellite <url>` on the satellite host — the whole setup of
  a satellite-only installation (it creates the database on first run; no
  local domain or admin site is needed).

That's all: the upstream pushes the link's domain set — rp-id, display
name and the origins table verbatim, including its auth host — and the
satellite persists it. The upstream is authoritative: pushed domains are
validated against the satellite's local configuration (an rp-id already
served locally, or origins colliding with it, are rejected and reported
back into the upstream's link list), and remote domains are read-only on
the satellite — the only satellite-side configuration is linking and
unlinking.

A link's scope is **adjustable at any time** from the upstream's link list
(edit which domains it serves): the new set is pushed over the live link —
register once, no new cryptographic setup. Revoking a link drops the
satellite's connections; the satellite observes the policy close and
unlinks its side (its copy of the domains is removed).

A satellite-only instance serves its backend apps on local addresses and
needs no inbound connectivity at all — the link is an outbound WebSocket
from the satellite.

In the stored config, a remote domain carries only the link reference:

```json
"remote": { "link": "<uplink id>" }
```

and the uplink itself lives in the database's `uplinks` table (the
upstream URL, its quantumpipe composite `key`, and the local
tolerance knobs):

- `cache_ttl` (default 60) — seconds the replica remains trusted after
  the sync channel goes down; then checks fail closed (503). Set it large
  (up to the 24 h session lifetime) for fail-open behavior.
- `refresh_interval` (default 300) — seconds between reconnects; every
  connect starts from a full snapshot, which reconciles any drift.

On the upstream, links live in the `satellite_links` table: the peer's
`key` bytes, its self-reported label, and the scope (`rp_ids`).

## How it works

**Registration and the sync channel share one encrypted endpoint** —
`{upstream}/auth/api/sync/ws`. Quantumpipe performs a mutually
authenticated hybrid ML-KEM-768 + X25519 exchange and transparently encrypts
every application frame. The five-word registration secret is stretched
with PBKDF2-SHA512 into a 32-byte registration key at offer creation and on
the connecting satellite; the upstream only handles the derived key.

Registration offers, handshake state and the rotated credential remain in
RAM until the exchange completes. The satellite then sends its label, the
upstream generates the permanent link id, commits the link and pushes that
id with its domain set. The satellite validates and commits its own uplink
and domains. Quantumpipe's atomic
credential swap spends the offer; an interrupted exchange before that point
leaves it available until its normal expiry.

Established links resume with their stored composite credentials. Every
connection starts with an authoritative `domains` push and acknowledgement,
followed by encrypted JSON snapshots of the scoped tables, `ready`, then
live upsert/delete events. The satellite sends `session_refresh`
write-backs; live `domains` frames push scope or origin changes.

**Dispatch is keyed by host, and only the satellite module knows about
stores.** `satellite.store_for_host(host)` returns the local DB or the
replica of the uplink backing the host's domain (raising 503
`HTTPException` when the replica is unavailable). The session read path
(`session_ctx`, `authz.verify`, `build_user_info`) just passes the host it
already has; writes dispatch likewise (`satellite.refresh_session` —
write-behind for remote, `db.update_session` for local;
`satellite.evict_session` on logout). `satellite.forward_request(request)`
returns the proxied response for remote domains or `None` for local ones.
Forwarded ASGI exchanges use the encrypted sync WebSocket rather than a
second HTTPS connection; the upstream applies link-domain and path
allowlists before invoking the normal FastAPI application.

**The replica** is a `ReplicaDB` instance in RAM, never persisted, one per
uplink connection. On connect the upstream sends a snapshot of the scoped
tables (the link's domains' credentials and sessions), then live
upsert/delete events emitted from the struct `store()`/`delete()` hooks
(which also cover cascade deletes) and field-mutating operations. The feed
is scoped to the link's rp-ids, and the user graph never leaves the
upstream: every session upsert carries an embedded `ctx` — the same
`ApiSessionContext` sent to users — holding the session's user/org/role
display data and effective permissions, computed for the session's bound
host. Mutations of users, orgs, roles or permissions are not published;
instead the upstream eagerly re-pushes the affected sessions with freshly
computed contexts, so renames and permission revocations take effect
within ~1 RTT. A single ordered WebSocket cannot gap; a slow subscriber is
dropped and resyncs. The feed carries no usable secrets: sessions are
keyed by `hash_secret` output, credentials carry public keys only, and the
OIDC signing key is never replicated.

## Endpoint behavior for remote domains

| Endpoint | Handling |
|---|---|
| `GET /auth/api/forward`, `GET /settings` | served from the replica (sub-ms) |
| `POST /auth/api/validate` | verified from the replica; the throttled refresh updates the replica and is written back over the sync channel; cookie renewed locally |
| `GET /check`, `GET /user-info` | proxied — these need the user graph (per-session contexts do not cover arbitrary user lookups or full profile data) |
| `POST /auth/api/logout` | proxied over ASGI-in-WebSocket (original Host preserved) and evicted from the replica immediately |
| `POST /auth/api/set-session`, `GET /token-info` | proxied (the exchange code/reset token lives on the upstream); the session arrives via sync event |
| `/auth/oidc/*` | proxied (signing key and OIDC sessions stay on the upstream) |
| `/auth/ws/*`, `/auth/remote-auth/*`, admin, profile | not served — the auth host requirement means these are reached on the upstream directly |

Proxied calls answer 503 when the sync link is unavailable.
`/auth/api/settings` reports `remote: true` for a satellite-served domain.
Should a remote domain's auth host be misrouted to the satellite anyway,
profile/avatar requests (`/auth/api/user/*`) are forwarded to the upstream
rather than answered from local storage — the satellite never takes writes
for a remote domain.

Freshness hierarchy:

1. Changes made **through** the satellite: immediate (write-behind,
   optimistic eviction).
2. Changes made **directly on the upstream**: a sync event, ~1 network
   RTT.
3. Channel down: the replica stays authoritative for local session checks
   until `cache_ttl` past the disconnect (dead-peer detection is bounded by
   the ~10 s keepalive), then 503. Forwarded calls require a live link. Every
   reconnect starts from a fresh snapshot.

## The upstream side

Nearly additive: the link table, RAM-only registration offers and the
`syncfeed` subscriber set fed by the commit hooks, plus the
`/auth/api/sync/ws` endpoint doing the handshake, serving snapshots and
live events, pushing domain configuration, accepting `session_refresh`
write-backs, and dispatching allowlisted ASGI exchanges within the link's
scope. With no satellites connected, the hooks are a no-op.

## Trust and caveats

- The satellite host holds only its link's domains' sessions (with their
  identity contexts) and credentials in RAM — it learns the users that
  actually sign in to those domains, never the directory, and never the
  OIDC key. Still treat it as trusted: it is authoritative for session
  checks within `cache_ttl`.
- Avatars are stored on the upstream's disk; profile data such as
  `user-info` is proxied to the upstream rather than answered locally.
- OIDC sessions in a proxied `user-info` show the client UUID
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
- **User simplicity.** One link registration per satellite; A needs
  deployment and cache-key discipline per frontend application.

## What it costs

- The read path must be honest about which DB it reads: `DB.session_ctx`
  and `/check` were rewritten to use their own tables instead of struct
  convenience properties that reach the global database. (A first draft's
  contextvar-dependent `db.data()` was rejected: a global accessor whose
  meaning shifts under the caller. Dispatch is instead keyed explicitly
  by the request host.)
- A sync protocol (registration handshake, snapshot + live events +
  reconnect reconciliation, live domain pushes).
- A trusted satellite host (its link's sessions and credentials in RAM).
- Additive upstream code (sync endpoint + commit hooks), where A needs
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
