# Multiple Domains (Multi-Site)

One Paskia instance on one port serves several domains from a single
database. Typical uses:

- `app1.company.com` and `app2.com` cannot share passkeys, but user
  management should stay under one roof.
- A few alternative brand names should accept the _same_ passkeys.

## Shared vs. per-domain

**Shared across all domains:** user accounts, organizations, roles,
permissions, and OIDC clients. A user account exists once and can sign in
on every domain.

**Per domain:** passkeys and sessions.

- A passkey is registered to one domain name (enforced by the browser): a
  passkey created for `company.com` works on `company.com` and its
  subdomains, never on an unrelated name — unless that name is configured
  as a [related origin](#related-origins-sharing-passkeys-across-domain-names).
  A user active on two domains simply holds one passkey per domain.
- A session is bound to the exact host that issued it.

## The simplest case: several sites on one domain

Multi-site does not require several domains. Sites under one name —
`app1.company.com`, `app2.company.com` and so on — share the domain
`company.com`: one passkey works on all of them (WebAuthn natively allows
the domain and its subdomains), and the default `**.company.com` origin
entry already lets every one of them sign in. Add explicit entries only
to restrict which sites may sign in, and mark an auth host (see below)
if you want sign-in centralized on one site.

## Managing domains

The admin panel's **Domains** section (master admins only) lists every
domain with its allowed origins. There you can add, edit and delete
domains; changes apply immediately without a restart and require a recent
sign-in (within 5 minutes). The 🔑 and 🔗 markers in the origins column
identify the auth host and related origins (below).

A domain consists of:

- **Domain (rp-id)** — the domain name passkeys belong to, e.g.
  `company.com`. ("rp-id" is the WebAuthn term; read it as "domain name".)
  It cannot be changed after creation, because existing passkeys are bound
  to it — delete and re-create the domain instead.
- **Display name (rp-name)** — branding shown in sign-in dialogs and
  registered with passkeys.
- **Allowed origins** — the sites where this domain's passkeys may sign
  in, plus any related origins.

Deleting a domain is refused while any passkey is still registered to it,
when it is the last remaining domain, or when it is the domain you are
currently using. Users and organizations are never deleted with a domain
— they are shared. An edit that would lock you out (your current site
could no longer run passkey ceremonies for that domain) is refused as
well.

## Allowed origins (sign-in sites)

This list controls which sites may sign in with the domain's passkeys.
Everything is explicit: an empty list allows nothing of the domain itself
(related origins, below, still work — a domain can in principle run
entirely on related origins). A new domain starts with one entry,
`**.{domain}`, which suits most deployments.

Entry forms:

- `**.company.com` — the domain itself and its subdomains at any depth,
  https only. The default entry of a new domain.
- `*.company.com` — exactly one subdomain level: `app.company.com` yes,
  but neither the apex `company.com` nor `a.b.company.com`. Use this when
  the apex or deeper subdomains should not serve sign-ins.
- `app.company.com` — exactly this host, https only.
- `http://localhost:8080` — a full origin with scheme, for non-https
  exceptions.

Under `localhost`, both wildcard forms match any scheme and any port, as
a development convenience. An entry on a different domain name
automatically becomes a related origin (🔗) instead — see below.

### Wildcard syntax

Wildcards follow the shell-glob convention — the same one permission
scopes use (`*` within a segment, `**` across segments, see
[the perm argument](api/perm.md)): `**` spans any number of hostname
labels including none, `*` spans exactly one. Wildcards must stay within
the domain, and plain `*` is not accepted — it would suggest "anything
goes".

Conventions elsewhere differ: DNS, TLS and nginx take `*.example.com` to
mean subdomains only (TLS: exactly one level), while browser-extension
match patterns take it as apex plus any depth. The `*`/`**` split
sidesteps that ambiguity, and the less obvious forms `*example.com` and
`.example.com` remain unsupported on purpose.

## The auth host (🔑)

Marking one allowed origin as the **auth host** (row menu ⋮ → "Set as
auth host") centralizes the account and admin interface on that site,
e.g. `auth.company.com`:

- On the auth host the web UI is served at the site root (`/` instead of
  `/auth/`), and all passkey operations for the domain happen there.
- The domain's other sites show only a minimal profile page at `/auth/`
  with logout and a link to the full profile; their sign-in dialogs talk
  to the auth host behind the scenes. Every sign-in site still needs to
  be listed in (or covered by) the allowed origins.

The auth host is strictly per-domain — domains never borrow each other's
auth host. To consolidate several domains on one sign-in site, that site
must lie under each domain's name (nested domains, e.g. domains
`company.com` and `auth.company.com`) and be marked on each of them.

## Related origins: sharing passkeys across domain names

Sometimes a few different domain names should accept the _same_ passkeys
— for example after a rebrand, when `app2.com` should keep working with
existing `company.com` passkeys. Adding `app2.com` to `company.com`'s
allowed origins makes it a **related origin**: browsers then let
`app2.com` use `company.com` passkeys directly — no redirects, no
cross-domain cookies. (This uses the WebAuthn "Related Origin Requests"
mechanism, which is why the UI also says ROR.)

Rules:

- At most **5 related origins per domain** — a browser limit. This is for
  a small family of equally trusted sites, not for hundreds of customer
  domains; use separate domains for those.
- Exact hosts only — no wildcards — and always outside the domain's own
  name.
- The browser verifies the setup against
  `https://<domain>/.well-known/webauthn`. Paskia serves that document
  automatically when it hosts the domain's main site; if the main site is
  hosted elsewhere, copy the JSON document shown in the domain dialog and
  publish it there. The dialog also checks the published document for
  you.
- A related origin shares the domain's security boundary completely — do
  not mix trust levels within one domain.
- When several domains could claim a host: a host that _is_ a configured
  domain name always serves its own domain; otherwise an explicit related
  origin listing wins over merely falling under another domain's name.

Passkeys never move between domains. If you later consolidate separate
domains onto one, users re-enroll: sign in once via remote authorization
(below), then register a new passkey for the common domain from the
profile page.

## Signing in across domains

Users exist once, but need a passkey per domain. Two mechanisms smooth
this over:

- **Remote authorization:** a user without a passkey for the current
  domain can start a login request and approve it from any device already
  signed in — on _any_ domain of the instance. The approval screen shows
  which site is requesting access.
- **Enroll on the spot:** when the signed-in user has no passkey for the
  current domain, the profile page offers "Add Passkey for {domain}", so
  everyday sign-in stays local from then on.

## OIDC with multiple domains

OIDC clients are shared by the whole instance: register a client once and
it works through every domain. Each domain serves its own discovery URL
(`https://<host>/.well-known/openid-configuration`), listed in the admin
OIDC client view. Have each app pick **one** discovery URL and use it
consistently, so its tokens always validate against the same issuer.

## Command line

The admin panel covers all domain management after bootstrap. On the
command line:

- `paskia init [domain] [name]` — creates the database `paskia.kantadb`
  with the first domain. Run again with an existing database to add
  another domain (or update a display name).
- `paskia migrate [domain]` — converts a legacy 1.x `{domain}.paskiadb`
  database to `paskia.kantadb`; see below.
- `paskia` — serves all configured domains; takes no domain options, only
  `--listen` as a per-run override.

## Upgrading from 1.x

2.0 intentionally changes the on-disk layout and the domain configuration
model:

- The database is the single file **`paskia.kantadb`** in the working
  directory; user files (avatars) live in **`paskia.data/users/`**.
  `paskia migrate` performs the conversion and renames the old database
  aside to `{domain}.paskiadb.converted-bak`. With several legacy
  databases, the positional argument selects one by name. Legacy wildcard
  origins convert as-is (https only, except any scheme and port under
  `localhost`); a legacy database without configured origins — where that
  meant the whole domain was allowed — gets an explicit `**.{domain}`
  entry.
- Origins, auth hosts and related origins are no longer environment
  settings — they live in the database and are managed in the admin
  panel's Domains section. `PASKIA_AUTH_HOST` remains only as a
  development-server (vite) setting.
- OIDC becomes instance-global: one signing key and one client set,
  reachable through every domain's discovery URL (previously each rp-id
  had its own). Existing clients keep working through any domain.
