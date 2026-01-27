"""CLI support for creating user credential reset links.

Usage (via main CLI):
    paskia reset [query]

If query is omitted, the master admin (first Administration role user in
an organization granting auth:admin) is targeted. Otherwise query is
matched as either an exact UUID or a case-insensitive substring of the
display name. If multiple users match, they are listed and the command
aborts. A new one-time reset link is always created.
"""

from __future__ import annotations

import asyncio
from uuid import UUID

from paskia import authsession as _authsession
from paskia import db
from paskia.util import hostutil, passphrase


async def _resolve_targets(query: str | None):
    if query:
        # Try UUID
        targets: list[tuple] = []
        try:
            q_uuid = UUID(query)
            p = next(
                (p for p in db.data().permissions.values() if p.scope == "auth:admin"),
                None,
            )
            if p:
                for org_uuid in p.orgs:
                    users = db.get_organization_users(org_uuid)
                    for u, role_name in users:
                        if u.uuid == q_uuid:
                            return [(u, role_name)]
            # UUID not found among admin orgs -> fall back to substring search (rare case)
        except ValueError:
            pass
        # Substring search
        needle = query.lower()
        p = next(
            (p for p in db.data().permissions.values() if p.scope == "auth:admin"), None
        )
        if p:
            for org_uuid in p.orgs:
                users = db.get_organization_users(org_uuid)
                for u, role_name in users:
                    if needle in (u.display_name or "").lower():
                        targets.append((u, role_name))
        # De-duplicate
        seen = set()
        deduped = []
        for u, role_name in targets:
            if u.uuid not in seen:
                seen.add(u.uuid)
                deduped.append((u, role_name))
        return deduped
    # No query -> master admin
    p = next(
        (p for p in db.data().permissions.values() if p.scope == "auth:admin"), None
    )
    if not p or not p.orgs:
        return []
    first_org_uuid = next(iter(p.orgs))
    users = db.get_organization_users(first_org_uuid)
    admin_users = [pair for pair in users if pair[1] == "Administration"]
    return admin_users[:1]


async def _create_reset(user, role_name: str):
    token = passphrase.generate()
    expiry = _authsession.reset_expires()
    db.create_reset_token(
        passphrase=token,
        user_uuid=user.uuid,
        expiry=expiry,
        token_type="manual reset",
    )
    return hostutil.reset_link_url(token), token


async def _main(query: str | None) -> int:
    try:
        candidates = await _resolve_targets(query)
        if not candidates:
            print("No matching users found")
            return 1
        if len(candidates) > 1:
            print("Multiple matches. Refine your query:")
            for u, role_name in candidates:
                print(f" - {u.display_name}  ({u.uuid}) role={role_name}")
            return 2
        user, role_name = candidates[0]
        link, token = await _create_reset(user, role_name)
        print(f"Reset link for {user.display_name} ({user.uuid}):\n{link}\n")
        return 0
    except Exception as e:  # pragma: no cover
        print("Failed to create reset link:", e)
        return 1


def run(query: str | None) -> int:
    """Synchronous wrapper for CLI entrypoint."""
    return asyncio.run(_main(query))


__all__ = ["run"]
