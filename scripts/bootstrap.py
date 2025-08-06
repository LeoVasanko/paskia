#!/usr/bin/env python3
"""
Bootstrap CLI script for passkey authentication system.

This script initializes a new passkey authentication system with:
- Default admin user
- Default organization
- Admin permissions
- Reset token for initial setup
"""

import asyncio
import sys


async def main():
    """Main CLI entry point."""
    from passkey.bootstrap import main as bootstrap_main
    from passkey.db.sql import init

    print("Initializing passkey authentication database...")
    await init()

    print("\nRunning bootstrap process...")
    await bootstrap_main()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n❌ Bootstrap interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Bootstrap failed: {e}")
        sys.exit(1)
