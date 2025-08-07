import argparse
import asyncio
import logging

import uvicorn


def main():
    # Configure logging to remove the "ERROR:root:" prefix
    logging.basicConfig(level=logging.INFO, format="%(message)s", force=True)
    parser = argparse.ArgumentParser(
        description="Run the passkey authentication server"
    )
    parser.add_argument(
        "--host", default="localhost", help="Host to bind to (default: localhost)"
    )
    parser.add_argument(
        "--port", type=int, default=4401, help="Port to bind to (default: 4401)"
    )
    parser.add_argument(
        "--dev", action="store_true", help="Enable development mode with auto-reload"
    )
    parser.add_argument(
        "--rp-id", default="localhost", help="Relying Party ID (default: localhost)"
    )
    parser.add_argument("--rp-name", help="Relying Party name (default: same as rp-id)")
    parser.add_argument("--origin", help="Origin URL (default: https://<rp-id>)")

    args = parser.parse_args()

    # Initialize the application
    try:
        from .. import globals

        asyncio.run(
            globals.init(rp_id=args.rp_id, rp_name=args.rp_name, origin=args.origin)
        )
    except ValueError as e:
        logging.error(f"⚠️ {e}")
        return

    uvicorn.run(
        "passkey.fastapi:app",
        host=args.host,
        port=args.port,
        reload=args.dev,
        log_level="info",
    )


if __name__ == "__main__":
    main()
