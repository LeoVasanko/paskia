import argparse

import uvicorn


def main():
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

    args = parser.parse_args()

    uvicorn.run(
        "passkey.fastapi:app",
        host=args.host,
        port=args.port,
        reload=args.dev,
        log_level="info",
    )


if __name__ == "__main__":
    main()
