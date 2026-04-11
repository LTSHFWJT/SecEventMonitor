import argparse

import uvicorn

from seceventmonitor import create_app


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 20000


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start SecEventMonitor")
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Bind host, default: {DEFAULT_HOST}",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Bind port, default: {DEFAULT_PORT}",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    return args


def main() -> None:
    args = _parse_args()
    app = create_app()
    uvicorn.run(app, host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
