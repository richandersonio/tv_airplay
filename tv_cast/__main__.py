"""Entry point for running as a module: python -m tv_cast"""

import signal
from typing import Any

from .config import load_config
from .casting import cleanup_on_exit
from .cli import run_cli

_cleanup_done = False


def signal_handler(sig: int, frame: Any) -> None:
    """Handle Ctrl+C and termination signals."""
    global _cleanup_done
    if not _cleanup_done:
        _cleanup_done = True
        cleanup_on_exit()
    print("👋 Goodbye!")
    exit(0)


def main() -> None:
    """Main entry point."""
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Load configuration
    load_config()

    try:
        run_cli()
    except KeyboardInterrupt:
        global _cleanup_done
        if not _cleanup_done:
            _cleanup_done = True
            cleanup_on_exit()
        print("👋 Goodbye!")


if __name__ == "__main__":
    main()
