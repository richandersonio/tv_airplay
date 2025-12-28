#!/usr/bin/env python3
"""
Samsung TV Video Caster

Cast any video file directly to your Samsung TV via DLNA.
Automatically converts to HLS format for maximum compatibility.

Usage:
    uv run python tv_cast.py video.mp4              # Cast a video
    uv run python tv_cast.py video.mp4 --duration 60  # Cast for 60 seconds
    uv run python tv_cast.py --stop                 # Stop current playback

This is a thin wrapper around the tv_cast package.
You can also run: uv run python -m tv_cast
Or after installing: tv-cast
"""

import sys

try:
    from tv_cast.__main__ import main
except ImportError as e:
    print("❌ Error: Dependencies not found.")
    print("\n💡 This script requires dependencies to be installed.")
    print("   Please run it with: uv run python tv_cast.py")
    print("   Or install dependencies: uv sync")
    print(f"\n   Original error: {e}")
    sys.exit(1)

if __name__ == "__main__":
    main()
