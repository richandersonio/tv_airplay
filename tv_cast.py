#!/usr/bin/env python3
"""
Samsung TV Video Caster

Cast any video file directly to your Samsung TV via DLNA.
Automatically converts to HLS format for maximum compatibility.

Usage:
    python tv_cast.py video.mp4              # Cast a video
    python tv_cast.py video.mp4 --duration 60  # Cast for 60 seconds
    python tv_cast.py --stop                 # Stop current playback

This is a thin wrapper around the tv_cast package.
You can also run: python -m tv_cast
Or after installing: tv-cast
"""

from tv_cast.__main__ import main

if __name__ == "__main__":
    main()
