"""Video conversion to HLS format."""

import json
import os
import shutil
import subprocess
from typing import Tuple, Optional

from .config import HLS_CACHE_DIR, CONFIG_DIR, FFMPEG_THREADS


def get_cache_dir(video_path: str) -> str:
    """Get cache directory for a video file."""
    video_name = os.path.basename(video_path)
    video_mtime = os.path.getmtime(video_path)
    video_size = os.path.getsize(video_path)

    cache_key = f"{video_name}_{video_size}_{int(video_mtime)}"
    cache_key = "".join(
        c if c.isalnum() or c in "._-" else "_" for c in cache_key)

    return os.path.join(HLS_CACHE_DIR, cache_key)


def is_cached(video_path: str) -> Tuple[bool, str]:
    """Check if video is already converted. Returns (is_cached, cache_dir)."""
    cache_dir = get_cache_dir(video_path)
    playlist_path = os.path.join(cache_dir, "playlist.m3u8")

    if os.path.exists(playlist_path):
        segments = [f for f in os.listdir(cache_dir) if f.endswith('.ts')]
        if segments:
            return True, cache_dir

    return False, cache_dir


def check_video_codec(input_file: str) -> Tuple[str, float]:
    """Check if video is H.264 and get duration."""
    probe_cmd = [
        "ffprobe", "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "stream=codec_name:format=duration",
        "-of", "json",
        input_file
    ]
    result = subprocess.run(
        probe_cmd, capture_output=True, text=True, check=False)

    try:
        data = json.loads(result.stdout)
        codec = data.get("streams", [{}])[0].get("codec_name", "")
        duration = float(data.get("format", {}).get("duration", 0))
        return codec, duration
    except (json.JSONDecodeError, KeyError, ValueError, IndexError):
        return "", 0.0


def convert_to_hls(input_file: str) -> Optional[str]:
    """Convert video to HLS format for Samsung TV compatibility."""

    cached, cache_dir = is_cached(input_file)

    if cached:
        print(f"⚡ Using cached HLS conversion")
        return os.path.join(cache_dir, "playlist.m3u8")

    codec, duration = check_video_codec(input_file)
    can_copy = codec in ("h264", "hevc", "h265")

    os.makedirs(cache_dir, exist_ok=True)
    playlist_path = os.path.join(cache_dir, "playlist.m3u8")

    if can_copy:
        print(f"🚀 Fast remux to HLS (video is already {codec})...")
        cmd = [
            "ffmpeg", "-y",
            "-i", input_file,
            "-c:v", "copy",
            "-c:a", "aac",
            "-b:a", "128k",
            "-f", "hls",
            "-hls_time", "4",
            "-hls_list_size", "0",
            "-hls_segment_filename", os.path.join(cache_dir, "segment%03d.ts"),
            "-progress", "pipe:1",
            playlist_path
        ]
    else:
        print(
            f"🔄 Converting to HLS (using {FFMPEG_THREADS} threads, ultrafast)...")
        cmd = [
            "ffmpeg", "-y",
            "-threads", str(FFMPEG_THREADS),
            "-i", input_file,
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-crf", "23",
            "-threads", str(FFMPEG_THREADS),
            "-c:a", "aac",
            "-b:a", "128k",
            "-f", "hls",
            "-hls_time", "4",
            "-hls_list_size", "0",
            "-hls_segment_filename", os.path.join(cache_dir, "segment%03d.ts"),
            "-progress", "pipe:1",
            playlist_path
        ]

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    last_percent = -1

    try:
        for line in process.stdout:
            line = line.strip()

            if line.startswith("out_time="):
                try:
                    time_str = line.split("=")[1]
                    parts = time_str.replace("-", "0").split(":")
                    if len(parts) == 3:
                        h, m, s = parts
                        current_seconds = int(
                            h) * 3600 + int(m) * 60 + float(s)

                        if duration > 0:
                            percent = min(
                                100, int((current_seconds / duration) * 100))
                            if percent != last_percent:
                                bar_len = 30
                                filled = int(bar_len * percent / 100)
                                bar = "█" * filled + "░" * (bar_len - filled)
                                print(f"\r   [{bar}] {percent}%",
                                      end="", flush=True)
                                last_percent = percent
                except (ValueError, IndexError):
                    pass
    except KeyboardInterrupt:
        process.kill()
        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)
        print("\n❌ Conversion cancelled")
        return None

    process.wait()

    if process.returncode != 0:
        stderr = process.stderr.read()
        print(f"\n❌ Conversion failed: {stderr[-500:]}")
        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)
        return None

    print(f"\n   ✅ Done! (cached for next time)")
    return playlist_path


def image_to_video(image_path: str, duration: int = 10) -> Optional[str]:
    """Convert an image to a video file for streaming."""

    image_path = os.path.abspath(image_path)
    image_name = os.path.basename(image_path)

    image_video_cache = os.path.join(CONFIG_DIR, "image_videos")
    os.makedirs(image_video_cache, exist_ok=True)

    image_mtime = os.path.getmtime(image_path)
    image_size = os.path.getsize(image_path)
    cache_key = f"{image_name}_{image_size}_{int(image_mtime)}_{duration}s"
    cache_key = "".join(
        c if c.isalnum() or c in "._-" else "_" for c in cache_key)
    output_path = os.path.join(image_video_cache, f"{cache_key}.mp4")

    if os.path.exists(output_path):
        print(f"⚡ Using cached image video")
        return output_path

    print(f"🖼️  Converting image to {duration}s video...")

    cmd = [
        "ffmpeg", "-y",
        "-loop", "1",
        "-i", image_path,
        "-c:v", "libx264",
        "-t", str(duration),
        "-pix_fmt", "yuv420p",
        "-vf", "scale=1920:1080:force_original_aspect_ratio=increase,crop=1920:1080",
        "-r", "30",
        "-preset", "ultrafast",
        output_path
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"❌ Failed to convert image: {result.stderr}")
        return None

    print(f"   ✅ Created {duration}s video")
    return output_path


def clear_cache() -> None:
    """Clear all cached data (HLS conversions, YouTube downloads, image videos)."""
    cleared = False

    if os.path.exists(HLS_CACHE_DIR):
        count = len(os.listdir(HLS_CACHE_DIR))
        shutil.rmtree(HLS_CACHE_DIR)
        print(f"🗑️  Cleared {count} HLS conversion(s)")
        cleared = True

    from .config import YOUTUBE_CACHE_DIR
    if os.path.exists(YOUTUBE_CACHE_DIR):
        count = len([f for f in os.listdir(
            YOUTUBE_CACHE_DIR) if f.endswith('.mp4')])
        if count > 0:
            shutil.rmtree(YOUTUBE_CACHE_DIR)
            print(f"🗑️  Cleared {count} YouTube download(s)")
            cleared = True

    image_cache = os.path.join(CONFIG_DIR, "image_videos")
    if os.path.exists(image_cache):
        count = len(os.listdir(image_cache))
        if count > 0:
            shutil.rmtree(image_cache)
            print(f"🗑️  Cleared {count} image video(s)")
            cleared = True

    if not cleared:
        print("📁 Cache is already empty")
