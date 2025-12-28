"""Command-line interface for TV Caster."""

import argparse
import asyncio
import os

from .config import (
    CONFIG_DIR, HLS_CACHE_DIR, YOUTUBE_CACHE_DIR,
    get_current_device, set_current_device, get_discovered_devices,
    load_config, save_config, save_discovered_devices, forget_device,
)
from .conversion import clear_cache, image_to_video
from .casting import cast_video, stop_playback
from .discovery import discover_dlna_devices, discover_all_devices
from .menu import main_menu, playback_menu_loop, device_menu


def show_status():
    """Show current device status."""
    current_device = get_current_device()

    if current_device:
        print(f"📺 Current device: {current_device['name']}")
        print(f"   IP: {current_device.get('ip', 'unknown')}")
        if current_device.get('location'):
            print(f"   DLNA: {current_device['location']}")
    else:
        print("⚠️  No device selected")
        print("   Use --scan to find TVs, then --device IP to select one")

    print(f"\n📁 Cache:")

    hls_count = 0
    if os.path.exists(HLS_CACHE_DIR):
        hls_count = len(os.listdir(HLS_CACHE_DIR))
    print(f"   HLS conversions: {hls_count}")

    yt_count = 0
    if os.path.exists(YOUTUBE_CACHE_DIR):
        yt_count = len([f for f in os.listdir(YOUTUBE_CACHE_DIR) if f.endswith('.mp4')])
    print(f"   YouTube downloads: {yt_count}")

    image_cache = os.path.join(CONFIG_DIR, "image_videos")
    img_count = 0
    if os.path.exists(image_cache):
        img_count = len(os.listdir(image_cache))
    print(f"   Image videos: {img_count}")

    if hls_count + yt_count + img_count > 0:
        print(f"\n   Use --clear-cache to clear all")


def list_devices_cli():
    """List all discovered devices."""
    discovered_devices = get_discovered_devices()
    current_device = get_current_device()

    if not discovered_devices:
        print("⚠️  No devices discovered yet")
        print("   Use --scan to find TVs on the network")
        return

    castable = [d for d in discovered_devices if d.get('castable', False)]
    other = [d for d in discovered_devices if not d.get('castable', False)]

    if castable:
        print("📺 Cast-capable devices:\n")
        for dev in castable:
            current = " ← selected" if current_device and current_device.get('ip') == dev.get('ip') else ""
            print(f"   {dev.get('ip'):15}  {dev.get('name', 'Unknown')}{current}")

    if other:
        print("\n📱 Other devices:\n")
        for dev in other:
            print(f"   {dev.get('ip'):15}  {dev.get('name', 'Unknown')}")


async def scan_devices_cli():
    """Scan for cast-capable devices (CLI mode)."""
    print("🔍 Scanning for cast-capable TVs...")
    devices = await discover_dlna_devices(timeout=5)

    if devices:
        save_discovered_devices(devices)
        print(f"\n✅ Found {len(devices)} TV(s):\n")
        for dev in devices:
            print(f"   {dev.get('ip'):15}  {dev.get('name', 'Unknown')}")
        print(f"\n💡 Use --device IP to select a TV")
    else:
        print("\n❌ No TVs found on the network")
        print("   Make sure your TV is on and connected to the same network")


async def scan_all_devices_cli():
    """Scan for all network devices (CLI mode)."""
    devices = await discover_all_devices(timeout=8)

    if devices:
        save_discovered_devices(devices)
        castable = [d for d in devices if d.get('castable', False)]
        print(f"\n💡 Found {len(castable)} castable device(s)")
        if castable:
            print("   Use --device IP to select one")


def set_device_by_ip(ip: str):
    """Set the current device by IP address."""
    discovered_devices = get_discovered_devices()

    for dev in discovered_devices:
        if dev.get('ip') == ip:
            set_current_device(dev)
            save_config()
            print(f"✅ Selected: {dev.get('name', ip)} ({ip})")
            return

    device = {
        'ip': ip,
        'name': f"TV ({ip})",
        'type': 'dlna',
        'castable': True,
    }
    set_current_device(device)
    save_config()
    print(f"✅ Selected: {ip}")
    print("   (Device will be fully discovered on first connection)")


def cast_image_cli(image_path: str, duration: int):
    """Cast an image from CLI."""
    current_device = get_current_device()

    if not current_device:
        print("❌ No device selected. Use --scan and --device IP to set one.")
        return

    if not os.path.exists(image_path):
        print(f"❌ Image not found: {image_path}")
        return

    _, ext = os.path.splitext(image_path.lower())
    if ext not in {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}:
        print(f"❌ Unsupported image format: {ext}")
        return

    video_path = image_to_video(image_path, duration=duration)
    if video_path:
        asyncio.run(cast_video(video_path, duration=duration + 2))
    else:
        print("❌ Failed to convert image")


def run_cli():
    """Run the command-line interface."""
    load_config()

    parser = argparse.ArgumentParser(
        description="Cast videos to your TV",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Casting
  python -m tv_cast movie.mp4           # Cast a video (Ctrl+C to stop)
  python -m tv_cast movie.mp4 -d 30     # Cast for 30 seconds
  python -m tv_cast "https://youtube.com/watch?v=..."  # Cast YouTube video
  python -m tv_cast --image photo.jpg   # Display an image for 10 seconds
  python -m tv_cast --stop              # Stop current playback

  # Device management
  python -m tv_cast --scan              # Scan network for TVs
  python -m tv_cast --device 192.168.1.50  # Set TV by IP address
  python -m tv_cast --status            # Show current device
  python -m tv_cast --list-devices      # List all discovered devices
  python -m tv_cast --forget            # Forget current device

  # Cache
  python -m tv_cast --clear-cache       # Clear cached conversions

  # Interactive mode
  python -m tv_cast                     # Launch interactive menu
        """
    )

    parser.add_argument("video", nargs="?", help="Video file or YouTube URL to cast")

    # Casting options
    parser.add_argument("-d", "--duration", type=int, default=0,
                        help="Duration in seconds (0 = until Ctrl+C)")
    parser.add_argument("--image", metavar="PATH",
                        help="Display an image on TV (10 second duration)")
    parser.add_argument("--stop", action="store_true",
                        help="Stop current playback")

    # Device management
    parser.add_argument("--scan", action="store_true",
                        help="Scan network for cast-capable TVs")
    parser.add_argument("--scan-all", action="store_true",
                        help="Scan network for ALL devices (deep scan)")
    parser.add_argument("--device", metavar="IP",
                        help="Set TV by IP address")
    parser.add_argument("--select-device", action="store_true",
                        help="Interactively select a device")
    parser.add_argument("--list-devices", action="store_true",
                        help="List all discovered devices")
    parser.add_argument("--status", action="store_true",
                        help="Show current device and status")
    parser.add_argument("--forget", action="store_true",
                        help="Forget/unpair current device")

    # Cache
    parser.add_argument("--clear-cache", action="store_true",
                        help="Clear cached HLS conversions")

    args = parser.parse_args()

    # Handle commands in priority order
    if args.status:
        show_status()
    elif args.list_devices:
        list_devices_cli()
    elif args.scan:
        asyncio.run(scan_devices_cli())
    elif args.scan_all:
        asyncio.run(scan_all_devices_cli())
    elif args.device:
        set_device_by_ip(args.device)
    elif args.select_device:
        from .discovery import discover_dlna_devices
        asyncio.run(device_menu())
    elif args.forget:
        forget_device()
    elif args.clear_cache:
        clear_cache()
    elif args.stop:
        asyncio.run(stop_playback())
    elif args.image:
        cast_image_cli(args.image, args.duration or 10)
    elif args.video:
        current_device = get_current_device()
        if not current_device:
            print("❌ No device selected. Use --scan and --device IP to set one.")
            return
        asyncio.run(cast_video(args.video, args.duration))
    else:
        # Interactive mode
        run_interactive()


def run_interactive():
    """Run the interactive menu loop."""
    while True:
        try:
            choice = main_menu()

            if choice == 'QUIT':
                break
            elif choice == 'PLAYBACK':
                playback_menu_loop()
            elif choice == 'DEVICES':
                asyncio.run(device_menu())
            elif choice == 'CLEAR_CACHE':
                clear_cache()
                print()

        except KeyboardInterrupt:
            print("\n")
            continue

