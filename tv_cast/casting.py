"""Video casting to Samsung TVs via DLNA."""

import asyncio
import http.server
import os
import threading
from typing import Optional, Tuple, Any

from async_upnp_client.aiohttp import AiohttpRequester
from async_upnp_client.client_factory import UpnpFactory

from .config import (
    HTTP_PORT, get_current_device, set_current_device,
    save_config, save_discovered_devices
)
from .utils import get_local_ip, check_port, is_youtube_url
from .conversion import convert_to_hls
from .youtube import download_youtube
from .discovery import discover_dlna_devices


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler that logs requests."""

    def log_message(self, format, *args):
        print(f"   📥 TV: {args[0]}")

    def end_headers(self):
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()


async def get_av_transport() -> Tuple[Optional[Any], Optional[str]]:
    """Connect to selected device and get AVTransport service."""
    current_device = get_current_device()

    if not current_device:
        print("❌ No device selected. Use 'd' to select a device.")
        return None, None

    ip = current_device['ip']
    device_name = current_device.get('name', ip)

    print(f"   Checking if {ip} is reachable...")

    test_ports = [9197, 8001, 8002, 7676, 7678, 80]
    reachable = False
    for port in test_ports:
        if check_port(ip, port, timeout=1.0):
            reachable = True
            break

    if not reachable:
        print(f"\n⚠️  Device '{device_name}' at {ip} is not responding.")
        print("   Possible causes:")
        print("   • TV is turned off or in deep standby")
        print("   • TV's IP address may have changed")

        switched = await _scan_and_offer_alternatives(ip, device_name)
        if switched:
            print(f"\n📺 Connecting to new device...")
            return await get_av_transport()
        return None, None

    requester = AiohttpRequester()
    factory = UpnpFactory(requester)

    locations_to_try = []

    saved_location = current_device.get('location')
    if saved_location:
        locations_to_try.append(saved_location)

    port = current_device.get('port', 9197)
    common_endpoints = [
        f'http://{ip}:{port}/dmr',
        f'http://{ip}:9197/dmr',
        f'http://{ip}:9197/dmr/SamsungMRDesc.xml',
        f'http://{ip}:7676/dmr',
        f'http://{ip}:7678/dmr',
    ]

    for endpoint in common_endpoints:
        if endpoint not in locations_to_try:
            locations_to_try.append(endpoint)

    last_error = None
    for location in locations_to_try:
        try:
            device = await asyncio.wait_for(
                factory.async_create_device(location),
                timeout=10.0
            )

            for service in device.services.values():
                if 'AVTransport' in service.service_type:
                    if location != saved_location:
                        current_device['location'] = location
                        save_config()
                    return service, device.friendly_name

        except asyncio.TimeoutError:
            last_error = f"Connection timed out ({location})"
            continue
        except Exception as e:
            last_error = str(e)
            continue

    print(f"\n⚠️  Could not connect to DLNA service on {device_name}")
    print("   Possible causes:")
    print("   • TV's DLNA/media sharing is disabled")
    print("   • TV needs to accept connection (check for popup on TV)")
    print("   • TV firmware may need updating")
    if last_error:
        print(f"\n   Last error: {last_error[:100]}")

    switched = await _scan_and_offer_alternatives(ip, device_name)
    if switched:
        print(f"\n📺 Connecting to new device...")
        return await get_av_transport()

    return None, None


async def _scan_and_offer_alternatives(failed_ip: str, failed_name: str) -> bool:
    """Scan for alternative DLNA devices and offer to switch."""
    print(f"\n🔍 Scanning for other TVs on the network...")

    try:
        alternative_devices = await discover_dlna_devices(timeout=4)
        alternatives = [
            d for d in alternative_devices if d.get('ip') != failed_ip]

        if not alternatives:
            print("   No other TVs found on the network.")
            print("\n   💡 Try:")
            print("   • Turn on the TV and wait a moment")
            print("   • Check that the TV is on the same WiFi network")
            print("   • Run a full scan from the 'Network Devices' menu")
            return False

        print(f"\n📺 Found {len(alternatives)} other TV(s):\n")
        for i, dev in enumerate(alternatives, 1):
            print(f"   {i}. {dev.get('name', 'Unknown')} ({dev.get('ip')})")

        print(f"\n   0. Cancel (don't switch)")
        print()

        try:
            choice = input(
                f"Switch to a different TV? (1-{len(alternatives)}, or 0 to cancel): ").strip()

            if choice == '0' or choice.lower() in ('', 'n', 'no', 'q'):
                print("   Keeping current device selection.")
                return False

            idx = int(choice) - 1
            if 0 <= idx < len(alternatives):
                selected = alternatives[idx]
                set_current_device(selected)
                save_config()
                save_discovered_devices(alternatives)
                print(
                    f"\n✅ Switched to: {selected.get('name')} ({selected.get('ip')})")
                return True
            else:
                print("   Invalid selection. Keeping current device.")
                return False

        except (ValueError, EOFError, KeyboardInterrupt):
            print("\n   Keeping current device selection.")
            return False

    except Exception as e:
        print(f"   Scan failed: {e}")
        print("\n   💡 Try running a full scan from the 'Network Devices' menu")
        return False


async def stop_playback() -> bool:
    """Stop current playback on TV."""
    current_device = get_current_device()
    if not current_device:
        print("❌ No device selected")
        return False

    print(f"📺 Connecting to {current_device['name']}...")

    try:
        av_transport, tv_name = await get_av_transport()
        if av_transport:
            print(f"   ✅ Connected: {tv_name}")
            print("⏹️  Stopping playback...")
            stop = av_transport.action('Stop')
            await stop.async_call(InstanceID=0)
            print("   ✅ Stopped")
            return True
    except Exception as e:
        print(f"❌ Error: {e}")

    return False


async def cast_video(video_path: str, duration: int = 0) -> bool:
    """Cast video to Samsung TV."""
    current_device = get_current_device()

    print("=" * 60)
    print("📺 Samsung TV Video Caster")
    print("=" * 60)

    if is_youtube_url(video_path):
        print(f"\n🎬 YouTube: {video_path}")
        video_path = download_youtube(video_path)
        if not video_path:
            return False
    elif not os.path.exists(video_path):
        print(f"❌ File not found: {video_path}")
        return False

    video_path = os.path.abspath(video_path)
    video_name = os.path.basename(video_path)
    print(f"\n🎬 Video: {video_name}")

    playlist_path = convert_to_hls(video_path)
    if not playlist_path:
        return False

    cache_dir = os.path.dirname(playlist_path)

    local_ip = get_local_ip()
    original_dir = os.getcwd()
    os.chdir(cache_dir)

    server = http.server.HTTPServer((local_ip, HTTP_PORT), QuietHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    hls_url = f"http://{local_ip}:{HTTP_PORT}/playlist.m3u8"
    print(f"\n🌐 Stream URL: {hls_url}")

    try:
        device_name = current_device['name'] if current_device else "device"
        print(f"\n📺 Connecting to {device_name}...")
        av_transport, tv_name = await get_av_transport()

        if not av_transport:
            print("❌ Could not connect to TV")
            return False

        print(f"   ✅ Connected: {tv_name}")

        didl = f'''<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" 
                    xmlns:dc="http://purl.org/dc/elements/1.1/" 
                    xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/">
            <item id="0" parentID="-1" restricted="1">
                <dc:title>{video_name}</dc:title>
                <upnp:class>object.item.videoItem</upnp:class>
                <res protocolInfo="http-get:*:application/vnd.apple.mpegurl:*">{hls_url}</res>
            </item>
        </DIDL-Lite>'''

        try:
            stop = av_transport.action('Stop')
            await stop.async_call(InstanceID=0)
        except Exception:
            pass

        print("\n🎬 Loading video...")
        set_uri = av_transport.action('SetAVTransportURI')
        await set_uri.async_call(InstanceID=0, CurrentURI=hls_url, CurrentURIMetaData=didl)

        await asyncio.sleep(0.5)

        print("▶️  Starting playback...")
        play = av_transport.action('Play')
        await play.async_call(InstanceID=0, Speed='1')

        print("\n" + "=" * 60)
        print("🎉 NOW PLAYING ON YOUR TV!")
        print("=" * 60)

        if duration > 0:
            print(f"\n⏱️  Playing for {duration} seconds...")
            await asyncio.sleep(duration)
        else:
            print("\n⏱️  Press Ctrl+C to stop and return to menu")
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                pass

        print("\n⏹️  Stopping playback...")
        stop = av_transport.action('Stop')
        await stop.async_call(InstanceID=0)
        print("   ✅ Stopped")

        return True

    except KeyboardInterrupt:
        print("\n⏹️  Stopping playback...")
        try:
            av_transport, _ = await get_av_transport()
            stop = av_transport.action('Stop')
            await stop.async_call(InstanceID=0)
            print("   ✅ Stopped")
        except Exception:
            pass
        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        os.chdir(original_dir)
        server.shutdown()


def cleanup_on_exit() -> None:
    """Stop playback when exiting the app."""
    current_device = get_current_device()

    if not current_device:
        return

    print("\n⏹️  Stopping playback...")

    try:
        import urllib.request
        from urllib.parse import urlparse

        location = current_device.get('location')
        if not location:
            ip = current_device['ip']
            port = current_device.get('port', 9197)
            location = f'http://{ip}:{port}/dmr'

        parsed = urlparse(location)
        control_url = f"http://{parsed.hostname}:{parsed.port}/upnp/control/AVTransport1"

        soap_body = '''<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:Stop xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
            <InstanceID>0</InstanceID>
        </u:Stop>
    </s:Body>
</s:Envelope>'''

        req = urllib.request.Request(
            control_url,
            data=soap_body.encode('utf-8'),
            headers={
                'Content-Type': 'text/xml; charset="utf-8"',
                'SOAPACTION': '"urn:schemas-upnp-org:service:AVTransport:1#Stop"',
            }
        )

        urllib.request.urlopen(req, timeout=2)
        print("   ✅ Stopped")
    except Exception:
        pass
