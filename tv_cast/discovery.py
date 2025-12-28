"""Device discovery via DLNA, mDNS, and network scanning."""

import asyncio
import concurrent.futures
import socket
import subprocess
import time
from typing import List, Dict, Any, Optional

from .config import get_discovered_devices, set_discovered_devices, save_discovered_devices
from .utils import get_local_ip, get_local_subnet, ping_host, get_hostname, check_port


async def discover_dlna_devices(timeout: int = 5) -> List[Dict[str, Any]]:
    """Discover DLNA Media Renderer devices on the network."""
    from async_upnp_client.search import async_search

    devices = []
    seen = set()

    async def on_response(response):
        location = response.get('location', '')
        if location and location not in seen:
            seen.add(location)

            try:
                from urllib.parse import urlparse
                from async_upnp_client.aiohttp import AiohttpRequester
                from async_upnp_client.client_factory import UpnpFactory

                parsed = urlparse(location)
                ip = parsed.hostname
                port = parsed.port or 80

                requester = AiohttpRequester()
                factory = UpnpFactory(requester)

                try:
                    device = await factory.async_create_device(location)
                    name = device.friendly_name or f"Unknown ({ip})"

                    # Check if device has AVTransport (media playback)
                    has_av = any('AVTransport' in str(s.service_type)
                                 for s in device.services.values())

                    if has_av:
                        devices.append({
                            'name': name,
                            'ip': ip,
                            'port': port,
                            'location': location,
                            'type': 'dlna',
                            'castable': True,
                        })
                        print(f"   📺 {name} ({ip})")
                except Exception:
                    pass
            except (ValueError, AttributeError):
                pass

    try:
        await async_search(
            search_target='urn:schemas-upnp-org:device:MediaRenderer:1',
            timeout=timeout,
            async_callback=on_response
        )
    except Exception:
        pass

    return devices


def discover_mdns_devices(timeout: int = 5) -> List[Dict[str, Any]]:
    """Discover devices via mDNS/Bonjour."""
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

    devices = []
    seen_ips = set()

    service_types = [
        "_airplay._tcp.local.",
        "_raop._tcp.local.",
        "_googlecast._tcp.local.",
        "_spotify-connect._tcp.local.",
        "_homekit._tcp.local.",
        "_hap._tcp.local.",
        "_companion-link._tcp.local.",
        "_sleep-proxy._udp.local.",
        "_smb._tcp.local.",
        "_afpovertcp._tcp.local.",
        "_http._tcp.local.",
        "_ipp._tcp.local.",
        "_printer._tcp.local.",
        "_ssh._tcp.local.",
        "_workstation._tcp.local.",
        "_device-info._tcp.local.",
    ]

    class MyListener(ServiceListener):
        def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            try:
                info = zc.get_service_info(type_, name)
                if info and info.addresses:
                    ip = socket.inet_ntoa(info.addresses[0])

                    if ip in seen_ips:
                        return
                    seen_ips.add(ip)

                    device_type = "unknown"
                    castable = False
                    icon = "📱"

                    if "_airplay" in type_ or "_raop" in type_:
                        device_type = "airplay"
                        castable = True
                        icon = "🍎"
                    elif "_googlecast" in type_:
                        device_type = "chromecast"
                        castable = True
                        icon = "📺"
                    elif "_spotify" in type_:
                        device_type = "spotify"
                        icon = "🎵"
                    elif "_homekit" in type_ or "_hap" in type_:
                        device_type = "homekit"
                        icon = "🏠"
                    elif "_companion" in type_ or "_sleep-proxy" in type_:
                        device_type = "apple"
                        icon = "🍎"
                    elif "_smb" in type_ or "_afp" in type_:
                        device_type = "file-share"
                        icon = "📁"
                    elif "_printer" in type_ or "_ipp" in type_:
                        device_type = "printer"
                        icon = "🖨️"
                    elif "_ssh" in type_:
                        device_type = "computer"
                        icon = "💻"
                    elif "_workstation" in type_:
                        device_type = "computer"
                        icon = "💻"
                    elif "_http" in type_:
                        device_type = "web"
                        icon = "🌐"

                    friendly_name = name.split(".")[0] if name else f"Device ({ip})"

                    if info.properties:
                        model = info.properties.get(b'model', b'').decode(
                            'utf-8', errors='ignore')
                        if model:
                            friendly_name = f"{friendly_name} ({model})"

                    devices.append({
                        'name': friendly_name,
                        'ip': ip,
                        'port': info.port,
                        'type': device_type,
                        'castable': castable,
                        'service': type_,
                    })
                    print(f"   {icon} {friendly_name} ({ip})")

            except (AttributeError, ValueError, IndexError):
                pass

        def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            pass

        def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            pass

    zc = Zeroconf()
    listener = MyListener()

    browsers = []
    for service_type in service_types:
        try:
            browser = ServiceBrowser(zc, service_type, listener)
            browsers.append(browser)
        except Exception:
            pass

    time.sleep(timeout)
    zc.close()
    return devices


def get_mac_vendor(mac: str) -> Optional[str]:
    """Get vendor name from MAC address prefix."""
    vendors = {
        "00:1A:79": "Tesla",
        "4C:FC:AA": "Tesla",
        "00:17:F2": "Apple",
        "3C:06:30": "Apple",
        "B8:27:EB": "Raspberry Pi",
        "B8:17:C2": "Samsung",
        "78:BD:BC": "Samsung",
        "8C:71:F8": "Samsung",
        "00:1A:11": "Google",
        "F4:F5:D8": "Google",
        "00:50:F2": "Microsoft",
        "B4:2E:99": "Amazon",
        "00:04:20": "Roku",
        "00:0E:08": "Sony",
        "A0:D3:7A": "LG",
        "00:1B:63": "HP",
        "00:21:9B": "Dell",
    }

    if not mac:
        return None

    mac_prefix = mac.upper().replace("-", ":")[0:8]
    return vendors.get(mac_prefix)


def scan_arp_table() -> List[Dict[str, str]]:
    """Get devices from the system ARP table."""
    import platform
    import re

    devices = []

    try:
        if platform.system().lower() == "darwin":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        elif platform.system().lower() == "windows":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        else:
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=5)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                mac_match = re.search(
                    r'([0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2})',
                    line
                )

                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(1).upper().replace("-", ":")

                    if "(incomplete)" in line.lower() or mac == "FF:FF:FF:FF:FF:FF":
                        continue

                    devices.append({'ip': ip, 'mac': mac})
    except Exception:
        pass

    return devices


def discover_network_hosts(timeout: int = 10) -> List[Dict[str, Any]]:
    """Discover all hosts on the local network via ARP + ping sweep."""

    devices = []
    seen_ips = set()

    print("   📋 Checking ARP table...")

    arp_devices = scan_arp_table()

    for dev in arp_devices:
        ip = dev['ip']
        if ip not in seen_ips:
            seen_ips.add(ip)

            hostname = get_hostname(ip)
            vendor = get_mac_vendor(dev.get('mac', ''))

            if hostname:
                name = hostname.split('.')[0]
            elif vendor:
                name = f"{vendor} Device"
            else:
                name = "Device"

            device_type = "unknown"
            if vendor:
                vendor_lower = vendor.lower()
                if "tesla" in vendor_lower:
                    device_type = "tesla"
                elif "apple" in vendor_lower:
                    device_type = "apple"
                elif "samsung" in vendor_lower:
                    device_type = "samsung"

            devices.append({
                'name': f"{name} ({ip})",
                'ip': ip,
                'mac': dev.get('mac'),
                'type': device_type,
                'vendor': vendor,
                'hostname': hostname,
                'castable': False,
            })

    # Ping sweep
    subnet = get_local_subnet()
    my_ip = get_local_ip()

    print(f"   🔍 Ping sweep on {subnet}.0/24...")

    ips_to_scan = [
        f"{subnet}.{i}" for i in range(1, 255)
        if f"{subnet}.{i}" not in seen_ips and f"{subnet}.{i}" != my_ip
    ]

    def check_host(ip):
        if ping_host(ip, timeout=0.5):
            return ip
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_host, ip): ip for ip in ips_to_scan}

        try:
            for future in concurrent.futures.as_completed(futures, timeout=timeout):
                try:
                    ip = future.result(timeout=0.1)
                    if ip and ip not in seen_ips:
                        seen_ips.add(ip)
                        hostname = get_hostname(ip)
                        name = hostname.split('.')[0] if hostname else "Device"

                        devices.append({
                            'name': f"{name} ({ip})",
                            'ip': ip,
                            'type': 'unknown',
                            'hostname': hostname,
                            'castable': False,
                        })
                except Exception:
                    pass
        except concurrent.futures.TimeoutError:
            pass

        for future in futures:
            future.cancel()

    return devices


async def discover_all_devices(timeout: int = 8) -> List[Dict[str, Any]]:
    """Discover all devices on the network (ARP, ping, mDNS, DLNA)."""

    print(f"🔍 Scanning network for all devices...")
    print()

    all_devices = []
    seen_ips = set()

    loop = asyncio.get_event_loop()

    mdns_devices = []
    network_devices = []
    dlna_devices = []

    with concurrent.futures.ThreadPoolExecutor() as pool:
        mdns_future = loop.run_in_executor(pool, discover_mdns_devices, 3)
        network_future = loop.run_in_executor(pool, discover_network_hosts, 6)

        try:
            dlna_devices = await asyncio.wait_for(discover_dlna_devices(3), timeout=5)
        except (asyncio.TimeoutError, Exception):
            pass

        try:
            mdns_devices = await asyncio.wait_for(mdns_future, timeout=5)
        except (asyncio.TimeoutError, Exception):
            pass

        try:
            network_devices = await asyncio.wait_for(network_future, timeout=10)
        except (asyncio.TimeoutError, Exception):
            pass

    # Merge results
    for dev in dlna_devices:
        ip = dev.get('ip')
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            all_devices.append(dev)

    for dev in mdns_devices:
        ip = dev.get('ip')
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            all_devices.append(dev)
        elif ip in seen_ips:
            for existing in all_devices:
                if existing.get('ip') == ip:
                    if dev.get('castable') and not existing.get('castable'):
                        existing['castable'] = True
                    break

    for dev in network_devices:
        ip = dev.get('ip')
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            all_devices.append(dev)
        elif ip in seen_ips:
            for existing in all_devices:
                if existing.get('ip') == ip:
                    if dev.get('mac') and not existing.get('mac'):
                        existing['mac'] = dev.get('mac')
                    if dev.get('vendor') and not existing.get('vendor'):
                        existing['vendor'] = dev.get('vendor')
                    break

    # Filter out multicast/broadcast
    all_devices = [d for d in all_devices if not d.get('ip', '').startswith('224.')]

    print(f"\n✅ Found {len(all_devices)} device(s)")

    return all_devices

