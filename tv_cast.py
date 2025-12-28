#!/usr/bin/env python3
"""
Samsung TV Video Caster

Cast any video file directly to your Samsung TV via DLNA.
Automatically converts to HLS format for maximum compatibility.

Usage:
    python tv_cast.py video.mp4              # Cast a video
    python tv_cast.py video.mp4 --duration 60  # Cast for 60 seconds
    python tv_cast.py --stop                 # Stop current playback
"""

import argparse
import asyncio
import os
import shutil
import socket
import subprocess
import http.server
import threading
import tempfile

from async_upnp_client.aiohttp import AiohttpRequester
from async_upnp_client.client_factory import UpnpFactory


# Settings
HTTP_PORT = 8765
CONFIG_DIR = os.path.expanduser("~/.tv_cast")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
HLS_CACHE_DIR = os.path.join(CONFIG_DIR, "hls_cache")
YOUTUBE_CACHE_DIR = os.path.join(CONFIG_DIR, "youtube")
FFMPEG_THREADS = 20

# Selected device (loaded from config)
CURRENT_DEVICE = None


DISCOVERED_DEVICES = []  # Previously discovered devices


def load_config():
    """Load saved configuration."""
    global CURRENT_DEVICE, DISCOVERED_DEVICES
    os.makedirs(CONFIG_DIR, exist_ok=True)

    if os.path.exists(CONFIG_FILE):
        try:
            import json
            with open(CONFIG_FILE) as f:
                config = json.load(f)
                CURRENT_DEVICE = config.get('device')
                DISCOVERED_DEVICES = config.get('discovered_devices', [])
        except:
            pass


def make_json_serializable(obj):
    """Convert an object to be JSON serializable."""
    if obj is None:
        return None
    elif isinstance(obj, (str, int, float, bool)):
        return obj
    elif isinstance(obj, bytes):
        return obj.decode('utf-8', errors='ignore')
    elif isinstance(obj, dict):
        return {str(k): make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [make_json_serializable(item) for item in obj]
    elif hasattr(obj, '__dict__'):
        return make_json_serializable(obj.__dict__)
    else:
        # Try to convert to string as last resort
        try:
            return str(obj)
        except:
            return None


def save_config():
    """Save current configuration."""
    import json
    os.makedirs(CONFIG_DIR, exist_ok=True)

    # Make sure all data is JSON serializable
    config = {
        'device': make_json_serializable(CURRENT_DEVICE),
        'discovered_devices': make_json_serializable(DISCOVERED_DEVICES),
    }
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)


def save_discovered_devices(devices: list):
    """Save discovered devices to config."""
    global DISCOVERED_DEVICES

    # Merge with existing - update known devices, add new ones
    existing_ips = {d.get('ip') for d in DISCOVERED_DEVICES}

    for device in devices:
        if device.get('ip') in existing_ips:
            # Update existing device
            for i, existing in enumerate(DISCOVERED_DEVICES):
                if existing.get('ip') == device.get('ip'):
                    DISCOVERED_DEVICES[i] = device
                    break
        else:
            # Add new device
            DISCOVERED_DEVICES.append(device)

    save_config()


def forget_device():
    """Forget/unpair the current device."""
    global CURRENT_DEVICE
    CURRENT_DEVICE = None
    save_config()
    print("🔌 Device forgotten")


async def discover_dlna_devices(timeout: int = 5) -> list:
    """Discover DLNA Media Renderer devices on the network."""
    from async_upnp_client.search import async_search
    from async_upnp_client.aiohttp import AiohttpRequester

    devices = []
    seen = set()

    async def on_response(response):
        location = response.get('location', '')
        if location and location not in seen:
            seen.add(location)

            try:
                from urllib.parse import urlparse
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
                except Exception as e:
                    pass
            except:
                pass

    try:
        await async_search(
            search_target='urn:schemas-upnp-org:device:MediaRenderer:1',
            timeout=timeout,
            async_callback=on_response
        )
    except Exception as e:
        pass

    return devices


def discover_mdns_devices(timeout: int = 5) -> list:
    """Discover devices via mDNS/Bonjour (phones, computers, smart devices, etc.)."""
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
    import time

    devices = []
    seen_ips = set()

    # Service types to search for
    service_types = [
        "_airplay._tcp.local.",      # Apple TV, AirPlay speakers
        "_raop._tcp.local.",         # AirPlay audio
        "_googlecast._tcp.local.",   # Chromecast, Google Home
        "_spotify-connect._tcp.local.",  # Spotify devices
        "_homekit._tcp.local.",      # HomeKit devices
        "_hap._tcp.local.",          # HomeKit Accessory Protocol
        "_companion-link._tcp.local.",  # Apple devices
        "_sleep-proxy._udp.local.",  # Apple devices
        "_smb._tcp.local.",          # Windows/Samba shares
        "_afpovertcp._tcp.local.",   # Mac file sharing
        "_http._tcp.local.",         # Web servers
        "_ipp._tcp.local.",          # Printers
        "_printer._tcp.local.",      # Printers
        "_ssh._tcp.local.",          # SSH servers
        "_workstation._tcp.local.",  # Linux workstations
        "_device-info._tcp.local.",  # Device info
    ]

    class MyListener(ServiceListener):
        def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            try:
                info = zc.get_service_info(type_, name)
                if info and info.addresses:
                    import socket
                    ip = socket.inet_ntoa(info.addresses[0])

                    if ip in seen_ips:
                        return
                    seen_ips.add(ip)

                    # Determine device type from service
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

                    # Extract friendly name
                    friendly_name = name.split(
                        ".")[0] if name else f"Device ({ip})"

                    # Try to get more info from properties
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

            except Exception as e:
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
        except:
            pass

    # Wait for discovery
    time.sleep(timeout)

    zc.close()
    return devices


def get_local_subnet():
    """Get the local subnet for scanning."""
    local_ip = get_local_ip()
    # Assume /24 subnet (most common for home networks)
    parts = local_ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}"


# Common ports to scan for device identification
COMMON_PORTS = {
    21: ("ftp", "FTP Server"),
    22: ("ssh", "SSH Server"),
    23: ("telnet", "Telnet"),
    53: ("dns", "DNS Server"),
    80: ("http", "Web Server"),
    443: ("https", "HTTPS Server"),
    445: ("smb", "Windows File Share"),
    548: ("afp", "Apple File Share"),
    554: ("rtsp", "RTSP Streaming"),
    631: ("ipp", "Printer (IPP)"),
    1883: ("mqtt", "MQTT Broker"),
    3000: ("http", "Web App"),
    3389: ("rdp", "Remote Desktop"),
    5000: ("http", "Web App / Synology"),
    5001: ("https", "Synology HTTPS"),
    5353: ("mdns", "mDNS"),
    7000: ("airplay", "AirPlay"),
    7100: ("airplay", "AirPlay"),
    8000: ("http", "Web Server"),
    8008: ("chromecast", "Chromecast"),
    8009: ("chromecast", "Chromecast"),
    8080: ("http", "Web Server / Proxy"),
    8443: ("https", "HTTPS Alt"),
    8888: ("http", "Web Server"),
    9000: ("http", "Web App"),
    9090: ("http", "Prometheus / Web"),
    9100: ("printer", "Printer (RAW)"),
    9197: ("dlna", "DLNA/UPnP"),
    32400: ("plex", "Plex Media Server"),
    32469: ("plex", "Plex DLNA"),
    49152: ("upnp", "UPnP"),
    62078: ("apple", "Apple iDevice"),
}


def check_port(ip: str, port: int, timeout: float = 0.3) -> bool:
    """Check if a port is open on a host."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    except:
        return False
    finally:
        sock.close()


def scan_ports(ip: str, ports: list = None, timeout: float = 0.3) -> list:
    """Scan common ports on a host."""
    import concurrent.futures

    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports = []

    def check(port):
        if check_port(ip, port, timeout):
            return port
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures, timeout=5):
            try:
                port = future.result(timeout=0.1)
                if port:
                    open_ports.append(port)
            except:
                pass

    return sorted(open_ports)


def nmap_scan(ip: str, scan_type: str = "quick") -> dict:
    """Use nmap for deep device scanning.

    scan_type options:
    - "quick": Fast scan of common ports with service detection
    - "ping": Just check if host is up and get basic info
    - "os": OS detection (requires root/sudo)
    - "full": Comprehensive scan with version detection
    - "aggressive": Very thorough scan with scripts
    """
    try:
        import nmap
    except ImportError:
        return {'error': 'python-nmap not installed'}

    nm = nmap.PortScanner()
    result = {
        'ports': [],
        'services': [],
        'os': None,
        'os_accuracy': None,
        'hostname': None,
        'mac': None,
        'vendor': None,
        'device_type': None,
        'uptime': None,
        'scripts': {},
        'scan_type': scan_type,
    }

    try:
        # Check if running as root for privileged scans
        import os as os_mod
        is_root = os_mod.geteuid() == 0 if hasattr(os_mod, 'geteuid') else False

        # Different scan types with different tradeoffs
        # Use -sT (TCP connect) for non-root, -sS (SYN) for root
        scan_flag = '-sS' if is_root else '-sT'

        if scan_type == "ping":
            # Just ping and get MAC/vendor - ARP ping works on local network
            nm.scan(ip, arguments='-sn')
        elif scan_type == "quick":
            # Fast scan - top 100 ports, service detection
            nm.scan(
                ip, arguments=f'{scan_flag} -sV -T4 -F --version-intensity 2 --host-timeout 30s')
        elif scan_type == "os":
            # OS detection - needs root for accurate results
            if is_root:
                nm.scan(ip, arguments='-O -sV -T4 -F --host-timeout 60s')
            else:
                # Without root, use aggressive mode which does some OS guessing
                nm.scan(
                    ip, arguments=f'{scan_flag} -sV -A -T4 -F --host-timeout 60s')
        elif scan_type == "full":
            # More thorough - top 1000 ports
            nm.scan(
                ip, arguments=f'{scan_flag} -sV -T4 --version-intensity 5 --host-timeout 120s')
        elif scan_type == "aggressive":
            # Very thorough with scripts
            nm.scan(
                ip, arguments=f'{scan_flag} -sV -sC -A -T4 --host-timeout 180s')
        else:
            # Default to quick
            nm.scan(
                ip, arguments=f'{scan_flag} -sV -T4 -F --version-intensity 2 --host-timeout 30s')

        if ip in nm.all_hosts():
            host = nm[ip]

            # Hostname
            if 'hostnames' in host and host['hostnames']:
                for h in host['hostnames']:
                    if h.get('name'):
                        result['hostname'] = h['name']
                        break

            # MAC and vendor
            if 'addresses' in host:
                if 'mac' in host['addresses']:
                    result['mac'] = host['addresses']['mac']

            if 'vendor' in host and host['vendor']:
                for mac, vendor in host['vendor'].items():
                    result['vendor'] = vendor
                    break

            # OS detection
            if 'osmatch' in host and host['osmatch']:
                best_match = host['osmatch'][0]
                result['os'] = best_match.get('name')
                result['os_accuracy'] = best_match.get('accuracy')

                # Get device type from OS class
                if 'osclass' in best_match:
                    for osclass in best_match['osclass']:
                        if osclass.get('type'):
                            result['device_type'] = osclass['type']
                            break

            # Uptime
            if 'uptime' in host:
                result['uptime'] = host['uptime'].get('lastboot')

            # Ports and services
            for proto in ['tcp', 'udp']:
                if proto in host:
                    for port, port_info in host[proto].items():
                        port_data = {
                            'port': port,
                            'protocol': proto,
                            'state': port_info.get('state'),
                            'service': port_info.get('name'),
                            'product': port_info.get('product'),
                            'version': port_info.get('version'),
                            'extrainfo': port_info.get('extrainfo'),
                        }
                        result['ports'].append(port_data)

                        if port_info.get('state') == 'open':
                            service_str = port_info.get('name', 'unknown')
                            if port_info.get('product'):
                                service_str += f" ({port_info['product']}"
                                if port_info.get('version'):
                                    service_str += f" {port_info['version']}"
                                service_str += ")"
                            result['services'].append({
                                'port': port,
                                'name': service_str,
                            })

            # Script results
            if 'hostscript' in host:
                for script in host['hostscript']:
                    script_id = script.get('id', 'unknown')
                    result['scripts'][script_id] = script.get('output', '')
        else:
            result['error'] = 'Host not found in scan results'

    except nmap.PortScannerError as e:
        result['error'] = f'Nmap error: {e}'
    except Exception as e:
        result['error'] = f'Scan error: {e}'

    return result


def get_mac_vendor_lookup(mac: str) -> str:
    """Look up vendor from MAC address using mac-vendor-lookup library."""
    try:
        from mac_vendor_lookup import MacLookup
        lookup = MacLookup()
        return lookup.lookup(mac)
    except:
        return None


def get_mac_address(ip: str) -> str:
    """Get MAC address for an IP using getmac library."""
    try:
        from getmac import get_mac_address as gma
        return gma(ip=ip)
    except:
        return None


def deep_probe_device(ip: str, use_nmap: bool = True) -> dict:
    """Perform deep probe of a device using multiple techniques."""
    result = {
        'ip': ip,
        'hostname': None,
        'mac': None,
        'vendor': None,
        'os': None,
        'os_version': None,
        'device_type': None,
        'open_ports': [],
        'services': [],
        'nmap_info': None,
        'uptime': None,
    }

    # Get hostname
    result['hostname'] = get_hostname(ip)

    # Get MAC address using getmac library (most reliable)
    try:
        mac = get_mac_address(ip)
        if mac and mac != '00:00:00:00:00:00':
            result['mac'] = mac.upper().replace('-', ':')
    except:
        pass

    # Lookup vendor from MAC using mac-vendor-lookup library
    if result['mac']:
        try:
            vendor = get_mac_vendor_lookup(result['mac'])
            if vendor:
                result['vendor'] = vendor
        except:
            pass

        # Fallback to our built-in lookup
        if not result['vendor']:
            vendor = get_mac_vendor(result['mac'])
            if vendor:
                result['vendor'] = vendor

    # Infer device type from vendor
    if result['vendor']:
        vendor_lower = result['vendor'].lower()
        if 'apple' in vendor_lower:
            result['device_type'] = 'apple'
        elif 'samsung' in vendor_lower:
            result['device_type'] = 'samsung'
        elif 'google' in vendor_lower:
            result['device_type'] = 'google'
        elif 'amazon' in vendor_lower:
            result['device_type'] = 'amazon'
        elif 'tesla' in vendor_lower:
            result['device_type'] = 'tesla'
        elif 'raspberry' in vendor_lower:
            result['device_type'] = 'raspberry-pi'
        elif 'roku' in vendor_lower:
            result['device_type'] = 'roku'
        elif 'sony' in vendor_lower:
            result['device_type'] = 'sony'
        elif 'lg' in vendor_lower:
            result['device_type'] = 'lg'
        elif 'hp' in vendor_lower or 'hewlett' in vendor_lower:
            result['device_type'] = 'printer'
        elif 'canon' in vendor_lower or 'epson' in vendor_lower or 'brother' in vendor_lower:
            result['device_type'] = 'printer'
        elif 'synology' in vendor_lower:
            result['device_type'] = 'synology'
        elif 'intel' in vendor_lower or 'dell' in vendor_lower or 'lenovo' in vendor_lower:
            result['device_type'] = 'computer'
        elif 'tp-link' in vendor_lower or 'netgear' in vendor_lower or 'cisco' in vendor_lower or 'ubiquiti' in vendor_lower:
            result['device_type'] = 'router'
        elif 'nest' in vendor_lower or 'ring' in vendor_lower or 'ecobee' in vendor_lower:
            result['device_type'] = 'smart-home'
        elif 'sonos' in vendor_lower or 'bose' in vendor_lower:
            result['device_type'] = 'speaker'

    # Use nmap for comprehensive scanning
    if use_nmap:
        try:
            nmap_result = nmap_scan(ip, "quick")
            result['nmap_info'] = nmap_result

            if not nmap_result.get('error'):
                # Extract info from nmap
                if nmap_result.get('hostname') and not result['hostname']:
                    result['hostname'] = nmap_result['hostname']

                if nmap_result.get('mac') and not result['mac']:
                    result['mac'] = nmap_result['mac']

                if nmap_result.get('vendor') and not result['vendor']:
                    result['vendor'] = nmap_result['vendor']

                if nmap_result.get('os'):
                    result['os'] = nmap_result['os']
                    result['os_accuracy'] = nmap_result.get('os_accuracy')

                if nmap_result.get('device_type') and not result['device_type']:
                    result['device_type'] = nmap_result['device_type']

                if nmap_result.get('uptime'):
                    result['uptime'] = nmap_result['uptime']

                # Ports and services
                for port_info in nmap_result.get('ports', []):
                    if port_info.get('state') == 'open':
                        result['open_ports'].append(port_info['port'])

                result['services'] = nmap_result.get('services', [])

        except Exception as e:
            result['nmap_error'] = str(e)

    return result


def get_http_info(ip: str, port: int = 80, timeout: float = 2) -> dict:
    """Get information from HTTP server."""
    import urllib.request
    import ssl

    info = {}

    protocol = "https" if port in (443, 8443, 5001) else "http"
    url = f"{protocol}://{ip}:{port}/"

    try:
        # Create context that doesn't verify SSL (for self-signed certs)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url, headers={'User-Agent': 'Mozilla/5.0'})

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            info['status'] = response.status
            info['server'] = response.headers.get('Server', '')
            info['content_type'] = response.headers.get('Content-Type', '')

            # Read first part of body to extract title
            try:
                body = response.read(4096).decode('utf-8', errors='ignore')

                # Extract title
                import re
                title_match = re.search(
                    r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
                if title_match:
                    info['title'] = title_match.group(1).strip()

                # Look for common device identifiers
                body_lower = body.lower()
                if 'tesla' in body_lower:
                    info['device_hint'] = 'tesla'
                elif 'synology' in body_lower:
                    info['device_hint'] = 'synology'
                elif 'plex' in body_lower:
                    info['device_hint'] = 'plex'
                elif 'router' in body_lower or 'gateway' in body_lower:
                    info['device_hint'] = 'router'
                elif 'printer' in body_lower:
                    info['device_hint'] = 'printer'
                elif 'camera' in body_lower or 'webcam' in body_lower:
                    info['device_hint'] = 'camera'
                elif 'samsung' in body_lower:
                    info['device_hint'] = 'samsung'
                elif 'lg' in body_lower:
                    info['device_hint'] = 'lg'
                elif 'roku' in body_lower:
                    info['device_hint'] = 'roku'

            except:
                pass

    except Exception as e:
        pass

    return info


async def probe_apple_device(ip: str, timeout: int = 3) -> dict:
    """Probe an Apple device using pyatv for detailed information."""
    import pyatv

    apple_info = {}

    try:
        # Scan for Apple devices at this specific IP
        devices = await pyatv.scan(asyncio.get_event_loop(),
                                   hosts=[ip],
                                   timeout=timeout)

        if devices:
            config = devices[0]

            apple_info['name'] = config.name
            apple_info['identifier'] = config.identifier
            apple_info['address'] = str(config.address)

            # Get device info
            dev_info = config.device_info
            if dev_info:
                if dev_info.model:
                    apple_info['model'] = dev_info.model.name
                if dev_info.model_str:
                    apple_info['model_str'] = dev_info.model_str
                if dev_info.raw_model:
                    apple_info['raw_model'] = dev_info.raw_model
                if dev_info.operating_system:
                    apple_info['os'] = dev_info.operating_system.name
                if dev_info.version:
                    apple_info['version'] = dev_info.version
                if dev_info.build_number:
                    apple_info['build'] = dev_info.build_number
                if dev_info.mac:
                    apple_info['mac'] = dev_info.mac

            # Get services/protocols
            apple_info['protocols'] = []
            for service in config.services:
                proto_info = {
                    'protocol': service.protocol.name,
                    'port': service.port,
                }
                if service.properties:
                    proto_info['properties'] = dict(service.properties)
                apple_info['protocols'].append(proto_info)

            # Get all properties
            if config.properties:
                apple_info['properties'] = dict(config.properties)

    except Exception as e:
        apple_info['probe_error'] = str(e)

    return apple_info


def probe_apple_device_sync(ip: str, timeout: int = 3) -> dict:
    """Synchronous wrapper for Apple device probing."""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(probe_apple_device(ip, timeout))
        loop.close()
        return result
    except Exception as e:
        return {'probe_error': str(e)}


def probe_device(device: dict, quick: bool = False, use_nmap: bool = True) -> dict:
    """Deep probe a device to gather detailed information."""
    ip = device.get('ip')
    if not ip:
        return device

    # Start with existing info
    probed = dict(device)
    probed['open_ports'] = device.get('open_ports', [])
    probed['services'] = device.get('services', [])
    probed['web_info'] = device.get('web_info', {})

    # Use nmap for comprehensive scanning (if not quick mode)
    if use_nmap and not quick:
        deep_info = deep_probe_device(ip, use_nmap=True)

        # Merge deep probe results
        if deep_info.get('hostname') and not probed.get('hostname'):
            probed['hostname'] = deep_info['hostname']

        if deep_info.get('mac'):
            probed['mac'] = deep_info['mac']

        if deep_info.get('vendor'):
            probed['vendor'] = deep_info['vendor']

        if deep_info.get('os'):
            probed['os'] = deep_info['os']
            if deep_info.get('os_accuracy'):
                probed['os_accuracy'] = deep_info['os_accuracy']

        if deep_info.get('device_type'):
            probed['nmap_device_type'] = deep_info['device_type']

        if deep_info.get('uptime'):
            probed['uptime'] = deep_info['uptime']

        if deep_info.get('open_ports'):
            probed['open_ports'] = deep_info['open_ports']

        if deep_info.get('services'):
            probed['services'] = deep_info['services']

        if deep_info.get('nmap_info'):
            probed['nmap_info'] = deep_info['nmap_info']
    else:
        # Quick port scan fallback
        if quick:
            ports_to_check = [22, 80, 443, 554, 7000, 8008, 8080, 9100]
        else:
            ports_to_check = list(COMMON_PORTS.keys())

        open_ports = scan_ports(ip, ports_to_check)
        probed['open_ports'] = open_ports

        # Identify services from open ports
        services = []
        for port in open_ports:
            if port in COMMON_PORTS:
                service_type, service_name = COMMON_PORTS[port]
                services.append({
                    'port': port,
                    'type': service_type,
                    'name': service_name,
                })
        probed['services'] = services

    open_ports = probed.get('open_ports', [])

    # Check if this might be an Apple device - probe with pyatv
    is_apple = (
        device.get('type', '').startswith('apple') or
        (device.get('vendor') or '').lower() == 'apple' or
        'apple' in (probed.get('vendor') or '').lower() or
        7000 in open_ports or  # AirPlay
        62078 in open_ports    # Apple device port
    )

    if is_apple or device.get('type') in ('airplay', 'apple', 'apple-mobile'):
        apple_info = probe_apple_device_sync(ip, timeout=2)
        if apple_info and not apple_info.get('probe_error'):
            probed['apple_info'] = apple_info

            # Update device info from Apple probe
            if apple_info.get('name'):
                probed['name'] = apple_info['name']
            if apple_info.get('model_str'):
                probed['model'] = apple_info['model_str']
            if apple_info.get('os'):
                probed['os'] = apple_info['os']
            if apple_info.get('version'):
                probed['os_version'] = apple_info['version']
            if apple_info.get('mac'):
                probed['mac'] = apple_info['mac']

            # Determine specific Apple device type
            model = apple_info.get('model', '').lower()
            raw_model = apple_info.get('raw_model', '').lower()

            if 'homepod' in model or 'homepod' in raw_model:
                probed['type'] = 'homepod'
                probed['castable'] = True
            elif 'appletv' in model or 'appletv' in raw_model:
                probed['type'] = 'apple-tv'
                probed['castable'] = True
            elif 'airport' in model or 'airport' in raw_model:
                probed['type'] = 'airport'
            elif apple_info.get('os') == 'MacOS':
                probed['type'] = 'mac'
            elif apple_info.get('protocols'):
                # Check protocols to determine castability
                protocols = [p.get('protocol', '')
                             for p in apple_info['protocols']]
                if 'AirPlay' in protocols or 'RAOP' in protocols:
                    probed['castable'] = True

    # Probe web interfaces
    http_ports = [p for p in open_ports if p in (
        80, 443, 8080, 8443, 3000, 5000, 5001, 8000, 8888, 9000)]

    for port in http_ports[:2]:  # Only probe first 2 web ports
        if port not in probed.get('web_info', {}):
            web_info = get_http_info(ip, port)
            if web_info:
                if 'web_info' not in probed:
                    probed['web_info'] = {}
                probed['web_info'][port] = web_info

                # Update device type based on web info
                if web_info.get('device_hint') and probed.get('type') == 'unknown':
                    probed['type'] = web_info['device_hint']

                # Use web title as name if we don't have a good one
                if web_info.get('title') and probed.get('name', '').startswith('Device'):
                    probed['name'] = f"{web_info['title']} ({ip})"

    # Infer device type from nmap device type
    if probed.get('nmap_device_type') and (not probed.get('type') or probed.get('type') == 'unknown'):
        nmap_type = probed['nmap_device_type'].lower()
        if 'phone' in nmap_type:
            probed['type'] = 'phone'
        elif 'router' in nmap_type or 'wap' in nmap_type:
            probed['type'] = 'router'
        elif 'printer' in nmap_type:
            probed['type'] = 'printer'
        elif 'camera' in nmap_type or 'webcam' in nmap_type:
            probed['type'] = 'camera'
        elif 'storage' in nmap_type or 'nas' in nmap_type:
            probed['type'] = 'nas'
        elif 'media' in nmap_type:
            probed['type'] = 'media'
        elif 'general purpose' in nmap_type:
            probed['type'] = 'computer'

    # Infer device type from OS
    if probed.get('os') and (not probed.get('type') or probed.get('type') == 'unknown'):
        os_lower = probed['os'].lower()
        if 'windows' in os_lower:
            probed['type'] = 'windows'
        elif 'linux' in os_lower:
            probed['type'] = 'linux'
        elif 'mac os' in os_lower or 'macos' in os_lower or 'darwin' in os_lower:
            probed['type'] = 'mac'
        elif 'ios' in os_lower or 'iphone' in os_lower or 'ipad' in os_lower:
            probed['type'] = 'apple-mobile'
        elif 'android' in os_lower:
            probed['type'] = 'android'
        elif 'freebsd' in os_lower or 'openbsd' in os_lower:
            probed['type'] = 'bsd'

    # Infer device type from vendor
    if probed.get('vendor') and (not probed.get('type') or probed.get('type') == 'unknown'):
        vendor_lower = probed['vendor'].lower()
        if 'apple' in vendor_lower:
            probed['type'] = 'apple'
        elif 'samsung' in vendor_lower:
            probed['type'] = 'samsung'
        elif 'google' in vendor_lower:
            probed['type'] = 'google'
        elif 'amazon' in vendor_lower:
            probed['type'] = 'amazon'
        elif 'tesla' in vendor_lower:
            probed['type'] = 'tesla'
        elif 'roku' in vendor_lower:
            probed['type'] = 'roku'
        elif 'sony' in vendor_lower:
            probed['type'] = 'sony'
        elif 'lg' in vendor_lower:
            probed['type'] = 'lg'
        elif 'raspberry' in vendor_lower:
            probed['type'] = 'raspberry-pi'
        elif 'synology' in vendor_lower:
            probed['type'] = 'synology'
        elif 'hp' in vendor_lower or 'hewlett' in vendor_lower:
            probed['type'] = 'printer'
        elif 'canon' in vendor_lower or 'epson' in vendor_lower or 'brother' in vendor_lower:
            probed['type'] = 'printer'

    # Infer device type from services (if not already identified)
    if not probed.get('type') or probed.get('type') == 'unknown':
        port_set = set(open_ports)

        if 7000 in port_set or 7100 in port_set:
            probed['type'] = 'airplay'
            probed['castable'] = True
        elif 8008 in port_set or 8009 in port_set:
            probed['type'] = 'chromecast'
            probed['castable'] = True
        elif 9197 in port_set or 49152 in port_set:
            probed['type'] = 'dlna'
            probed['castable'] = True
        elif 32400 in port_set:
            probed['type'] = 'plex'
        elif 9100 in port_set or 631 in port_set:
            probed['type'] = 'printer'
        elif 3389 in port_set:
            probed['type'] = 'windows'
        elif 548 in port_set:
            probed['type'] = 'apple'
        elif 445 in port_set and 22 not in port_set:
            probed['type'] = 'windows'
        elif 22 in port_set and 548 not in port_set and 445 not in port_set:
            probed['type'] = 'linux'
        elif 554 in port_set:
            probed['type'] = 'camera'
        elif 1883 in port_set:
            probed['type'] = 'iot-hub'

    # Build a better name if we have more info now
    if probed.get('name', '').startswith('Device') or '(' in probed.get('name', ''):
        name_parts = []
        if probed.get('vendor'):
            name_parts.append(probed['vendor'])
        if probed.get('model'):
            name_parts.append(probed['model'])
        elif probed.get('os'):
            # Shorten OS name
            os_short = probed['os'].split('(')[0].strip()[:30]
            name_parts.append(os_short)

        if name_parts:
            probed['name'] = ' '.join(name_parts)
        elif probed.get('hostname'):
            probed['name'] = probed['hostname'].split('.')[0]

    return probed


def probe_devices_parallel(devices: list, quick: bool = False, use_nmap: bool = True) -> list:
    """Probe multiple devices in parallel using nmap and other tools."""
    import concurrent.futures

    probed_devices = []
    total = len(devices)

    if use_nmap:
        print(f"   🔬 Deep scanning {total} devices with nmap...")
    else:
        print(f"   🔬 Probing {total} devices...")

    # Use fewer workers for nmap to avoid overwhelming the network
    max_workers = 3 if use_nmap else 10
    timeout_per_device = 15 if use_nmap else 5
    total_timeout = max(60, total * timeout_per_device // max_workers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(
            probe_device, dev, quick, use_nmap): dev for dev in devices}

        completed = 0
        try:
            for future in concurrent.futures.as_completed(futures, timeout=total_timeout):
                try:
                    result = future.result(timeout=timeout_per_device)
                    probed_devices.append(result)
                    completed += 1

                    # Show progress with more detail
                    ip = result.get('ip', '?')

                    info_parts = []
                    if result.get('os'):
                        os_short = result['os'].split('(')[0].strip()[:25]
                        info_parts.append(f"OS: {os_short}")
                    if result.get('vendor'):
                        info_parts.append(result['vendor'][:20])
                    if result.get('open_ports'):
                        info_parts.append(f"{len(result['open_ports'])} ports")

                    if info_parts:
                        print(
                            f"   [{completed}/{total}] {ip}: {', '.join(info_parts)}")
                    else:
                        print(f"   [{completed}/{total}] {ip}: scanned")

                except Exception as e:
                    completed += 1
                    # Keep original device info on probe failure
                    dev = futures[future]
                    probed_devices.append(dev)
                    print(
                        f"   [{completed}/{total}] {dev.get('ip', '?')}: error - {str(e)[:30]}")

        except concurrent.futures.TimeoutError:
            print(
                f"   ⚠️  Timeout - {total - completed} devices not fully scanned")
            # Add remaining unprobed devices
            for future, dev in futures.items():
                if not future.done():
                    probed_devices.append(dev)

    return probed_devices


def ping_host(ip: str, timeout: float = 0.3) -> bool:
    """Check if a host is reachable via ping."""
    import platform

    # Platform-specific ping command
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        # macOS uses -W in milliseconds for timeout
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]

    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout + 0.5)
        return result.returncode == 0
    except:
        return False


def get_hostname(ip: str) -> str:
    """Try to resolve hostname for an IP."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        return None


def get_mac_vendor(mac: str) -> str:
    """Get vendor name from MAC address prefix."""
    # Common MAC prefixes (first 3 bytes)
    vendors = {
        "00:1A:79": "Tesla",
        "4C:FC:AA": "Tesla",
        "98:ED:5C": "Tesla",
        "00:17:F2": "Apple",
        "3C:06:30": "Apple",
        "A4:83:E7": "Apple",
        "F0:18:98": "Apple",
        "AC:BC:32": "Apple",
        "14:7D:DA": "Apple",
        "E0:B5:2D": "Apple",
        "F4:5C:89": "Apple",
        "DC:A4:CA": "Apple",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "00:1E:C2": "Apple",
        "B8:17:C2": "Samsung",
        "78:BD:BC": "Samsung",
        "8C:71:F8": "Samsung",
        "FC:F1:36": "Samsung",
        "CC:6E:A4": "Samsung",
        "5C:49:7D": "Samsung",
        "64:1C:AE": "Samsung",
        "AC:5F:3E": "Samsung",
        "E4:92:FB": "Samsung",
        "18:3A:2D": "Samsung",
        "50:01:BB": "Samsung",
        "00:1A:11": "Google",
        "F4:F5:D8": "Google",
        "54:60:09": "Google",
        "94:EB:2C": "Google",
        "44:07:0B": "Google",
        "A4:77:33": "Google",
        "30:FD:38": "Google",
        "F8:0F:F9": "Google",
        "E4:F0:42": "Google",
        "48:D6:D5": "Google",
        "00:09:B0": "Schlage/Allegion",
        "00:50:F2": "Microsoft",
        "00:15:5D": "Microsoft",
        "00:0D:3A": "Microsoft",
        "7C:1E:52": "Microsoft",
        "28:18:78": "Microsoft",
        "60:45:BD": "Microsoft",
        "00:1D:D8": "Microsoft",
        "00:22:48": "Microsoft",
        "B4:2E:99": "Amazon",
        "68:54:FD": "Amazon",
        "A0:02:DC": "Amazon",
        "74:C2:46": "Amazon",
        "44:65:0D": "Amazon",
        "FC:65:DE": "Amazon",
        "68:37:E9": "Amazon",
        "40:B4:CD": "Amazon",
        "00:FC:8B": "Amazon",
        "84:D6:D0": "Amazon",
        "F0:F0:A4": "Amazon",
        "34:D2:70": "Amazon",
        "5C:41:5A": "Amazon",
        "00:04:20": "Roku",
        "B0:A7:37": "Roku",
        "D8:31:34": "Roku",
        "C8:3A:6B": "Roku",
        "B8:3E:59": "Roku",
        "CC:6D:A0": "Roku",
        "00:0E:08": "Sony",
        "FC:0F:E6": "Sony",
        "00:1D:BA": "Sony",
        "40:B8:37": "Sony",
        "70:9E:29": "Sony",
        "AC:9B:0A": "Sony",
        "00:19:C5": "Sony",
        "00:24:BE": "Sony",
        "A8:E3:EE": "Sony",
        "78:84:3C": "Sony",
        "30:52:CB": "Sony",
        "A0:D3:7A": "LG",
        "00:1C:62": "LG",
        "00:1E:75": "LG",
        "10:68:3F": "LG",
        "64:99:5D": "LG",
        "CC:2D:8C": "LG",
        "34:4D:F7": "LG",
        "58:A2:B5": "LG",
        "38:8C:50": "LG",
        "00:AA:70": "LG",
        "50:55:27": "LG",
        "B4:E6:2A": "LG",
        "88:C9:D0": "LG",
        "00:24:E4": "Withings/Nokia",
        "00:1B:63": "HP",
        "3C:D9:2B": "HP",
        "10:1F:74": "HP",
        "94:57:A5": "HP",
        "B0:5A:DA": "HP",
        "E4:11:5B": "HP",
        "80:CE:62": "HP",
        "2C:44:FD": "HP",
        "18:A9:05": "HP",
        "00:26:55": "HP",
        "64:51:06": "HP",
        "EC:B1:D7": "HP",
        "38:63:BB": "HP",
        "00:11:85": "HP",
        "38:22:D6": "HP",
        "A0:D3:C1": "HP",
        "30:E1:71": "HP",
        "28:92:4A": "HP",
        "48:0F:CF": "HP",
        "B4:B5:2F": "HP",
        "E8:F7:24": "HP",
        "C8:CB:B8": "HP",
        "D4:85:64": "HP",
        "00:21:5A": "HP",
        "00:1F:29": "HP",
        "00:60:B0": "HP",
        "00:80:A0": "HP",
        "00:30:C1": "HP",
        "00:17:A4": "HP",
        "00:13:21": "HP",
        "00:1B:78": "HP",
        "00:19:BB": "HP",
        "00:0F:61": "HP",
        "00:0B:CD": "HP",
        "00:0A:57": "HP",
        "00:08:02": "HP",
        "00:04:EA": "HP",
        "00:01:E6": "HP",
        "00:01:E7": "HP",
        "00:00:63": "HP",
        "74:E5:43": "Liteon/Dell",
        "00:21:9B": "Dell",
        "18:03:73": "Dell",
        "B8:CA:3A": "Dell",
        "00:14:22": "Dell",
        "F8:BC:12": "Dell",
        "D4:BE:D9": "Dell",
        "24:B6:FD": "Dell",
        "F8:B1:56": "Dell",
        "34:17:EB": "Dell",
        "B8:2A:72": "Dell",
        "5C:26:0A": "Dell",
        "E4:43:4B": "Dell",
        "00:06:5B": "Dell",
        "00:08:74": "Dell",
        "00:0B:DB": "Dell",
        "00:0D:56": "Dell",
        "00:0F:1F": "Dell",
        "00:11:43": "Dell",
        "00:12:3F": "Dell",
        "00:13:72": "Dell",
        "00:15:C5": "Dell",
        "00:18:8B": "Dell",
        "00:19:B9": "Dell",
        "00:1A:A0": "Dell",
        "00:1C:23": "Dell",
        "00:1D:09": "Dell",
        "00:1E:4F": "Dell",
        "00:1E:C9": "Dell",
        "00:22:19": "Dell",
        "00:23:AE": "Dell",
        "00:24:E8": "Dell",
        "00:25:64": "Dell",
        "00:26:B9": "Dell",
        "14:18:77": "Dell",
        "14:B3:1F": "Dell",
        "14:FE:B5": "Dell",
        "18:66:DA": "Dell",
        "18:A9:9B": "Dell",
        "18:DB:F2": "Dell",
        "1C:40:24": "Dell",
        "20:47:47": "Dell",
        "24:6E:96": "Dell",
        "28:F1:0E": "Dell",
        "34:E6:D7": "Dell",
        "44:A8:42": "Dell",
        "4C:76:25": "Dell",
        "54:9F:35": "Dell",
        "5C:26:0A": "Dell",
        "5C:F9:DD": "Dell",
        "64:00:6A": "Dell",
        "74:86:7A": "Dell",
        "78:2B:CB": "Dell",
        "78:45:C4": "Dell",
        "80:18:44": "Dell",
        "84:2B:2B": "Dell",
        "84:7B:EB": "Dell",
        "84:8F:69": "Dell",
        "88:88:88": "Dell",
        "90:B1:1C": "Dell",
        "98:90:96": "Dell",
        "98:E7:43": "Dell",
        "A4:1F:72": "Dell",
        "A4:BA:DB": "Dell",
        "B0:83:FE": "Dell",
        "B4:E1:0F": "Dell",
        "BC:30:5B": "Dell",
        "C8:1F:66": "Dell",
        "C8:4B:D6": "Dell",
        "D0:67:E5": "Dell",
        "D4:81:D7": "Dell",
        "D4:AE:52": "Dell",
        "E0:DB:55": "Dell",
        "E4:54:E8": "Dell",
        "EC:F4:BB": "Dell",
        "F0:1F:AF": "Dell",
        "F4:8E:38": "Dell",
        "F8:B1:56": "Dell",
        "F8:DB:88": "Dell",
    }

    if not mac:
        return None

    # Normalize MAC format
    mac_prefix = mac.upper().replace("-", ":")[0:8]
    return vendors.get(mac_prefix)


def scan_arp_table() -> list:
    """Get devices from the system ARP table."""
    import platform

    devices = []

    try:
        if platform.system().lower() == "darwin":  # macOS
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5)
        elif platform.system().lower() == "windows":
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5)
        else:  # Linux
            result = subprocess.run(
                ["arp", "-n"], capture_output=True, text=True, timeout=5)

        if result.returncode == 0:
            import re
            # Parse ARP output - format varies by OS
            for line in result.stdout.split('\n'):
                # macOS/BSD format: hostname (ip) at mac on interface
                # Linux format: ip hwtype mac flags interface
                # Windows format: ip mac type

                # Try to extract IP and MAC
                ip_match = re.search(
                    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                mac_match = re.search(
                    r'([0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2})', line)

                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(1).upper().replace("-", ":")

                    # Skip incomplete entries
                    if "(incomplete)" in line.lower() or mac == "FF:FF:FF:FF:FF:FF":
                        continue

                    devices.append({'ip': ip, 'mac': mac})
    except Exception as e:
        pass

    return devices


def discover_network_hosts(timeout: int = 10) -> list:
    """Discover all hosts on the local network via ARP + ping sweep."""
    import concurrent.futures

    devices = []
    seen_ips = set()

    print("   📋 Checking ARP table...")

    # First, get devices from ARP table (instant)
    arp_devices = scan_arp_table()

    for dev in arp_devices:
        ip = dev['ip']
        if ip not in seen_ips:
            seen_ips.add(ip)

            # Try to get hostname
            hostname = get_hostname(ip)

            # Try to identify vendor from MAC
            vendor = get_mac_vendor(dev.get('mac', ''))

            # Build device name
            if hostname:
                name = hostname.split('.')[0]  # Remove domain
            elif vendor:
                name = f"{vendor} Device"
            else:
                name = f"Device"

            # Determine device type from vendor/hostname
            device_type = "unknown"
            if vendor:
                vendor_lower = vendor.lower()
                if "tesla" in vendor_lower:
                    device_type = "tesla"
                elif "apple" in vendor_lower:
                    device_type = "apple"
                elif "samsung" in vendor_lower:
                    device_type = "samsung"
                elif "google" in vendor_lower:
                    device_type = "google"
                elif "amazon" in vendor_lower:
                    device_type = "amazon"
                elif "roku" in vendor_lower:
                    device_type = "roku"
                elif "sony" in vendor_lower:
                    device_type = "sony"
                elif "lg" in vendor_lower:
                    device_type = "lg"
                elif "hp" in vendor_lower:
                    device_type = "printer"
                elif "raspberry" in vendor_lower:
                    device_type = "raspberry-pi"
                elif "dell" in vendor_lower or "microsoft" in vendor_lower:
                    device_type = "computer"

            if hostname:
                hostname_lower = hostname.lower()
                if "iphone" in hostname_lower or "ipad" in hostname_lower:
                    device_type = "apple-mobile"
                elif "macbook" in hostname_lower or "imac" in hostname_lower or "mac-" in hostname_lower:
                    device_type = "apple"
                elif "android" in hostname_lower or "galaxy" in hostname_lower or "pixel" in hostname_lower:
                    device_type = "android"
                elif "tesla" in hostname_lower or "tmc" in hostname_lower or "wall-connector" in hostname_lower:
                    device_type = "tesla"

            devices.append({
                'name': f"{name} ({ip})",
                'ip': ip,
                'mac': dev.get('mac'),
                'type': device_type,
                'vendor': vendor,
                'hostname': hostname,
                'castable': False,
            })

    # Ping sweep to find more devices (in parallel)
    subnet = get_local_subnet()
    my_ip = get_local_ip()

    print(f"   🔍 Ping sweep on {subnet}.0/24...")

    ips_to_scan = [f"{subnet}.{i}" for i in range(
        1, 255) if f"{subnet}.{i}" not in seen_ips and f"{subnet}.{i}" != my_ip]

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
                        name = hostname.split(
                            '.')[0] if hostname else f"Device"

                        device_type = "unknown"
                        if hostname:
                            hostname_lower = hostname.lower()
                            if "iphone" in hostname_lower or "ipad" in hostname_lower:
                                device_type = "apple-mobile"
                            elif "macbook" in hostname_lower or "imac" in hostname_lower:
                                device_type = "apple"
                            elif "android" in hostname_lower or "galaxy" in hostname_lower:
                                device_type = "android"
                            elif "tesla" in hostname_lower:
                                device_type = "tesla"

                        devices.append({
                            'name': f"{name} ({ip})",
                            'ip': ip,
                            'type': device_type,
                            'hostname': hostname,
                            'castable': False,
                        })
                except:
                    pass
        except concurrent.futures.TimeoutError:
            # Some pings didn't complete in time - that's OK
            pass

        # Cancel any remaining futures
        for future in futures:
            future.cancel()

    return devices


async def discover_all_devices(timeout: int = 8) -> list:
    """Discover all devices on the network (ARP, ping, mDNS, DLNA, UPnP)."""
    import concurrent.futures

    print(f"🔍 Scanning network for all devices...")
    print()

    all_devices = []
    seen_ips = set()

    # Run all discovery methods concurrently
    loop = asyncio.get_event_loop()

    mdns_devices = []
    network_devices = []
    dlna_devices = []

    with concurrent.futures.ThreadPoolExecutor() as pool:
        # Run blocking scans in threads
        mdns_future = loop.run_in_executor(pool, discover_mdns_devices, 3)
        network_future = loop.run_in_executor(pool, discover_network_hosts, 6)

        # Run DLNA discovery (async)
        try:
            dlna_devices = await asyncio.wait_for(discover_dlna_devices(3), timeout=5)
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

        # Get results from threads with timeout
        try:
            mdns_devices = await asyncio.wait_for(mdns_future, timeout=5)
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

        try:
            network_devices = await asyncio.wait_for(network_future, timeout=10)
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

    # Merge results - priority: DLNA > mDNS > network hosts
    # This ensures we keep the best info about each device

    # First add DLNA devices (they're castable)
    for dev in dlna_devices:
        ip = dev.get('ip')
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            all_devices.append(dev)

    # Add mDNS devices (may be castable, have good names)
    for dev in mdns_devices:
        ip = dev.get('ip')
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            all_devices.append(dev)
        elif ip in seen_ips:
            # Update existing device with mDNS info if better
            for existing in all_devices:
                if existing.get('ip') == ip:
                    if dev.get('castable') and not existing.get('castable'):
                        existing['castable'] = True
                    if not existing.get('service') and dev.get('service'):
                        existing['service'] = dev.get('service')
                    break

    # Add network hosts that weren't found by other methods
    for dev in network_devices:
        ip = dev.get('ip')
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            all_devices.append(dev)
        elif ip in seen_ips:
            # Update existing device with MAC/vendor info if available
            for existing in all_devices:
                if existing.get('ip') == ip:
                    if dev.get('mac') and not existing.get('mac'):
                        existing['mac'] = dev.get('mac')
                    if dev.get('vendor') and not existing.get('vendor'):
                        existing['vendor'] = dev.get('vendor')
                    break

    # Filter out multicast/broadcast addresses
    all_devices = [d for d in all_devices if not d.get(
        'ip', '').startswith(('224.', '239.', '255.'))]

    # Probe all devices for more details using nmap
    if all_devices:
        print()
        all_devices = probe_devices_parallel(
            all_devices, quick=False, use_nmap=True)

    # Sort: castable first, then by name
    all_devices.sort(key=lambda x: (
        not x.get('castable', False), x.get('name', '').lower()))

    print(f"\n   ✅ Found {len(all_devices)} device(s)")

    return all_devices


async def discover_devices(timeout: int = 5) -> list:
    """Discover DLNA Media Renderer devices only (for casting)."""
    print(f"🔍 Scanning for cast-capable devices ({timeout}s)...")
    return await discover_dlna_devices(timeout)


async def select_device() -> bool:
    """Let user select a device from discovered ones."""
    global CURRENT_DEVICE

    print("=" * 60)
    print("📺 Device Selection")
    print("=" * 60)
    print()

    devices = await discover_devices()

    # Save discovered devices for future use
    if devices:
        save_discovered_devices(devices)

    if not devices:
        print("\n❌ No DLNA devices found on the network")
        print("   Make sure your TV is on and connected to the same network")
        return False

    print(f"\n📡 Found {len(devices)} device(s):\n")
    for i, dev in enumerate(devices, 1):
        current = " ← current" if CURRENT_DEVICE and CURRENT_DEVICE.get(
            'ip') == dev['ip'] else ""
        print(f"   {i}. {dev['name']} ({dev['ip']}){current}")

    print(f"\n   0. Cancel")
    print()

    while True:
        try:
            choice = input(f"Select device (1-{len(devices)}): ").strip()

            if choice == '0' or choice.lower() == 'q':
                return False

            idx = int(choice) - 1
            if 0 <= idx < len(devices):
                CURRENT_DEVICE = devices[idx]
                save_config()
                print(f"\n✅ Selected: {CURRENT_DEVICE['name']}")
                return True
            else:
                print(f"   Please enter 1-{len(devices)} or 0 to cancel")
        except ValueError:
            print("   Please enter a number")
        except KeyboardInterrupt:
            print()
            return False


def get_device_icon(device: dict) -> str:
    """Get an icon for a device based on its type."""
    device_type = device.get('type', 'unknown')
    icons = {
        'dlna': '📺',
        'airplay': '🍎',
        'chromecast': '📺',
        'spotify': '🎵',
        'homekit': '🏠',
        'apple': '🍎',
        'apple-mobile': '📱',
        'apple-tv': '📺',
        'homepod': '🔊',
        'mac': '💻',
        'airport': '📡',
        'android': '🤖',
        'phone': '📱',
        'samsung': '📱',
        'google': '🔍',
        'amazon': '📦',
        'roku': '📺',
        'sony': '📺',
        'lg': '📺',
        'tesla': '⚡',
        'raspberry-pi': '🍓',
        'file-share': '📁',
        'printer': '🖨️',
        'computer': '💻',
        'windows': '🪟',
        'linux': '🐧',
        'bsd': '😈',
        'nas': '💾',
        'synology': '💾',
        'plex': '🎬',
        'media': '🎬',
        'camera': '📷',
        'router': '📡',
        'iot-hub': '🔌',
        'web': '🌐',
        'unknown': '❓',
    }
    return icons.get(device_type, '📱')


def show_device_details(device: dict):
    """Display detailed information about a device."""
    print()
    print("=" * 60)
    print(f"📋 Device Details: {device.get('name', 'Unknown')}")
    print("=" * 60)

    icon = get_device_icon(device)

    print(f"\n   {icon} Name: {device.get('name', 'Unknown')}")
    print(f"   🌐 IP Address: {device.get('ip', 'Unknown')}")

    if device.get('mac'):
        print(f"   🔗 MAC Address: {device.get('mac')}")

    if device.get('vendor'):
        print(f"   �icing Vendor: {device.get('vendor')}")

    if device.get('hostname'):
        print(f"   🏷️  Hostname: {device.get('hostname')}")

    print(f"   📂 Type: {device.get('type', 'unknown')}")
    print(f"   📺 Castable: {'Yes' if device.get('castable') else 'No'}")

    # Model info
    if device.get('model'):
        print(f"   📱 Model: {device.get('model')}")

    # OS info
    if device.get('os'):
        os_str = device.get('os')
        if device.get('os_version'):
            os_str += f" {device.get('os_version')}"
        print(f"   💿 OS: {os_str}")

    # Apple-specific info
    if device.get('apple_info'):
        apple = device['apple_info']
        print(f"\n   🍎 Apple Device Details:")

        if apple.get('model_str'):
            print(f"      • Model: {apple['model_str']}")
        if apple.get('raw_model'):
            print(f"      • Model ID: {apple['raw_model']}")
        if apple.get('os'):
            os_str = apple['os']
            if apple.get('version'):
                os_str += f" {apple['version']}"
            if apple.get('build'):
                os_str += f" ({apple['build']})"
            print(f"      • OS: {os_str}")
        if apple.get('identifier'):
            print(f"      • Identifier: {apple['identifier']}")

        # Protocols/services
        if apple.get('protocols'):
            print(f"\n      Supported Protocols:")
            for proto in apple['protocols']:
                proto_name = proto.get('protocol', 'Unknown')
                port = proto.get('port', '?')
                print(f"         • {proto_name} (port {port})")

                # Show interesting properties
                props = proto.get('properties', {})
                if props:
                    for key in ['am', 'model', 'manufacturer', 'serialNumber', 'deviceid', 'features']:
                        if key in props:
                            val = props[key]
                            if isinstance(val, bytes):
                                val = val.decode('utf-8', errors='ignore')
                            print(f"           {key}: {val}")

    # OS info from nmap
    if device.get('os') and not device.get('apple_info'):
        os_str = device.get('os')
        if device.get('os_accuracy'):
            os_str += f" ({device['os_accuracy']}% confidence)"
        print(f"\n   💿 Operating System: {os_str}")

    if device.get('nmap_device_type'):
        print(f"   🔍 Device Class: {device['nmap_device_type']}")

    if device.get('uptime'):
        print(f"   ⏰ Last Boot: {device['uptime']}")

    # Open ports with service details
    if device.get('services'):
        print(f"\n   🔓 Open Ports & Services:")
        for svc in device['services']:
            port = svc.get('port', '?')
            name = svc.get('name', 'unknown')
            print(f"      • {port}: {name}")
    elif device.get('open_ports'):
        print(f"\n   🔓 Open Ports ({len(device['open_ports'])}):")
        for port in device['open_ports']:
            service_info = COMMON_PORTS.get(
                port, ('unknown', 'Unknown Service'))
            print(f"      • {port}: {service_info[1]}")

    # Web info
    if device.get('web_info'):
        print(f"\n   🌐 Web Interfaces:")
        for port, info in device['web_info'].items():
            title = info.get('title', 'No title')
            server = info.get('server', '')
            print(f"      • Port {port}: {title}")
            if server:
                print(f"        Server: {server}")

    # Location (for DLNA)
    if device.get('location'):
        print(f"\n   📍 DLNA Location: {device.get('location')}")

    # Show any nmap info/errors
    if device.get('nmap_info'):
        nmap_info = device['nmap_info']
        if nmap_info.get('error'):
            print(f"\n   ⚠️  Nmap Error: {nmap_info['error']}")
        if nmap_info.get('scripts'):
            print(f"\n   📜 Nmap Scripts:")
            for script_id, output in nmap_info['scripts'].items():
                print(f"      • {script_id}: {output[:100]}...")

    if device.get('nmap_error'):
        print(f"\n   ⚠️  Nmap Error: {device['nmap_error']}")

    print()
    input("   Press Enter to continue...")


async def device_menu() -> str:
    """Show device management menu with previously found devices and scan option."""
    global CURRENT_DEVICE

    while True:
        print("=" * 60)
        print("📡 Network Devices")
        print("=" * 60)

        # Show current cast device
        if CURRENT_DEVICE:
            print(
                f"\n   ✅ Cast Device: {CURRENT_DEVICE['name']} ({CURRENT_DEVICE.get('ip', 'unknown')})")
        else:
            print(f"\n   ⚠️  No cast device selected")

        # Show previously discovered devices
        if DISCOVERED_DEVICES:
            # Separate castable and non-castable devices
            castable = [d for d in DISCOVERED_DEVICES if d.get(
                'castable', False)]
            other = [d for d in DISCOVERED_DEVICES if not d.get(
                'castable', False)]

            if castable:
                print(f"\n📺 Cast-capable Devices:\n")
                for i, dev in enumerate(castable, 1):
                    is_current = CURRENT_DEVICE and CURRENT_DEVICE.get(
                        'ip') == dev.get('ip')
                    marker = " ← selected" if is_current else ""
                    icon = get_device_icon(dev)

                    # Show services if available
                    services_str = ""
                    if dev.get('open_ports'):
                        ports = dev['open_ports'][:4]
                        services_str = f" [ports: {', '.join(str(p) for p in ports)}]"

                    print(
                        f"   {i}. {icon} {dev.get('name', 'Unknown')}{marker}{services_str}")

            if other:
                start_idx = len(castable) + 1
                print(f"\n📱 Other Network Devices:\n")
                for i, dev in enumerate(other, start_idx):
                    icon = get_device_icon(dev)
                    dev_type = dev.get('type', 'unknown')

                    # Show additional info
                    extra_info = []
                    if dev.get('vendor'):
                        extra_info.append(dev['vendor'])
                    elif dev_type != 'unknown':
                        extra_info.append(dev_type)

                    if dev.get('open_ports'):
                        ports = dev['open_ports'][:3]
                        extra_info.append(
                            f"ports: {', '.join(str(p) for p in ports)}")

                    extra_str = f" [{', '.join(extra_info)}]" if extra_info else ""
                    print(
                        f"   {i}. {icon} {dev.get('name', 'Unknown')}{extra_str}")
        else:
            print(f"\n   (no devices discovered yet - try scanning)")

        print(f"\n   s. 🔍 Scan network for ALL devices")
        print(f"   t. 📺 Scan for TVs only (cast-capable)")
        if DISCOVERED_DEVICES:
            print(f"   d#. 🔬 Deep scan device (e.g. d1, d2)")
            print(f"   v#. 📋 View device details (e.g. v1, v2)")
        if CURRENT_DEVICE:
            print(f"   f. 🔌 Forget cast device")
        if DISCOVERED_DEVICES:
            print(f"   c. 🗑️  Clear all saved devices")
        print(f"   b. ← Back to main menu")
        print()

        # Only castable devices can be selected for casting
        castable_devices = [
            d for d in DISCOVERED_DEVICES if d.get('castable', False)]
        max_choice = len(DISCOVERED_DEVICES)

        try:
            if max_choice > 0:
                choice = input(
                    f"Select device (1-{max_choice}) or option: ").strip().lower()
            else:
                choice = input("Enter option (s/t/b): ").strip().lower()

            if choice == 'b' or choice == 'q':
                return 'BACK'

            if choice == 's':
                # Full network scan
                print()
                devices = await discover_all_devices(timeout=5)
                if devices:
                    save_discovered_devices(devices)
                    print(f"\n✅ Found {len(devices)} device(s)")
                else:
                    print("\n❌ No devices found on the network")
                print()
                continue

            if choice == 't':
                # TV-only scan
                print()
                await select_device()
                print()
                continue

            if choice == 'f' and CURRENT_DEVICE:
                forget_device()
                print()
                continue

            if choice == 'c' and DISCOVERED_DEVICES:
                DISCOVERED_DEVICES.clear()
                CURRENT_DEVICE = None
                save_config()
                print("🗑️  Cleared all saved devices")
                print()
                continue

            # Handle "v1", "v2", etc. for viewing details
            if choice.startswith('v') and len(choice) > 1:
                try:
                    idx = int(choice[1:]) - 1
                    if 0 <= idx < len(DISCOVERED_DEVICES):
                        show_device_details(DISCOVERED_DEVICES[idx])
                        continue
                except:
                    pass

            # Handle "d1", "d2", etc. for deep scanning
            if choice.startswith('d') and len(choice) > 1:
                try:
                    idx = int(choice[1:]) - 1
                    if 0 <= idx < len(DISCOVERED_DEVICES):
                        device = DISCOVERED_DEVICES[idx]
                        ip = device.get('ip')
                        print(f"\n🔬 Deep scanning {ip}...")
                        print("   (This may take 30-60 seconds)")

                        # Run aggressive nmap scan
                        probed = probe_device(
                            device, quick=False, use_nmap=True)

                        # Also try OS detection scan
                        print("   Running OS detection...")
                        os_result = nmap_scan(ip, "os")
                        if os_result.get('os'):
                            probed['os'] = os_result['os']
                            probed['os_accuracy'] = os_result.get(
                                'os_accuracy')
                        if os_result.get('device_type'):
                            probed['nmap_device_type'] = os_result['device_type']
                        if os_result.get('vendor') and not probed.get('vendor'):
                            probed['vendor'] = os_result['vendor']
                        if os_result.get('mac') and not probed.get('mac'):
                            probed['mac'] = os_result['mac']

                        # Update the device in our list
                        DISCOVERED_DEVICES[idx] = probed
                        save_config()

                        print(f"\n✅ Deep scan complete!")
                        show_device_details(probed)
                        continue
                except Exception as e:
                    print(f"   ❌ Error: {e}")
                    continue

            if max_choice > 0:
                idx = int(choice) - 1
                if 0 <= idx < len(DISCOVERED_DEVICES):
                    selected = DISCOVERED_DEVICES[idx]

                    if selected.get('castable', False):
                        CURRENT_DEVICE = selected
                        save_config()
                        print(
                            f"\n✅ Selected for casting: {CURRENT_DEVICE['name']}")
                    else:
                        # Show details for non-castable devices
                        show_device_details(selected)
                    print()
                    continue
                else:
                    print(f"   Please enter 1-{max_choice} or a menu option")
            else:
                print("   Please enter a valid option")

        except ValueError:
            print("   Please enter a valid option")
        except KeyboardInterrupt:
            print()
            return 'BACK'


def get_local_ip():
    """Get local IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def is_youtube_url(url: str) -> bool:
    """Check if URL is a YouTube video."""
    youtube_patterns = [
        "youtube.com/watch",
        "youtu.be/",
        "youtube.com/shorts",
        "youtube.com/live",
    ]
    return any(p in url.lower() for p in youtube_patterns)


def download_youtube(url: str) -> str:
    """Download YouTube video and return local path."""
    import yt_dlp
    import json as json_module

    os.makedirs(YOUTUBE_CACHE_DIR, exist_ok=True)

    print(f"📺 Fetching YouTube video info...")

    # First get video info
    with yt_dlp.YoutubeDL({'quiet': True, 'no_warnings': True}) as ydl:
        try:
            info = ydl.extract_info(url, download=False)
            video_id = info.get('id', 'video')
            title = info.get('title', 'Unknown')
            duration = info.get('duration', 0)

            print(f"   Title: {title}")
            if duration:
                mins, secs = divmod(duration, 60)
                print(f"   Duration: {int(mins)}:{int(secs):02d}")

            # Save info for later display
            info_path = os.path.join(
                YOUTUBE_CACHE_DIR, f"{video_id}.info.json")
            with open(info_path, 'w') as f:
                json_module.dump(
                    {'id': video_id, 'title': title, 'duration': duration}, f)

        except Exception as e:
            print(f"❌ Failed to get video info: {e}")
            return None

    # Check if already downloaded
    output_path = os.path.join(YOUTUBE_CACHE_DIR, f"{video_id}.mp4")
    if os.path.exists(output_path):
        print(f"⚡ Using cached download")
        return output_path

    print(f"⬇️  Downloading (best quality up to 1080p)...")

    # Download with progress
    def progress_hook(d):
        if d['status'] == 'downloading':
            percent = d.get('_percent_str', '?%').strip()
            speed = d.get('_speed_str', '?').strip()
            print(f"\r   {percent} at {speed}    ", end="", flush=True)
        elif d['status'] == 'finished':
            print(f"\r   ✅ Download complete!          ")

    ydl_opts = {
        'format': 'bestvideo[height<=1080][ext=mp4]+bestaudio[ext=m4a]/best[height<=1080][ext=mp4]/best',
        'outtmpl': output_path,
        'progress_hooks': [progress_hook],
        'quiet': True,
        'no_warnings': True,
        'merge_output_format': 'mp4',
    }

    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([url])
        return output_path
    except Exception as e:
        print(f"\n❌ Download failed: {e}")
        return None


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler that logs requests."""

    def log_message(self, format, *args):
        print(f"   📥 TV: {args[0]}")

    def end_headers(self):
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()


def get_cache_dir(video_path: str) -> str:
    """Get cache directory for a video file."""
    # Create a unique cache folder based on video filename and modification time
    video_name = os.path.basename(video_path)
    video_mtime = os.path.getmtime(video_path)
    video_size = os.path.getsize(video_path)

    # Create cache key from name, size, and mtime
    cache_key = f"{video_name}_{video_size}_{int(video_mtime)}"
    # Make it filesystem safe
    cache_key = "".join(
        c if c.isalnum() or c in "._-" else "_" for c in cache_key)

    return os.path.join(HLS_CACHE_DIR, cache_key)


def is_cached(video_path: str) -> tuple:
    """Check if video is already converted. Returns (is_cached, cache_dir)."""
    cache_dir = get_cache_dir(video_path)
    playlist_path = os.path.join(cache_dir, "playlist.m3u8")

    if os.path.exists(playlist_path):
        # Verify cache has segments
        segments = [f for f in os.listdir(cache_dir) if f.endswith('.ts')]
        if segments:
            return True, cache_dir

    return False, cache_dir


def check_video_codec(input_file: str) -> tuple:
    """Check if video is H.264 and get duration."""
    probe_cmd = [
        "ffprobe", "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "stream=codec_name:format=duration",
        "-of", "json",
        input_file
    ]
    result = subprocess.run(probe_cmd, capture_output=True, text=True)

    try:
        import json
        data = json.loads(result.stdout)
        codec = data.get("streams", [{}])[0].get("codec_name", "")
        duration = float(data.get("format", {}).get("duration", 0))
        return codec, duration
    except:
        return "", 0


def convert_to_hls(input_file: str, output_dir: str) -> str:
    """Convert video to HLS format for Samsung TV compatibility."""

    # Check cache first
    cached, cache_dir = is_cached(input_file)

    if cached:
        print(f"⚡ Using cached HLS conversion")
        return os.path.join(cache_dir, "playlist.m3u8")

    # Check source codec
    codec, duration = check_video_codec(input_file)
    can_copy = codec in ("h264", "hevc", "h265")

    # Need to convert - use cache directory
    os.makedirs(cache_dir, exist_ok=True)
    playlist_path = os.path.join(cache_dir, "playlist.m3u8")

    if can_copy:
        print(f"🚀 Fast remux to HLS (video is already {codec})...")
        cmd = [
            "ffmpeg", "-y",
            "-i", input_file,
            "-c:v", "copy",  # No re-encoding!
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
            "-preset", "ultrafast",  # Fastest encoding
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

    # Run with real-time progress output
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    # Parse progress output
    last_percent = -1

    try:
        for line in process.stdout:
            line = line.strip()

            # Parse time progress
            if line.startswith("out_time="):
                try:
                    time_str = line.split("=")[1]
                    # Parse HH:MM:SS.mmm format
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
                except:
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


async def get_av_transport():
    """Connect to selected device and get AVTransport service."""
    global CURRENT_DEVICE

    if not CURRENT_DEVICE:
        print("❌ No device selected. Use 'd' to select a device.")
        return None, None

    ip = CURRENT_DEVICE['ip']
    device_name = CURRENT_DEVICE.get('name', ip)

    # First, check if device is reachable at all
    print(f"   Checking if {ip} is reachable...")

    # Quick ping check via port
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

        # Scan for alternative TVs
        switched = await _scan_and_offer_alternatives(ip, device_name)
        if switched:
            # Retry with the new device
            print(f"\n📺 Connecting to new device...")
            return await get_av_transport()
        return None, None

    requester = AiohttpRequester()
    factory = UpnpFactory(requester)

    # Build list of locations to try
    locations_to_try = []

    # Try the saved location first
    saved_location = CURRENT_DEVICE.get('location')
    if saved_location:
        locations_to_try.append(saved_location)

    # Common Samsung TV DLNA endpoints
    port = CURRENT_DEVICE.get('port', 9197)
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
                    # Update saved location if we found a working one
                    if location != saved_location:
                        CURRENT_DEVICE['location'] = location
                        save_config()
                    return service, device.friendly_name

        except asyncio.TimeoutError:
            last_error = f"Connection timed out ({location})"
            continue
        except Exception as e:
            last_error = str(e)
            continue

    # All locations failed - try to find alternatives
    print(f"\n⚠️  Could not connect to DLNA service on {device_name}")
    print("   Possible causes:")
    print("   • TV's DLNA/media sharing is disabled")
    print("   • TV needs to accept connection (check for popup on TV)")
    print("   • TV firmware may need updating")
    if last_error:
        print(f"\n   Last error: {last_error[:100]}")

    # Scan for alternative TVs
    switched = await _scan_and_offer_alternatives(ip, device_name)
    if switched:
        # Retry with the new device
        print(f"\n📺 Connecting to new device...")
        return await get_av_transport()

    return None, None


async def _scan_and_offer_alternatives(failed_ip: str, failed_name: str) -> bool:
    """Scan for alternative DLNA devices and offer to switch.

    Returns True if user switched to a new device, False otherwise.
    """
    global CURRENT_DEVICE

    print(f"\n🔍 Scanning for other TVs on the network...")

    try:
        # Quick DLNA scan
        alternative_devices = await discover_dlna_devices(timeout=4)

        # Filter out the failed device
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

        # Ask user if they want to switch
        try:
            choice = input(
                f"Switch to a different TV? (1-{len(alternatives)}, or 0 to cancel): ").strip()

            if choice == '0' or choice.lower() in ('', 'n', 'no', 'q'):
                print("   Keeping current device selection.")
                return False

            idx = int(choice) - 1
            if 0 <= idx < len(alternatives):
                selected = alternatives[idx]
                CURRENT_DEVICE = selected
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


async def stop_playback():
    """Stop current playback on TV."""
    if not CURRENT_DEVICE:
        print("❌ No device selected")
        return

    print(f"📺 Connecting to {CURRENT_DEVICE['name']}...")

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


async def cast_video(video_path: str, duration: int = 0):
    """Cast video to Samsung TV."""
    print("=" * 60)
    print("📺 Samsung TV Video Caster")
    print("=" * 60)

    # Check if it's a YouTube URL
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

    # Convert to HLS (uses cache if available)
    playlist_path = convert_to_hls(video_path, None)
    if not playlist_path:
        return False

    # Get the cache directory where HLS files are stored
    cache_dir = os.path.dirname(playlist_path)

    # Start HTTP server from the cache directory
    local_ip = get_local_ip()
    original_dir = os.getcwd()
    os.chdir(cache_dir)

    server = http.server.HTTPServer((local_ip, HTTP_PORT), QuietHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    # HLS URL
    hls_url = f"http://{local_ip}:{HTTP_PORT}/playlist.m3u8"
    print(f"\n🌐 Stream URL: {hls_url}")

    try:
        # Connect to TV
        device_name = CURRENT_DEVICE['name'] if CURRENT_DEVICE else "device"
        print(f"\n📺 Connecting to {device_name}...")
        av_transport, tv_name = await get_av_transport()

        if not av_transport:
            print("❌ Could not connect to TV")
            return False

        print(f"   ✅ Connected: {tv_name}")

        # DLNA metadata
        didl = f'''<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" 
                    xmlns:dc="http://purl.org/dc/elements/1.1/" 
                    xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/">
            <item id="0" parentID="-1" restricted="1">
                <dc:title>{video_name}</dc:title>
                <upnp:class>object.item.videoItem</upnp:class>
                <res protocolInfo="http-get:*:application/vnd.apple.mpegurl:*">{hls_url}</res>
            </item>
        </DIDL-Lite>'''

        # Stop any current playback first
        try:
            stop = av_transport.action('Stop')
            await stop.async_call(InstanceID=0)
        except:
            pass  # Ignore if nothing playing

        # Set URI
        print("\n🎬 Loading video...")
        set_uri = av_transport.action('SetAVTransportURI')
        await set_uri.async_call(InstanceID=0, CurrentURI=hls_url, CurrentURIMetaData=didl)

        # Small delay for TV to process
        await asyncio.sleep(0.5)

        # Play
        print("▶️  Starting playback...")
        play = av_transport.action('Play')
        await play.async_call(InstanceID=0, Speed='1')

        print("\n" + "=" * 60)
        print("🎉 NOW PLAYING ON YOUR TV!")
        print("=" * 60)

        # Wait
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

        # Stop
        print("\n⏹️  Stopping playback...")
        stop = av_transport.action('Stop')
        await stop.async_call(InstanceID=0)
        print("   ✅ Stopped")

        return True

    except KeyboardInterrupt:
        # Handle Ctrl+C during connection/setup phase
        print("\n⏹️  Stopping playback...")
        try:
            av_transport, _ = await get_av_transport()
            stop = av_transport.action('Stop')
            await stop.async_call(InstanceID=0)
            print("   ✅ Stopped")
        except:
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
        # Cache is preserved for future use


def find_video_files(directory: str = ".") -> list:
    """Find all video files in directory."""
    video_extensions = {'.mp4', '.mkv', '.avi',
                        '.mov', '.wmv', '.flv', '.webm', '.m4v', '.ts'}
    videos = []

    for file in os.listdir(directory):
        if os.path.isfile(file):
            _, ext = os.path.splitext(file.lower())
            if ext in video_extensions:
                size = os.path.getsize(file)
                file_path = os.path.abspath(file)
                cached, _ = is_cached(file_path)
                videos.append((file, size, cached))

    # Sort by name
    videos.sort(key=lambda x: x[0].lower())
    return videos


def find_image_files(directory: str = ".") -> list:
    """Find all image files in directory."""
    image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
    images = []

    for file in os.listdir(directory):
        if os.path.isfile(file):
            _, ext = os.path.splitext(file.lower())
            if ext in image_extensions:
                size = os.path.getsize(file)
                images.append((file, size))

    # Sort by name
    images.sort(key=lambda x: x[0].lower())
    return images


SAMPLE_YOUTUBE_URL = "https://youtube.com/watch?v=yvsoeyqCIU8"
SAMPLE_YOUTUBE_TITLE = "Sample: Mo Holiday - Nov 27th 2017"


def select_youtube_submenu() -> str:
    """Show YouTube selection submenu with sample option."""
    print()
    print("   " + "-" * 40)
    print("   📺 YouTube")
    print("   " + "-" * 40)

    print(f"\n   1. {SAMPLE_YOUTUBE_TITLE}")
    print(f"\n   p. Enter a custom URL")
    print(f"   b. Back")
    print()

    while True:
        try:
            choice = input("   Select (1, p, or b): ").strip().lower()

            if choice == 'b':
                return None

            if choice == '1':
                return SAMPLE_YOUTUBE_URL

            if choice == 'p':
                url = input("   Enter YouTube URL: ").strip()
                if url and is_youtube_url(url):
                    return url
                else:
                    print("   ❌ Invalid YouTube URL")
                    continue

            print("   Please enter 1, p, or b")

        except ValueError:
            print("   Please enter a valid option")
        except KeyboardInterrupt:
            print()
            return None


def select_image_submenu() -> str:
    """Show image selection submenu - pick from directory or enter path."""
    print()
    print("   " + "-" * 40)
    print("   🖼️  Select Image")
    print("   " + "-" * 40)

    # Find images in current directory
    images = find_image_files()

    if images:
        print()
        for i, (name, size) in enumerate(images, 1):
            print(f"   {i}. {name} ({format_size(size)})")
    else:
        print("\n   (no images in current directory)")

    print(f"\n   p. Enter a custom path")
    print(f"   b. Back")
    print()

    while True:
        try:
            if images:
                choice = input(
                    f"   Select (1-{len(images)}, p, or b): ").strip().lower()
            else:
                choice = input("   Select (p or b): ").strip().lower()

            if choice == 'b':
                return None

            if choice == 'p':
                path = input("   Enter image path: ").strip()
                if path and os.path.exists(path):
                    _, ext = os.path.splitext(path.lower())
                    if ext in {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}:
                        return f"IMAGE:{path}"
                    else:
                        print("   ❌ Not a supported image format")
                        continue
                else:
                    print("   ❌ File not found")
                    continue

            if images:
                idx = int(choice) - 1
                if 0 <= idx < len(images):
                    return f"IMAGE:{images[idx][0]}"
                else:
                    print(f"   Please enter 1-{len(images)}, p, or b")
            else:
                print("   Please enter p or b")

        except ValueError:
            print("   Please enter a valid option")
        except KeyboardInterrupt:
            print()
            return None


def image_to_video(image_path: str, duration: int = 10) -> str:
    """Convert an image to a video file for streaming."""
    import json as json_module

    image_path = os.path.abspath(image_path)
    image_name = os.path.basename(image_path)

    # Create cache directory for image videos
    image_video_cache = os.path.join(CONFIG_DIR, "image_videos")
    os.makedirs(image_video_cache, exist_ok=True)

    # Create unique output name based on image
    image_mtime = os.path.getmtime(image_path)
    image_size = os.path.getsize(image_path)
    cache_key = f"{image_name}_{image_size}_{int(image_mtime)}_{duration}s"
    cache_key = "".join(
        c if c.isalnum() or c in "._-" else "_" for c in cache_key)
    output_path = os.path.join(image_video_cache, f"{cache_key}.mp4")

    # Check if already converted
    if os.path.exists(output_path):
        print(f"⚡ Using cached image video")
        return output_path

    print(f"🖼️  Converting image to {duration}s video...")

    # Use ffmpeg to create video from image
    # -loop 1: loop the image
    # -t: duration
    # -vf scale: scale to fill 1920x1080 (crops edges if needed to fill screen)
    # -pix_fmt yuv420p: compatible pixel format
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


def find_cached_youtube_videos() -> list:
    """Find all cached YouTube videos with their titles."""
    if not os.path.exists(YOUTUBE_CACHE_DIR):
        return []

    videos = []
    for file in os.listdir(YOUTUBE_CACHE_DIR):
        if file.endswith('.mp4'):
            file_path = os.path.join(YOUTUBE_CACHE_DIR, file)
            size = os.path.getsize(file_path)
            video_id = file.replace('.mp4', '')

            # Try to get title from yt-dlp info cache
            title = None
            info_file = os.path.join(
                YOUTUBE_CACHE_DIR, f"{video_id}.info.json")
            if os.path.exists(info_file):
                try:
                    import json
                    with open(info_file) as f:
                        info = json.load(f)
                        title = info.get('title', video_id)
                except:
                    pass

            if not title:
                title = video_id

            # Check if HLS is cached
            hls_cached, _ = is_cached(file_path)

            videos.append({
                'id': video_id,
                'title': title,
                'path': file_path,
                'size': size,
                'hls_cached': hls_cached,
            })

    # Sort by title
    videos.sort(key=lambda x: x['title'].lower())
    return videos


def format_size(size_bytes: int) -> str:
    """Format file size in human readable format."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def interactive_select() -> str:
    """Let user interactively select a video file."""
    print("=" * 60)
    print("🎬 TV Playback")
    print("=" * 60)

    # Show current device
    if CURRENT_DEVICE:
        print(f"   📡 Device: {CURRENT_DEVICE['name']}")
    else:
        print("   ⚠️  Device: Not selected")
    print()

    # Get local videos
    local_videos = find_video_files()

    # Get cached YouTube videos
    youtube_videos = find_cached_youtube_videos()

    # Get local images
    local_images = find_image_files()

    # Build combined list for selection
    all_items = []

    # Local videos section
    if local_videos:
        print("📁 Local Videos:\n")
        for i, (name, size, cached) in enumerate(local_videos, 1):
            cache_icon = "⚡" if cached else "  "
            print(f"   {i:2d}. {cache_icon} {name} ({format_size(size)})")
            all_items.append(('video', name))

    # YouTube videos section
    if youtube_videos:
        start_idx = len(all_items) + 1
        print(f"\n📺 Cached YouTube Videos:\n")
        for i, yt in enumerate(youtube_videos, start_idx):
            cache_icon = "⚡" if yt['hls_cached'] else "  "
            # Truncate long titles
            title = yt['title'][:45] + \
                "..." if len(yt['title']) > 48 else yt['title']
            print(
                f"   {i:2d}. {cache_icon} {title} ({format_size(yt['size'])})")
            all_items.append(('youtube', yt['path']))

    # Images section
    if local_images:
        start_idx = len(all_items) + 1
        print(f"\n🖼️  Images (will display for 10s):\n")
        for i, (name, size) in enumerate(local_images, start_idx):
            print(f"   {i:2d}.    {name} ({format_size(size)})")
            all_items.append(('image', name))

    if not local_videos and not youtube_videos and not local_images:
        print("   (no media found)")

    print(f"\n   ⚡ = cached (instant playback)")
    print(f"\n   y. 📺 YouTube - enter a new URL")
    print(f"   i. 🖼️  Display an image (enter path)")
    print(f"   0. ⏹️  Stop current playback")
    print(f"   b. ← Back to main menu")
    print()

    max_choice = len(all_items)

    while True:
        try:
            if max_choice > 0:
                choice = input(
                    f"Select (1-{max_choice}), y/i/0/b: ").strip().lower()
            else:
                choice = input("Enter y/i/0/b: ").strip().lower()

            if choice == 'b' or choice == 'q':
                return 'BACK'

            if choice == '0':
                return 'STOP'

            if choice == 'y':
                # Show YouTube submenu with sample option
                result = select_youtube_submenu()
                if result:
                    return result
                continue

            if choice == 'i':
                # Show image selection submenu
                result = select_image_submenu()
                if result:
                    return result
                continue

            if max_choice > 0:
                idx = int(choice) - 1
                if 0 <= idx < len(all_items):
                    item_type, item_path = all_items[idx]
                    if item_type == 'image':
                        return f"IMAGE:{item_path}"
                    return item_path
                else:
                    print(f"   Please enter 1-{max_choice} or a menu option")
            else:
                print("   Please enter a valid option")

        except ValueError:
            print("   Please enter a valid option")
        except KeyboardInterrupt:
            print()
            return 'BACK'


def main_menu() -> str:
    """Show the main parent menu."""
    print("=" * 60)
    print("📺 Samsung TV Caster — Dec 27th, 2025")
    print("=" * 60)

    # Show current device status
    if CURRENT_DEVICE:
        print(f"\n   ✅ Device: {CURRENT_DEVICE['name']}")
    else:
        print(f"\n   ⚠️  No device selected")

    # Show cache status
    cache_count = 0
    if os.path.exists(HLS_CACHE_DIR):
        cache_count += len(os.listdir(HLS_CACHE_DIR))
    if os.path.exists(YOUTUBE_CACHE_DIR):
        cache_count += len([f for f in os.listdir(YOUTUBE_CACHE_DIR)
                           if f.endswith('.mp4')])
    image_cache = os.path.join(CONFIG_DIR, "image_videos")
    if os.path.exists(image_cache):
        cache_count += len(os.listdir(image_cache))

    print(f"\n   1. 🎬 TV Playback - cast videos/images")
    print(f"   2. 📡 Network Devices - scan and select devices")
    if cache_count > 0:
        print(f"   3. 🗑️  Clear Cache ({cache_count} cached)")
    print(f"\n   q. Quit")
    print()

    while True:
        try:
            choice = input("Select option: ").strip().lower()

            if choice == 'q':
                return 'QUIT'

            if choice == '1':
                return 'PLAYBACK'

            if choice == '2':
                return 'DEVICES'

            if choice == '3' and cache_count > 0:
                return 'CLEAR_CACHE'

            print("   Please enter a valid option")

        except ValueError:
            print("   Please enter a valid option")
        except KeyboardInterrupt:
            print()
            return 'QUIT'


def clear_cache():
    """Clear all cached data (HLS conversions and YouTube downloads)."""
    cleared = False

    # Clear HLS cache
    if os.path.exists(HLS_CACHE_DIR):
        count = len(os.listdir(HLS_CACHE_DIR))
        shutil.rmtree(HLS_CACHE_DIR)
        print(f"🗑️  Cleared {count} HLS conversion(s)")
        cleared = True

    # Clear YouTube cache
    if os.path.exists(YOUTUBE_CACHE_DIR):
        count = len([f for f in os.listdir(
            YOUTUBE_CACHE_DIR) if f.endswith('.mp4')])
        if count > 0:
            shutil.rmtree(YOUTUBE_CACHE_DIR)
            print(f"🗑️  Cleared {count} YouTube download(s)")
            cleared = True

    # Clear image video cache
    image_cache = os.path.join(CONFIG_DIR, "image_videos")
    if os.path.exists(image_cache):
        count = len(os.listdir(image_cache))
        if count > 0:
            shutil.rmtree(image_cache)
            print(f"🗑️  Cleared {count} image video(s)")
            cleared = True

    if not cleared:
        print("📁 Cache is already empty")


def playback_menu_loop():
    """Run the playback menu loop."""
    while True:
        try:
            video = interactive_select()
            if video == 'BACK':
                # Go back to main menu
                return
            elif video == 'STOP':
                if CURRENT_DEVICE:
                    asyncio.run(stop_playback())
                else:
                    print("❌ No device selected")
                print()
            else:
                # Check if device is selected
                if not CURRENT_DEVICE:
                    print("\n❌ No device selected. Please select a device first.")
                    print(
                        "   Use the 'Network Devices' menu to scan and select a device.")
                    print()
                    continue

                # Handle image files
                if video.startswith("IMAGE:"):
                    image_path = video[6:]  # Remove "IMAGE:" prefix
                    video_path = image_to_video(image_path, duration=10)
                    if video_path:
                        # 12s to ensure full playback
                        asyncio.run(cast_video(video_path, duration=12))
                    else:
                        print("❌ Failed to convert image")
                else:
                    asyncio.run(cast_video(video))
                print()
        except KeyboardInterrupt:
            # Ctrl+C during playback - just go back to menu
            print("\n")
            continue


def main():
    # Load saved config
    load_config()

    parser = argparse.ArgumentParser(
        description="Cast videos to your TV",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Casting
  python tv_cast.py movie.mp4           # Cast a video (Ctrl+C to stop)
  python tv_cast.py movie.mp4 -d 30     # Cast for 30 seconds
  python tv_cast.py "https://youtube.com/watch?v=..."  # Cast YouTube video
  python tv_cast.py --image photo.jpg   # Display an image for 10 seconds
  python tv_cast.py --stop              # Stop current playback

  # Device management
  python tv_cast.py --scan              # Scan network for TVs
  python tv_cast.py --device 192.168.1.50  # Set TV by IP address
  python tv_cast.py --status            # Show current device
  python tv_cast.py --list-devices      # List all discovered devices
  python tv_cast.py --forget            # Forget current device

  # Cache
  python tv_cast.py --clear-cache       # Clear cached conversions

  # Interactive mode
  python tv_cast.py                     # Launch interactive menu
        """
    )
    # Positional argument
    parser.add_argument("video", nargs="?",
                        help="Video file or YouTube URL to cast")

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
        asyncio.run(select_device())
    elif args.forget:
        forget_device()
    elif args.clear_cache:
        clear_cache()
    elif args.stop:
        asyncio.run(stop_playback())
    elif args.image:
        cast_image_cli(args.image, args.duration or 10)
    elif args.video:
        # Check if device is selected
        if not CURRENT_DEVICE:
            print("❌ No device selected. Use --scan and --device IP to set one.")
            return
        asyncio.run(cast_video(args.video, args.duration))
    else:
        # Interactive mode - main menu loop
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


def show_status():
    """Show current device status."""
    if CURRENT_DEVICE:
        print(f"📺 Current device: {CURRENT_DEVICE['name']}")
        print(f"   IP: {CURRENT_DEVICE.get('ip', 'unknown')}")
        if CURRENT_DEVICE.get('location'):
            print(f"   DLNA: {CURRENT_DEVICE['location']}")
    else:
        print("⚠️  No device selected")
        print("   Use --scan to find TVs, then --device IP to select one")

    # Show cache info
    print(f"\n📁 Cache:")

    hls_count = 0
    if os.path.exists(HLS_CACHE_DIR):
        hls_count = len(os.listdir(HLS_CACHE_DIR))
    print(f"   HLS conversions: {hls_count}")

    yt_count = 0
    if os.path.exists(YOUTUBE_CACHE_DIR):
        yt_count = len([f for f in os.listdir(
            YOUTUBE_CACHE_DIR) if f.endswith('.mp4')])
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
    if not DISCOVERED_DEVICES:
        print("⚠️  No devices discovered yet")
        print("   Use --scan to find TVs on the network")
        return

    castable = [d for d in DISCOVERED_DEVICES if d.get('castable', False)]
    other = [d for d in DISCOVERED_DEVICES if not d.get('castable', False)]

    if castable:
        print("📺 Cast-capable devices:\n")
        for dev in castable:
            current = " ← selected" if CURRENT_DEVICE and CURRENT_DEVICE.get(
                'ip') == dev.get('ip') else ""
            print(f"   {dev.get('ip'):15}  {dev.get('name', 'Unknown')}{current}")

    if other:
        print("\n📱 Other devices:\n")
        for dev in other:
            print(f"   {dev.get('ip'):15}  {dev.get('name', 'Unknown')}")


async def scan_devices_cli():
    """Scan for cast-capable devices (CLI mode)."""
    global DISCOVERED_DEVICES

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
    global CURRENT_DEVICE

    # First check if we already know this device
    for dev in DISCOVERED_DEVICES:
        if dev.get('ip') == ip:
            CURRENT_DEVICE = dev
            save_config()
            print(f"✅ Selected: {dev.get('name', ip)} ({ip})")
            return

    # Device not in our list - create a minimal entry
    CURRENT_DEVICE = {
        'ip': ip,
        'name': f"TV ({ip})",
        'type': 'dlna',
        'castable': True,
    }
    save_config()
    print(f"✅ Selected: {ip}")
    print("   (Device will be fully discovered on first connection)")


def cast_image_cli(image_path: str, duration: int):
    """Cast an image from CLI."""
    if not CURRENT_DEVICE:
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
        # Add 2 seconds buffer to ensure full playback
        asyncio.run(cast_video(video_path, duration=duration + 2))
    else:
        print("❌ Failed to convert image")


_cleanup_done = False


def cleanup_on_exit():
    """Stop playback when exiting the app."""
    global _cleanup_done

    # Prevent duplicate cleanup
    if _cleanup_done:
        return
    _cleanup_done = True

    if not CURRENT_DEVICE:
        return

    print("\n⏹️  Stopping playback...")

    # Use synchronous approach to avoid async issues during shutdown
    try:
        import urllib.request

        location = CURRENT_DEVICE.get('location')
        if not location:
            ip = CURRENT_DEVICE['ip']
            port = CURRENT_DEVICE.get('port', 9197)
            location = f'http://{ip}:{port}/dmr'

        # Extract base URL for control
        from urllib.parse import urlparse
        parsed = urlparse(location)
        control_url = f"http://{parsed.hostname}:{parsed.port}/upnp/control/AVTransport1"

        # SOAP request to stop playback
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
        # Silently fail - we're exiting anyway
        pass


if __name__ == "__main__":
    import signal

    def signal_handler(sig, frame):
        cleanup_on_exit()
        print("👋 Goodbye!")
        exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        main()
    except KeyboardInterrupt:
        cleanup_on_exit()
        print("👋 Goodbye!")
