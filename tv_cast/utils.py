"""Utility functions."""

import os
import socket
import subprocess
from typing import Optional, Dict, Any


def get_local_ip() -> str:
    """Get local IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
        except OSError:
            return '127.0.0.1'


def get_local_subnet() -> str:
    """Get the local subnet for scanning."""
    local_ip = get_local_ip()
    parts = local_ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}"


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


def check_port(ip: str, port: int, timeout: float = 0.3) -> bool:
    """Check if a port is open on a host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
            return result == 0
        except OSError:
            return False


def ping_host(ip: str, timeout: float = 0.3) -> bool:
    """Check if a host is reachable via ping."""
    import platform

    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]

    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout + 0.5, check=False)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def get_hostname(ip: str) -> Optional[str]:
    """Try to resolve hostname for an IP."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except OSError:
        return None


def is_youtube_url(url: str) -> bool:
    """Check if URL is a YouTube video."""
    youtube_patterns = [
        "youtube.com/watch",
        "youtu.be/",
        "youtube.com/shorts",
        "youtube.com/live",
    ]
    return any(p in url.lower() for p in youtube_patterns)


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


def get_device_icon(device: Dict[str, Any]) -> str:
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
