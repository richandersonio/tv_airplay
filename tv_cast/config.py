"""Configuration management and constants."""

import json
import os
from typing import Optional, Dict, List, Any

# Settings
HTTP_PORT = 8765
CONFIG_DIR = os.path.expanduser("~/.tv_cast")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
HLS_CACHE_DIR = os.path.join(CONFIG_DIR, "hls_cache")
YOUTUBE_CACHE_DIR = os.path.join(CONFIG_DIR, "youtube")
IMAGE_CACHE_DIR = os.path.join(CONFIG_DIR, "image_videos")
FFMPEG_THREADS = 20

# Sample content
SAMPLE_YOUTUBE_URL = "https://youtube.com/watch?v=yvsoeyqCIU8"
SAMPLE_YOUTUBE_TITLE = "Sample: Mo Holiday - Nov 27th 2017"

# App info
APP_VERSION = "0.1.0"
APP_DATE = "Dec 27th, 2025"

# Global state (mutable)
_state = {
    'current_device': None,
    'discovered_devices': [],
}


def get_current_device() -> Optional[Dict[str, Any]]:
    """Get current selected device."""
    return _state['current_device']


def set_current_device(device: Optional[Dict[str, Any]]) -> None:
    """Set current selected device."""
    _state['current_device'] = device


def get_discovered_devices() -> List[Dict[str, Any]]:
    """Get list of discovered devices."""
    return _state['discovered_devices']


def set_discovered_devices(devices: List[Dict[str, Any]]) -> None:
    """Set list of discovered devices."""
    _state['discovered_devices'] = devices


def make_json_serializable(obj: Any) -> Any:
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
        try:
            return str(obj)
        except Exception:
            return None


def load_config() -> None:
    """Load saved configuration."""
    os.makedirs(CONFIG_DIR, exist_ok=True)

    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, encoding='utf-8') as f:
                config = json.load(f)
                _state['current_device'] = config.get('device')
                _state['discovered_devices'] = config.get(
                    'discovered_devices', [])
        except (json.JSONDecodeError, OSError):
            pass


def save_config() -> None:
    """Save current configuration."""
    os.makedirs(CONFIG_DIR, exist_ok=True)

    config = {
        'device': make_json_serializable(_state['current_device']),
        'discovered_devices': make_json_serializable(_state['discovered_devices']),
    }
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)


def save_discovered_devices(devices: List[Dict[str, Any]]) -> None:
    """Save discovered devices to config."""
    existing_ips = {d.get('ip') for d in _state['discovered_devices']}

    for device in devices:
        if device.get('ip') in existing_ips:
            for i, existing in enumerate(_state['discovered_devices']):
                if existing.get('ip') == device.get('ip'):
                    _state['discovered_devices'][i] = device
                    break
        else:
            _state['discovered_devices'].append(device)

    save_config()


def forget_device() -> None:
    """Forget/unpair the current device."""
    _state['current_device'] = None
    save_config()
    print("🔌 Device forgotten")
