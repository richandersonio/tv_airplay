# TV AirPlay

Cast videos to your Samsung TV via DLNA/AirPlay.

_Last updated: December 27th, 2025_

## Prerequisites

### macOS

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install uv (Python package manager)
brew install uv
```

### Linux

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install system dependencies (Debian/Ubuntu)
sudo apt install ffmpeg nmap

# Install deno (optional, for YouTube)
curl -fsSL https://deno.land/install.sh | sh
```

## Setup

```bash
# Clone the repo
git clone <repo-url>
cd tv_airplay

# Install Python packages
uv sync

# Install system dependencies (macOS only)
brew bundle
```

This installs:

- **Python packages** from `uv.lock` — yt-dlp, async-upnp-client, zeroconf, etc.
- **System tools** from `Brewfile` — ffmpeg, deno, nmap

## Usage

All features work from the command line. The interactive menu is optional.

### Casting

```bash
# Cast a local video (Ctrl+C to stop)
uv run python tv_cast.py video.mp4

# Cast for specific duration (seconds)
uv run python tv_cast.py video.mp4 -d 60

# Cast a YouTube video
uv run python tv_cast.py "https://youtube.com/watch?v=yvsoeyqCIU8"

# Display an image (default 10 seconds)
uv run python tv_cast.py --image photo.jpg

# Stop current playback
uv run python tv_cast.py --stop
```

### Try It Out

```bash
# Sample YouTube video to test with
uv run python tv_cast.py "https://youtube.com/watch?v=yvsoeyqCIU8"
```

### Device Management

```bash
# Scan for TVs
uv run python tv_cast.py --scan

# Set TV by IP address
uv run python tv_cast.py --device 192.168.1.50

# Show current device
uv run python tv_cast.py --status

# List all discovered devices
uv run python tv_cast.py --list-devices

# Forget current device
uv run python tv_cast.py --forget

# Interactive device selection
uv run python tv_cast.py --select-device

# Deep scan all network devices
uv run python tv_cast.py --scan-all
```

### Cache

```bash
# Clear cached HLS conversions
uv run python tv_cast.py --clear-cache
```

### Interactive Mode

```bash
# Launch interactive menu (optional)
uv run python tv_cast.py
```

## System Dependencies

| Tool   | Required | Purpose                                         |
| ------ | -------- | ----------------------------------------------- |
| ffmpeg | ✅ Yes   | Video conversion to HLS                         |
| deno   | Optional | YouTube format extraction (suppresses warnings) |
| nmap   | Optional | Deep network device scanning                    |

Install all with: `brew bundle`

## Common uv Commands

```bash
# Sync dependencies (after pulling changes)
uv sync

# Add a new dependency
uv add package-name

# Update all dependencies
uv lock --upgrade && uv sync

# Run any command in the venv
uv run <command>
```
