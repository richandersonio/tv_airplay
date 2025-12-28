# TV Cast

Cast videos to your Samsung TV via DLNA.

_Last updated: December 28th, 2025_

## Prerequisites

**macOS:**

```bash
brew install uv
```

**Linux:**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
sudo apt install ffmpeg nmap  # Debian/Ubuntu
```

## Setup

```bash
git clone https://github.com/richanderson/tv_airplay.git
cd tv_airplay
uv sync
brew bundle  # macOS only
```

## Usage

### Casting

```bash
uv run python tv_cast.py video.mp4              # Cast video
uv run python tv_cast.py video.mp4 -d 60        # Cast for 60 seconds
uv run python tv_cast.py "https://youtube.com/watch?v=..."  # YouTube
uv run python tv_cast.py --image photo.jpg      # Display image (10s)
uv run python tv_cast.py --stop                 # Stop playback
```

**Alternative entry points:**

```bash
uv run python -m tv_cast video.mp4
uv run tv-cast video.mp4
```

### Device Management

```bash
uv run python tv_cast.py --scan                 # Find TVs
uv run python tv_cast.py --scan-all             # Deep network scan
uv run python tv_cast.py --device 192.168.1.50  # Set TV by IP
uv run python tv_cast.py --select-device        # Interactive device selection
uv run python tv_cast.py --status               # Show current device
uv run python tv_cast.py --list-devices         # List all devices
uv run python tv_cast.py --forget               # Forget device
```

### Cache & Interactive Mode

```bash
uv run python tv_cast.py --clear-cache          # Clear cache
uv run python tv_cast.py                        # Interactive menu
```

## System Dependencies

| Tool   | Required | Purpose                                         |
| ------ | -------- | ----------------------------------------------- |
| ffmpeg | ✅ Yes   | Video conversion to HLS                         |
| deno   | Optional | YouTube format extraction (suppresses warnings) |
| nmap   | Optional | Deep network device scanning                    |

## Project Structure

```
tv_airplay/
├── tv_cast.py           # Entry point (thin wrapper)
├── tv_cast/             # Main package
│   ├── __init__.py      # Package metadata
│   ├── __main__.py      # Module entry point
│   ├── cli.py           # Command-line interface
│   ├── config.py        # Configuration management
│   ├── casting.py       # DLNA video casting
│   ├── conversion.py    # HLS/ffmpeg conversion
│   ├── discovery.py     # Device discovery (DLNA, mDNS)
│   ├── menu.py          # Interactive menus
│   ├── utils.py         # Helper functions
│   └── youtube.py       # YouTube downloading
├── pyproject.toml       # Python dependencies
├── Brewfile             # System dependencies
└── README.md
```

## Package Files

**`tv_cast/__init__.py`** - Package metadata (version, date)

**`tv_cast/__main__.py`** - Module entry point, signal handlers, cleanup on exit

**`tv_cast/config.py`** - Configuration management (device state, cache dirs, load/save)

**`tv_cast/utils.py`** - Network utilities, formatting helpers, YouTube URL validation

**`tv_cast/discovery.py`** - Device discovery via DLNA (UPnP), mDNS (Bonjour), network scanning

**`tv_cast/conversion.py`** - HLS video conversion (ffmpeg), caching, image-to-video

**`tv_cast/youtube.py`** - YouTube video downloading and caching via yt-dlp

**`tv_cast/casting.py`** - DLNA video casting, HTTP server for HLS segments, playback control

**`tv_cast/menu.py`** - Interactive menus (main, playback, device selection)

**`tv_cast/cli.py`** - Command-line argument parsing and CLI commands

## Common uv Commands

```bash
uv sync                          # Sync dependencies
uv add package-name              # Add dependency
uv lock --upgrade && uv sync    # Update all dependencies
uv run <command>                 # Run command in venv
```

## License

MIT License - see [LICENSE](LICENSE) for details.
