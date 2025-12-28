"""YouTube video downloading."""

import os

from .config import YOUTUBE_CACHE_DIR
from .conversion import is_cached


def download_youtube(url: str) -> str:
    """Download YouTube video and return local path."""
    import yt_dlp
    import json as json_module

    os.makedirs(YOUTUBE_CACHE_DIR, exist_ok=True)

    print(f"📺 Fetching YouTube video info...")

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

            info_path = os.path.join(YOUTUBE_CACHE_DIR, f"{video_id}.info.json")
            with open(info_path, 'w') as f:
                json_module.dump({'id': video_id, 'title': title, 'duration': duration}, f)

        except Exception as e:
            print(f"❌ Failed to get video info: {e}")
            return None

    output_path = os.path.join(YOUTUBE_CACHE_DIR, f"{video_id}.mp4")
    if os.path.exists(output_path):
        print(f"⚡ Using cached download")
        return output_path

    print(f"⬇️  Downloading (best quality up to 1080p)...")

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

            title = None
            info_file = os.path.join(YOUTUBE_CACHE_DIR, f"{video_id}.info.json")
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

            hls_cached, _ = is_cached(file_path)

            videos.append({
                'id': video_id,
                'title': title,
                'path': file_path,
                'size': size,
                'hls_cached': hls_cached,
            })

    videos.sort(key=lambda x: x['title'].lower())
    return videos

