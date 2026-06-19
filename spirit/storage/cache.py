import json
import os
import hashlib
from datetime import datetime


CACHE_FILE = os.path.join(os.path.dirname(__file__), "scan_cache.json")


def _hash_directory(path):
    """
    Creates a hash of all JS/TS/PY/JSON files in the directory.
    If any file changes, the hash changes.
    """
    hasher = hashlib.md5()
    extensions = ('.js', '.ts', '.py', '.jsx', '.tsx', '.json')
    excluded = {'node_modules', 'venv', '.git', '__pycache__'}

    file_hashes = []
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted([d for d in dirs if d not in excluded])
        for file in sorted(files):
            if file.endswith(extensions) and not file.endswith('.spirit.bak'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'rb') as f:
                        content = f.read()
                    file_hashes.append(f"{filepath}:{hashlib.md5(content).hexdigest()}")
                except Exception:
                    pass

    combined = "\n".join(file_hashes)
    hasher.update(combined.encode())
    return hasher.hexdigest()


def get_cached_scan(path):
    """
    Returns cached scan data if the directory hasn't changed.
    Returns None if cache is stale or missing.
    """
    abs_path = os.path.abspath(path)

    if not os.path.exists(CACHE_FILE):
        return None

    try:
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            cache = json.load(f)

        if abs_path not in cache:
            return None

        entry = cache[abs_path]
        current_hash = _hash_directory(abs_path)

        if entry.get("hash") != current_hash:
            return None  # files changed, cache stale

        return entry.get("report_data")

    except Exception:
        return None


def save_scan_cache(path, report_data):
    """
    Save scan results to cache with directory hash.
    """
    abs_path = os.path.abspath(path)

    try:
        cache = {}
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                cache = json.load(f)

        cache[abs_path] = {
            "hash": _hash_directory(abs_path),
            "timestamp": datetime.now().isoformat(),
            "report_data": report_data
        }

        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2)

    except Exception:
        pass


def invalidate_cache(path):
    """
    Force invalidate cache for a path.
    Call this after spirit fix modifies files.
    """
    abs_path = os.path.abspath(path)

    if not os.path.exists(CACHE_FILE):
        return

    try:
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            cache = json.load(f)

        if abs_path in cache:
            del cache[abs_path]

        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2)

    except Exception:
        pass


def clear_all_cache():
    """Clear entire cache."""
    if os.path.exists(CACHE_FILE):
        os.remove(CACHE_FILE)