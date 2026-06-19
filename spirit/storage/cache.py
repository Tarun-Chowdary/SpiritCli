"""SpiritCLI Scan Cache — Directory hash-based caching system"""

import json
import os
import hashlib
import time
from datetime import datetime

CACHE_FILE = os.path.join(os.path.dirname(__file__), "scan_cache.json")


def _hash_directory(path):
    """
    Creates a hash of all source files in the directory.
    If any file changes, hash changes, cache invalidates.
    """
    hasher = hashlib.md5()
    extensions = (".js", ".ts", ".py", ".jsx", ".tsx", ".json")
    excluded = {"node_modules", "venv", ".git", "__pycache__"}

    file_hashes = []
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted([d for d in dirs if d not in excluded])
        for file in sorted(files):
            if file.endswith(extensions) and not file.endswith(".spirit.bak"):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "rb") as f:
                        content = f.read()
                    file_hashes.append(
                        f"{filepath}:{hashlib.md5(content).hexdigest()}"
                    )
                except Exception:
                    pass

    combined = "\n".join(file_hashes)
    hasher.update(combined.encode())
    return hasher.hexdigest()


def _load_cache():
    """Load cache file safely"""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(cache):
    """Save cache file safely"""
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


def get_cached_scan(path):
    """
    Returns cached scan data if directory unchanged.
    Returns None if cache is stale or missing.
    """
    abs_path = os.path.abspath(path)
    cache = _load_cache()

    if abs_path not in cache:
        return None

    entry = cache[abs_path]

    # check if it's a scan entry (has 'hash' key)
    if "hash" not in entry:
        return None

    current_hash = _hash_directory(abs_path)
    if entry.get("hash") != current_hash:
        return None  # files changed, cache stale

    return entry.get("report_data")


def save_scan_cache(path, report_data):
    """Save scan results to cache with directory hash."""
    abs_path = os.path.abspath(path)
    cache = _load_cache()

    cache[abs_path] = {
        "hash": _hash_directory(abs_path),
        "timestamp": datetime.now().isoformat(),
        "report_data": report_data,
    }

    _save_cache(cache)


def get_cached_cve(package_name, version):
    """
    Returns cached CVE data for a package+version.
    Valid for 24 hours — CVE databases update daily.
    """
    cache_key = f"cve::{package_name}::{version}"
    cache = _load_cache()

    if cache_key not in cache:
        return None

    entry = cache[cache_key]
    cached_time = entry.get("timestamp", 0)

    # CVE cache valid for 24 hours
    if time.time() - cached_time > 86400:
        return None

    return entry.get("data")


def save_cached_cve(package_name, version, data):
    """Save CVE results to cache with 24-hour TTL."""
    cache_key = f"cve::{package_name}::{version}"
    cache = _load_cache()

    cache[cache_key] = {
        "timestamp": time.time(),
        "data": data,
    }

    _save_cache(cache)


def get_cached_freshness(package_name, version):
    """
    Returns cached freshness data for a package.
    Valid for 6 hours — npm registry updates frequently.
    """
    cache_key = f"freshness::{package_name}::{version}"
    cache = _load_cache()

    if cache_key not in cache:
        return None

    entry = cache[cache_key]
    cached_time = entry.get("timestamp", 0)

    # freshness cache valid for 6 hours
    if time.time() - cached_time > 21600:
        return None

    return entry.get("data")


def save_cached_freshness(package_name, version, data):
    """Save freshness results to cache with 6-hour TTL."""
    cache_key = f"freshness::{package_name}::{version}"
    cache = _load_cache()

    cache[cache_key] = {
        "timestamp": time.time(),
        "data": data,
    }

    _save_cache(cache)


def invalidate_cache(path):
    """Force invalidate scan cache for a path. Call after spirit fix."""
    abs_path = os.path.abspath(path)
    cache = _load_cache()

    if abs_path in cache:
        del cache[abs_path]
        _save_cache(cache)


def clear_all_cache():
    """Clear entire cache file."""
    if os.path.exists(CACHE_FILE):
        try:
            os.remove(CACHE_FILE)
        except Exception:
            pass