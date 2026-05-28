# autoswagger2/utils/cache.py
import os
import json
import hashlib

class SpecCache:
    def __init__(self, cache_dir="~/.autoswagger2/cache"):
        self.cache_dir = os.path.expanduser(cache_dir)
        os.makedirs(self.cache_dir, exist_ok=True)
        
    def _get_hash(self, url):
        return hashlib.md5(url.encode('utf-8')).hexdigest()

    def get_cached_spec(self, url):
        """Avoids redundant requests by reading from cache."""
        cache_path = os.path.join(self.cache_dir, f"{self._get_hash(url)}.json")
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return None
        return None
        
    def cache_spec(self, url, spec):
        """Stores discovered specs in the cache."""
        # Only cache dictionaries (valid specs)
        if not isinstance(spec, dict):
            return
            
        cache_path = os.path.join(self.cache_dir, f"{self._get_hash(url)}.json")
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(spec, f)
        except Exception:
            pass
