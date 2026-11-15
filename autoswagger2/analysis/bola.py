# autoswagger2/analysis/bola.py
# Manages BOLA (Broken Object Level Authorization) testing.

import requests
import json
import re
import threading
import uuid
from ..utils.config import SAFE_HTTP_METHODS
from ..utils.rate_limiter import get_rate_limiter
from ..utils.helpers import (
    log,
    is_quiet_output,
    join_base_and_path,
    build_full_url,
    is_same_origin_host,
    build_cross_origin_safe_headers,
)

class BolaTester:
    def __init__(self, args, session):
        self.args = args
        self.session = session
        self.TIMEOUT = 10
        self._lock = threading.Lock()
        self.TOTAL_REQUESTS = 0

    def run_tests(self, target_endpoints, bola_param, bola_id, api_base_url, base_path):
        bola_results = []
        if not target_endpoints:
            if not is_quiet_output(self.args):
                log("BOLA: No target endpoints found for the given parameter.", level="INFO")
            return bola_results

        for endpoint in target_endpoints:
            path = endpoint['path']
            method = endpoint['method']

            if method.lower() not in SAFE_HTTP_METHODS and getattr(self.args, "risk", None) is False:
                if getattr(self.args, "verbose", False):
                    log(f"BOLA: Skipping unsafe method {method.upper()} {path} (use -risk to include).", level="INFO")
                continue

            if not is_quiet_output(self.args):
                log(f"BOLA: Testing endpoint {method.upper()} {path}", level="INFO")

            # 1. Send baseline request
            baseline_url, baseline_response = self._send_request(method, api_base_url, base_path, path, bola_param, bola_id)
            if baseline_response is None:
                if not is_quiet_output(self.args):
                    log(f"BOLA: Baseline request for ID '{bola_id}' failed (no response). Skipping.", level="WARNING")
                continue

            if baseline_response.status_code != 200:
                if not is_quiet_output(self.args):
                    log(f"BOLA: Baseline request for ID '{bola_id}' returned status {baseline_response.status_code}. Skipping.", level="WARNING")
                continue

            if self.args.verbose:
                log(f"BOLA: Baseline request for ID '{bola_id}' successful (Status 200).", level="DEBUG")

            # 2. Generate neighbor IDs and send attack requests
            neighbor_ids = self._generate_neighbor_ids(bola_id)
            if not neighbor_ids:
                if not is_quiet_output(self.args):
                    log(f"BOLA: Could not generate neighbor IDs for '{bola_id}'. Skipping attack phase.", level="WARNING")
                continue

            for neighbor_id in neighbor_ids:
                attack_url, attack_response = self._send_request(method, api_base_url, base_path, path, bola_param, neighbor_id)
                if attack_response:
                    # 3. Compare responses
                    is_vulnerable = self._compare_responses(baseline_response, attack_response)

                    result = {
                        "method": method.upper(),
                        "url_template": path,
                        "baseline_id": bola_id,
                        "attack_id": neighbor_id,
                        "baseline_status": baseline_response.status_code,
                        "attack_status": attack_response.status_code,
                        "baseline_length": len(baseline_response.content),
                        "attack_length": len(attack_response.content),
                        "vulnerable": is_vulnerable,
                        "request_body": None # BOLA tests are typically on GET requests
                    }
                    bola_results.append(result)

        return bola_results

    def _send_request(self, method, api_base_url, base_path, path_template, bola_param, object_id):
        substituted_template = path_template.replace(f"{{{bola_param}}}", str(object_id))
        substituted_template = re.sub(r"\{[^{}]+\}", "1", substituted_template)
        full_path = join_base_and_path(base_path, substituted_template)
        full_url = build_full_url(api_base_url, full_path)

        request_kwargs = {"allow_redirects": False, "timeout": self.TIMEOUT}
        if api_base_url and not is_same_origin_host(api_base_url, full_url):
            if not getattr(self.args, "allow_external", False):
                if getattr(self.args, "verbose", False):
                    log(f"BOLA: Blocked cross-origin request to {full_url}", level="WARNING")
                return full_url, None
            safe_headers = build_cross_origin_safe_headers(self.session)
            if safe_headers:
                request_kwargs["headers"] = safe_headers

        try:
            if self.args.verbose:
                log(f"BOLA: Sending {method.upper()} request to {full_url}", level="DEBUG")
            get_rate_limiter(self.args).wait()
            with self._lock:
                self.TOTAL_REQUESTS += 1
            response = self.session.request(method.lower(), full_url, **request_kwargs)
            if self.args.verbose:
                log(f"BOLA: Received status {response.status_code} from {full_url}", level="DEBUG")
            return full_url, response
        except requests.exceptions.RequestException as e:
            if self.args.verbose:
                log(f"BOLA request to {full_url} failed: {e}", level="DEBUG")
            return full_url, None

    def _generate_neighbor_ids(self, original_id):
        neighbors = []
        original_id_str = str(original_id).strip()

        # 1. Check if it is a pure integer
        try:
            int_id = int(original_id_str)
            return [str(int_id - 1), str(int_id + 1)]
        except ValueError:
            pass

        # 2. Check if it is a UUID (v4 or similar)
        uuid_pattern = r'^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-)([0-9a-fA-F]{12})$'
        uuid_match = re.match(uuid_pattern, original_id_str)
        if uuid_match:
            prefix, last_part = uuid_match.groups()
            try:
                # Increment/decrement the integer value of the last part
                val = int(last_part, 16)
                # Ensure we format it back with leading zeros to 12 chars
                neighbors.append(f"{prefix}{(val - 1) & 0xffffffffffff:012x}")
                neighbors.append(f"{prefix}{(val + 1) & 0xffffffffffff:012x}")
            except ValueError:
                pass
            # Also generate a completely random UUIDv4 as a fallback neighbor
            neighbors.append(str(uuid.uuid4()))
            return neighbors

        # 3. Check if it is a MongoDB ObjectID (24-char hex)
        mongo_pattern = r'^([0-9a-fA-F]{20})([0-9a-fA-F]{4})$'
        mongo_match = re.match(mongo_pattern, original_id_str)
        if mongo_match:
            prefix, last_part = mongo_match.groups()
            try:
                val = int(last_part, 16)
                neighbors.append(f"{prefix}{(val - 1) & 0xffff:04x}")
                neighbors.append(f"{prefix}{(val + 1) & 0xffff:04x}")
            except ValueError:
                pass
            return neighbors

        # 4. Check if it has an integer embedded with a prefix/suffix (e.g. usr-123 or id_123)
        prefix_suffix_pattern = r'^([a-zA-Z_-]+)(\d+)([a-zA-Z_-]*)$'
        ps_match = re.match(prefix_suffix_pattern, original_id_str)
        if ps_match:
            prefix, num_str, suffix = ps_match.groups()
            try:
                val = int(num_str)
                neighbors.append(f"{prefix}{val - 1}{suffix}")
                neighbors.append(f"{prefix}{val + 1}{suffix}")
            except ValueError:
                pass
            return neighbors

        # 5. Fallback for string identifiers: try common alternatives
        common_fallbacks = ["admin", "guest", "root", "user", "test"]
        for fallback in common_fallbacks:
            if fallback != original_id_str.lower():
                neighbors.append(fallback)
        
        return neighbors

    def _parse_json_bytes(self, content):
        if not isinstance(content, (bytes, bytearray)) or not content:
            return None
        try:
            return json.loads(content.decode('utf-8', errors='ignore'))
        except (json.JSONDecodeError, ValueError):
            return None

    def _compare_responses(self, baseline, attack):
        if attack.status_code != 200:
            return False

        # Prevent ZeroDivisionError if baseline is empty
        if len(baseline.content) == 0:
            return len(attack.content) > 0

        base_json = self._parse_json_bytes(baseline.content)
        attack_json = self._parse_json_bytes(attack.content)

        if base_json is not None and attack_json is not None:
            if isinstance(attack_json, dict):
                if (
                    attack_json.get('success') is False
                    or attack_json.get('status') in (401, 403, 404, 'error', 'unauthorized', 'forbidden')
                    or (bool(attack_json.get('error')) and not (isinstance(base_json, dict) and bool(base_json.get('error'))))
                ):
                    return False

            if isinstance(base_json, dict) and isinstance(attack_json, dict):
                if base_json == attack_json:
                    return False
                if not base_json or not attack_json:
                    return bool(attack_json) and not bool(base_json)
                overlap = len(set(base_json) & set(attack_json)) / max(len(base_json), len(attack_json))
                return overlap >= 0.5

            if isinstance(base_json, list) and isinstance(attack_json, list):
                return len(attack_json) > 0 and base_json != attack_json

        elif (base_json is not None) != (attack_json is not None):
            return False

        length_difference = abs(len(baseline.content) - len(attack.content))
        # Allow for a small difference in content length (e.g., 10%) for non-JSON responses
        if (length_difference / len(baseline.content)) < 0.1:
            return True
        return False
