# autoswagger2/analysis/urc.py
# Manages Unrestricted Resource Consumption testing.

import requests
import threading
import time
import re
from urllib.parse import urlencode
from ..utils.helpers import (
    log,
    is_quiet_output,
    join_base_and_path,
    build_full_url,
    is_same_origin_host,
    build_cross_origin_safe_headers,
)
from ..utils.config import PAGINATION_KEYWORDS
from ..utils.rate_limiter import get_rate_limiter
from ..discovery.openapi_parser import resolve_ref, merge_parameters

class UrcTester:
    def __init__(self, args, session):
        self.args = args
        self.session = session
        self.TIMEOUT = 10 # A longer timeout for this specific test
        self.ATTACK_VALUE = 999999
        self._lock = threading.Lock()
        self.TOTAL_REQUESTS = 0

    def run_tests(self, swagger_spec, api_base_url, base_path):
        urc_results = []
        target_endpoints = self._find_urc_targets(swagger_spec)

        if not target_endpoints:
            if not is_quiet_output(self.args):
                log("URC: No potential endpoints with pagination found to test.", level="INFO")
            return urc_results

        for endpoint in target_endpoints:
            path = endpoint['path']
            method = endpoint['method']
            param_name = endpoint['param_name']

            if not is_quiet_output(self.args):
                log(f"URC: Testing endpoint {method.upper()} {path} with parameter '{param_name}'", level="INFO")

            _, base_time, base_status, base_len = self._send_request(
                method, api_base_url, base_path, path, param_name, param_value=1
            )
            b_time = base_time if isinstance(base_status, int) else None
            b_len = base_len if isinstance(base_status, int) else None

            attack_url, response_time, status_code, content_length = self._send_request(
                method, api_base_url, base_path, path, param_name, param_value=self.ATTACK_VALUE
            )

            if response_time is not None:
                is_vulnerable = self._analyze_response(
                    response_time, status_code, content_length, baseline_time=b_time, baseline_length=b_len
                )

                result = {
                    "method": method.upper(),
                    "url_template": path,
                    "parameter": param_name,
                    "attack_value": self.ATTACK_VALUE,
                    "response_time_ms": int(response_time * 1000),
                    "status_code": status_code,
                    "content_length": content_length,
                    "vulnerable": is_vulnerable
                }
                urc_results.append(result)

        return urc_results

    def _find_urc_targets(self, swagger_spec):
        targets = []
        seen = set()
        for path, raw_path_details in swagger_spec.get('paths', {}).items():
            if not isinstance(raw_path_details, dict):
                continue
            path_details = resolve_ref(raw_path_details, swagger_spec)
            if not isinstance(path_details, dict):
                continue
            # Combine parameters defined at the path level and operation level
            path_params = path_details.get('parameters', [])
            if not isinstance(path_params, list):
                path_params = []
            for method, op_details in path_details.items():
                if method.lower() == 'get' and isinstance(op_details, dict):
                    operation_params = op_details.get('parameters', [])
                    if not isinstance(operation_params, list):
                        operation_params = []
                    all_params = merge_parameters(path_params, operation_params, swagger_spec)

                    for param in all_params:
                        if not isinstance(param, dict) or not param.get('name'):
                            continue
                        param_name = param['name']
                        key = (path, method.lower(), param_name)
                        if param.get('in') == 'query' and any(kw in param_name.lower() for kw in PAGINATION_KEYWORDS) and key not in seen:
                            seen.add(key)
                            targets.append({'path': path, 'method': method, 'param_name': param_name})
        return targets

    def _send_request(self, method, api_base_url, base_path, path_template, param_name, param_value=None):
        value = self.ATTACK_VALUE if param_value is None else param_value
        query_params = {param_name: value}
        substituted_template = re.sub(r"\{[^{}]+\}", "1", path_template)
        full_path = join_base_and_path(base_path, substituted_template)
        full_url = build_full_url(api_base_url, full_path) + "?" + urlencode(query_params)

        request_kwargs = {"allow_redirects": False, "timeout": self.TIMEOUT}
        if api_base_url and not is_same_origin_host(api_base_url, full_url):
            if not getattr(self.args, "allow_external", False):
                if getattr(self.args, "verbose", False):
                    log(f"URC: Blocked cross-origin request to {full_url}", level="WARNING")
                return full_url, None, "BLOCKED", 0
            safe_headers = build_cross_origin_safe_headers(self.session)
            if safe_headers:
                request_kwargs["headers"] = safe_headers

        get_rate_limiter(self.args).wait()
        start_time = time.time()
        try:
            if self.args.verbose:
                log(f"URC: Sending {method.upper()} request to {full_url}", level="DEBUG")
            with self._lock:
                self.TOTAL_REQUESTS += 1
            response = self.session.request(method.lower(), full_url, **request_kwargs)
            end_time = time.time()
            if self.args.verbose:
                log(f"URC: Received status {response.status_code} from {full_url}", level="DEBUG")
            return full_url, (end_time - start_time), response.status_code, len(response.content)
        except requests.exceptions.RequestException as e:
            end_time = time.time()
            if self.args.verbose:
                log(f"URC request to {full_url} failed: {e}", level="DEBUG")
            # If it times out, that's a strong indicator of a vulnerability
            if "timed out" in str(e).lower():
                return full_url, (end_time - start_time), "TIMEOUT", 0
            return full_url, None, "ERROR", 0

    def _analyze_response(self, response_time, status_code, content_length, baseline_time=None, baseline_length=None):
        # Compare against baseline when available to avoid false positives on naturally slow/large endpoints.
        vulnerable_by_timeout = status_code == "TIMEOUT"
        is_client_error = isinstance(status_code, int) and 400 <= status_code < 500
        vulnerable_by_time = (response_time > 5) and (
            baseline_time is None or response_time > max(baseline_time * 2.0, baseline_time + 2.0)
        )
        vulnerable_by_size = (not is_client_error) and (content_length > 500000) and (
            baseline_length is None or content_length > max(baseline_length * 2, baseline_length + 100000)
        )

        if self.args.verbose:
            log(f"URC Analysis: time_check={vulnerable_by_time} ({response_time:.2f}s), timeout_check={vulnerable_by_timeout}, size_check={vulnerable_by_size} ({content_length} bytes)", level="DEBUG")

        if vulnerable_by_time or vulnerable_by_timeout or vulnerable_by_size:
            return True
        return False
