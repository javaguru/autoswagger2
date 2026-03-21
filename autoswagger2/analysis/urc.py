# autoswagger2/analysis/urc.py
# Manages Unrestricted Resource Consumption testing.

import requests
import time
from urllib.parse import urljoin, urlencode
from ..utils.helpers import log
from ..utils.config import PAGINATION_KEYWORDS

class UrcTester:
    def __init__(self, args, session):
        self.args = args
        self.session = session
        self.TIMEOUT = 10 # A longer timeout for this specific test
        self.ATTACK_VALUE = 999999

    def run_tests(self, swagger_spec, api_base_url, base_path):
        urc_results = []
        target_endpoints = self._find_urc_targets(swagger_spec)

        if not target_endpoints:
            if not self.args.product:
                log("URC: No potential endpoints with pagination found to test.", level="INFO")
            return urc_results

        for endpoint in target_endpoints:
            path = endpoint['path']
            method = endpoint['method']
            param_name = endpoint['param_name']

            if not self.args.product:
                log(f"URC: Testing endpoint {method.upper()} {path} with parameter '{param_name}'", level="INFO")

            attack_url, response_time, status_code, content_length = self._send_request(method, api_base_url, base_path, path, param_name)

            if response_time is not None:
                is_vulnerable = self._analyze_response(response_time, status_code, content_length)

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
        for path, path_details in swagger_spec.get('paths', {}).items():
            # Combine parameters defined at the path level and operation level
            path_params = path_details.get('parameters', [])
            for method, op_details in path_details.items():
                if method.lower() == 'get' and isinstance(op_details, dict):
                    operation_params = op_details.get('parameters', [])
                    all_params = path_params + operation_params

                    for param in all_params:
                        if param.get('in') == 'query' and any(kw in param['name'].lower() for kw in PAGINATION_KEYWORDS):
                            targets.append({'path': path, 'method': method, 'param_name': param['name']})
        return targets

    def _send_request(self, method, api_base_url, base_path, path_template, param_name):
        query_params = {param_name: self.ATTACK_VALUE}
        full_path = base_path + path_template
        full_url = urljoin(api_base_url, full_path) + "?" + urlencode(query_params)

        start_time = time.time()
        try:
            if self.args.verbose:
                log(f"URC: Sending {method.upper()} request to {full_url}", level="DEBUG")
            response = self.session.request(method.lower(), full_url, timeout=self.TIMEOUT)
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

    def _analyze_response(self, response_time, status_code, content_length):
        # A response time over 5 seconds OR a response larger than 500KB is a strong indicator of a potential DoS vector.
        vulnerable_by_time = response_time > 5
        vulnerable_by_timeout = status_code == "TIMEOUT"
        vulnerable_by_size = content_length > 500000

        if self.args.verbose:
            log(f"URC Analysis: time_check={vulnerable_by_time} ({response_time:.2f}s), timeout_check={vulnerable_by_timeout}, size_check={vulnerable_by_size} ({content_length} bytes)", level="DEBUG")

        if vulnerable_by_time or vulnerable_by_timeout or vulnerable_by_size:
            return True
        return False
