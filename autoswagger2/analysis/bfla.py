# autoswagger2/analysis/bfla.py
# Manages BFLA (Broken Function Level Authorization) testing.

import requests
import json
import re
import threading
from ..utils.config import HTTP_METHODS, SAFE_HTTP_METHODS
from ..utils.rate_limiter import get_rate_limiter
from ..utils.helpers import (
    log,
    is_quiet_output,
    join_base_and_path,
    build_full_url,
    is_same_origin_host,
    build_cross_origin_safe_headers,
)
from ..core.requester import Requester
from ..discovery.openapi_parser import resolve_ref, merge_parameters

BFLA_KEYWORDS = [
    'admin', 'admins', 'administrator', 'admintest',
    'management', 'manage',
    'internal', 'debug', 'config', 'configuration',
    'actuator', 'console', 'superuser', 'staff', 'backoffice',
]

class BflaTester:
    def __init__(self, args, session, bola_param=None, bola_id=None):
        self.args = args
        self.session = session
        self.bola_param = bola_param
        self.bola_id = bola_id
        self.TIMEOUT = 10
        self._lock = threading.Lock()
        self.TOTAL_REQUESTS = 0

    def _is_admin_path(self, path):
        clean = re.sub(r"\{[^{}]+\}", "", path).lower()
        tokens = [t for t in re.split(r"[/_\-.]+", clean) if t]
        return any(t in BFLA_KEYWORDS or t.startswith("admin") for t in tokens)

    def run_tests(self, swagger_spec, api_base_url, base_path):
        bfla_results = []
        target_endpoints = self._find_bfla_targets(swagger_spec)

        if not target_endpoints:
            if not is_quiet_output(self.args):
                log("BFLA: No potential admin endpoints found to test.", level="INFO")
            return bfla_results

        requester = Requester(api_base_url, self.args, self.session)
        requester._current_spec = swagger_spec if isinstance(swagger_spec, dict) else {}
        is_risk = bool(getattr(self.args, "risk", False))

        for endpoint in target_endpoints:
            path = endpoint['path']
            method = endpoint['method']
            parameters = endpoint['parameters']
            schema = endpoint['schema']

            if method.lower() not in SAFE_HTTP_METHODS and not is_risk:
                if getattr(self.args, "verbose", False):
                    log(f"BFLA: Skipping unsafe method {method.upper()} {path} (use -risk to include).", level="INFO")
                continue

            if not is_quiet_output(self.args):
                log(f"BFLA: Testing endpoint {method.upper()} {path}", level="INFO")

            request_body = None
            if method.lower() in ['post', 'put', 'patch'] and schema:
                request_body = requester._build_request_body(schema, 'application/json', spec_data=swagger_spec)

            attack_url, attack_response = self._send_request(method, api_base_url, base_path, path, parameters, request_body)

            if attack_response:
                is_vulnerable = self._analyze_response(attack_response)

                result = {
                    "method": method.upper(),
                    "url_template": path,
                    "status_code": attack_response.status_code,
                    "vulnerable": is_vulnerable,
                    "request_body": request_body
                }
                bfla_results.append(result)

        return bfla_results

    def _find_bfla_targets(self, swagger_spec):
        targets = []
        for path, raw_methods in swagger_spec.get('paths', {}).items():
            if not isinstance(raw_methods, dict):
                continue
            methods = resolve_ref(raw_methods, swagger_spec)
            if not isinstance(methods, dict):
                continue
            if self._is_admin_path(path):
                path_params = methods.get('parameters', [])
                for method, details in methods.items():
                    if method.lower() not in HTTP_METHODS or not isinstance(details, dict):
                        continue
                    merged_params = merge_parameters(path_params, details.get('parameters', []), swagger_spec)
                    schema = None
                    if 'requestBody' in details and isinstance(details['requestBody'], dict):
                        rb = resolve_ref(details['requestBody'], swagger_spec)
                        content = rb.get('content', {}) if isinstance(rb, dict) else {}
                        if isinstance(content, dict):
                            for ct, media_obj in content.items():
                                if (ct == 'application/json' or '+json' in ct.lower()) and isinstance(media_obj, dict):
                                    schema = resolve_ref(media_obj.get('schema', {}), swagger_spec)
                                    break
                    else:
                        for param in merged_params:
                            if param.get('in') == 'body' and isinstance(param.get('schema'), dict):
                                schema = resolve_ref(param['schema'], swagger_spec)
                                break

                    targets.append({
                        'path': path,
                        'method': method,
                        'parameters': merged_params,
                        'schema': schema
                    })
        return targets

    def _send_request(self, method, api_base_url, base_path, path_template, parameters, body=None):

        path_with_params_substituted = path_template

        # Substitute path parameters
        for param in parameters:
            if not isinstance(param, dict):
                continue
            if param.get('in') == 'path':
                param_name = param.get('name')
                # Use the provided bola_id if the parameter name matches
                if self.bola_param and self.bola_id and param_name == self.bola_param:
                    value = self.bola_id
                else:
                    value = "1" # Default value for other params

                path_with_params_substituted = path_with_params_substituted.replace(f"{{{param_name}}}", str(value))

        path_with_params_substituted = re.sub(r"\{[^{}]+\}", "1", path_with_params_substituted)

        full_path = join_base_and_path(base_path, path_with_params_substituted)
        full_url = build_full_url(api_base_url, full_path)

        headers = {'Content-Type': 'application/json'} if body else {}
        if api_base_url and not is_same_origin_host(api_base_url, full_url):
            if not getattr(self.args, "allow_external", False):
                if getattr(self.args, "verbose", False):
                    log(f"BFLA: Blocked cross-origin request to {full_url}", level="WARNING")
                return full_url, None
            headers = build_cross_origin_safe_headers(self.session, headers)

        try:
            if self.args.verbose:
                log(f"BFLA: Sending {method.upper()} request to {full_url}", level="DEBUG")
            get_rate_limiter(self.args).wait()
            with self._lock:
                self.TOTAL_REQUESTS += 1
            response = self.session.request(method.lower(), full_url, headers=headers, data=body, allow_redirects=False, timeout=self.TIMEOUT)
            if self.args.verbose:
                log(f"BFLA: Received status {response.status_code} from {full_url}", level="DEBUG")
            return full_url, response
        except requests.exceptions.RequestException as e:
            if self.args.verbose:
                log(f"BFLA request to {full_url} failed: {e}", level="DEBUG")
            return full_url, None

    def _analyze_response(self, response):
        if not (200 <= response.status_code < 300):
            return False

        content = getattr(response, 'content', None)
        if isinstance(content, (bytes, bytearray)) and content:
            try:
                data = json.loads(content.decode('utf-8', errors='ignore'))
                if isinstance(data, dict):
                    if (
                        data.get('success') is False
                        or data.get('ok') is False
                        or data.get('status') in (401, 403, 'error', 'unauthorized', 'forbidden')
                        or data.get('code') in (401, 403)
                        or (bool(data.get('error')) and len(data) <= 3)
                    ):
                        return False
            except (json.JSONDecodeError, ValueError):
                pass

        return True
