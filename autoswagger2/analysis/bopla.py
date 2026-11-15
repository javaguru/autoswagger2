# autoswagger2/analysis/bopla.py
# Manages BOPLA (Broken Object Property Level Authorization) testing.

import requests
import json
import re
import threading
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from ..utils.helpers import (
    log,
    console,
    is_quiet_output,
    join_base_and_path,
    build_full_url,
    is_same_origin_host,
    build_cross_origin_safe_headers,
)
from ..utils.config import BOPLA_SENSITIVE_KEYS, HTTP_METHODS
from ..utils.rate_limiter import get_rate_limiter
from ..core.requester import Requester
from ..discovery.openapi_parser import resolve_ref, merge_parameters

class BoplaTester:
    def __init__(self, args, session, bola_param=None, bola_id=None):
        self.args = args
        self.session = session
        self.bola_param = bola_param
        self.bola_id = bola_id
        self.TIMEOUT = 10
        self._lock = threading.Lock()
        self.TOTAL_REQUESTS = 0

    def run_tests(self, swagger_spec, api_base_url, base_path):
        bopla_results = []
        target_endpoints = self._find_bopla_targets(swagger_spec)

        if not target_endpoints:
            if not is_quiet_output(self.args):
                log("BOPLA: No potential endpoints found to test (POST/PUT/PATCH with JSON body).", level="INFO")
            return bopla_results

        if is_quiet_output(self.args):
            # In quiet JSON/product mode, just loop without the progress bar
            for endpoint in target_endpoints:
                self._test_endpoint(endpoint, api_base_url, base_path, bopla_results, swagger_spec=swagger_spec)
        else:
            with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TimeElapsedColumn(),
                    console=console,
                    redirect_stdout=True,
                    redirect_stderr=True
            ) as progress:
                task = progress.add_task("Running BOPLA tests...", total=len(target_endpoints))
                for endpoint in target_endpoints:
                    self._test_endpoint(endpoint, api_base_url, base_path, bopla_results, swagger_spec=swagger_spec)
                    progress.update(task, advance=1)

        return bopla_results

    def _parse_json_body(self, response):
        if response is None:
            return None
        content = getattr(response, 'content', None)
        if not isinstance(content, (bytes, bytearray)) or not content:
            return None
        try:
            return json.loads(content.decode('utf-8', errors='ignore'))
        except (json.JSONDecodeError, ValueError):
            return None

    def _json_contains_key_value(self, obj, target_key, expected_value):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == target_key:
                    if isinstance(expected_value, bool):
                        if isinstance(v, bool) and v is expected_value:
                            return True
                    elif not isinstance(v, bool) and v == expected_value:
                        return True
                if self._json_contains_key_value(v, target_key, expected_value):
                    return True
        elif isinstance(obj, list):
            for item in obj:
                if self._json_contains_key_value(item, target_key, expected_value):
                    return True
        return False

    def _is_mass_assignment_confirmed(self, baseline_response, attack_response, key, value):
        if attack_response is None or not (200 <= attack_response.status_code < 300):
            return False

        attack_json = self._parse_json_body(attack_response)
        if attack_json is not None:
            if isinstance(attack_json, dict):
                if (
                    attack_json.get('success') is False
                    or attack_json.get('status') in (401, 403, 'error')
                    or ('error' in attack_json and attack_json['error'] and len(attack_json) <= 3)
                ):
                    return False

            baseline_json = self._parse_json_body(baseline_response)
            in_attack = self._json_contains_key_value(attack_json, key, value)
            in_baseline = self._json_contains_key_value(baseline_json, key, value) if baseline_json is not None else False
            if in_attack and not in_baseline:
                return True

            if baseline_response is not None and baseline_response.status_code >= 400:
                return True

            return False

        # Non-JSON responses
        if baseline_response is not None:
            if baseline_response.status_code == attack_response.status_code and baseline_response.content == attack_response.content:
                return False
            if baseline_response.status_code >= 400:
                return True

        attack_text = attack_response.content.decode('utf-8', errors='ignore') if isinstance(getattr(attack_response, 'content', None), (bytes, bytearray)) else ''
        baseline_text = baseline_response.content.decode('utf-8', errors='ignore') if baseline_response is not None and isinstance(getattr(baseline_response, 'content', None), (bytes, bytearray)) else ''
        if (f'"{key}"' in attack_text or f"{key}={value}" in attack_text) and f'"{key}"' not in baseline_text and f"{key}={value}" not in baseline_text:
            return True

        return False

    def _test_endpoint(self, endpoint, api_base_url, base_path, bopla_results, swagger_spec=None):
        path = endpoint['path']
        method = endpoint['method']
        schema = endpoint['schema']

        if not is_quiet_output(self.args):
            log(f"BOPLA: Testing endpoint {method.upper()} {path}", level="INFO")

        # Build a valid baseline request body
        requester = Requester(api_base_url, self.args, self.session)
        requester._current_spec = swagger_spec or {}
        baseline_body_str = requester._build_request_body(schema, 'application/json', spec_data=swagger_spec or {})
        if not baseline_body_str:
            return

        try:
            baseline_body_obj = json.loads(baseline_body_str)
            # Ensure we are working with a dictionary to inject properties
            if not isinstance(baseline_body_obj, dict):
                return
        except (json.JSONDecodeError, TypeError):
            return

        _, baseline_response = self._send_request(method, api_base_url, base_path, path, baseline_body_str)

        for key, values in BOPLA_SENSITIVE_KEYS.items():
            for value in values:
                injected_body = baseline_body_obj.copy()
                injected_body[key] = value
                injected_body_str = json.dumps(injected_body)

                attack_url, attack_response = self._send_request(method, api_base_url, base_path, path, injected_body_str)

                if self._is_mass_assignment_confirmed(baseline_response, attack_response, key, value):
                    result = {
                        "method": method.upper(),
                        "url_template": path,
                        "injected_property": key,
                        "request_body": injected_body_str,
                        "status_code": attack_response.status_code,
                        "vulnerable": True
                    }
                    bopla_results.append(result)
                    break

    def _resolve_schema_ref(self, schema, swagger_spec):
        return resolve_ref(schema, swagger_spec)

    def _find_bopla_targets(self, swagger_spec):
        targets = []
        for path, raw_methods in swagger_spec.get('paths', {}).items():
            if not isinstance(raw_methods, dict):
                continue
            methods = resolve_ref(raw_methods, swagger_spec)
            if not isinstance(methods, dict):
                continue
            path_params = methods.get('parameters', [])
            for method, details in methods.items():
                if method.lower() not in HTTP_METHODS or not isinstance(details, dict):
                    continue
                if method.lower() not in ['post', 'put', 'patch']:
                    continue

                schema = None
                if 'requestBody' in details and isinstance(details['requestBody'], dict):
                    rb = resolve_ref(details['requestBody'], swagger_spec)
                    content = rb.get('content', {}) if isinstance(rb, dict) else {}
                    if isinstance(content, dict):
                        for ct, media_obj in content.items():
                            if (ct == 'application/json' or '+json' in ct.lower()) and isinstance(media_obj, dict):
                                raw_schema = media_obj.get('schema', {})
                                if raw_schema:
                                    schema = self._resolve_schema_ref(raw_schema, swagger_spec)
                                    break
                else:
                    merged_params = merge_parameters(path_params, details.get('parameters', []), swagger_spec)
                    for param in merged_params:
                        if param.get('in') == 'body' and isinstance(param.get('schema'), dict):
                            schema = self._resolve_schema_ref(param['schema'], swagger_spec)
                            break

                if schema:
                    targets.append({'path': path, 'method': method, 'schema': schema})
        return targets

    def _send_request(self, method, api_base_url, base_path, path_template, body):
        substituted_template = path_template
        if self.bola_param and self.bola_id is not None:
            substituted_template = substituted_template.replace(f"{{{self.bola_param}}}", str(self.bola_id))
        substituted_template = re.sub(r"\{[^{}]+\}", "1", substituted_template)

        full_path = join_base_and_path(base_path, substituted_template)
        full_url = build_full_url(api_base_url, full_path)

        headers = {'Content-Type': 'application/json'}
        if api_base_url and not is_same_origin_host(api_base_url, full_url):
            if not getattr(self.args, "allow_external", False):
                if getattr(self.args, "verbose", False):
                    log(f"BOPLA: Blocked cross-origin request to {full_url}", level="WARNING")
                return full_url, None
            headers = build_cross_origin_safe_headers(self.session, headers)

        try:
            if self.args.verbose:
                log(f"BOPLA: Sending {method.upper()} request to {full_url} with injected body", level="DEBUG")
            get_rate_limiter(self.args).wait()
            with self._lock:
                self.TOTAL_REQUESTS += 1
            response = self.session.request(method.lower(), full_url, headers=headers, data=body, allow_redirects=False, timeout=self.TIMEOUT)

            log_level = "SUCCESS" if 200 <= response.status_code < 300 else "DEBUG"
            if self.args.verbose:
                log(f"BOPLA: Received status {response.status_code} from {full_url}", level=log_level)

            return full_url, response
        except requests.exceptions.RequestException as e:
            if self.args.verbose:
                log(f"BOPLA request to {full_url} failed: {e}", level="DEBUG")
            return full_url, None
