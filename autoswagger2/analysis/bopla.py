# autoswagger2/analysis/bopla.py
# Manages BOPLA (Broken Object Property Level Authorization) testing.

import requests
import json
from urllib.parse import urljoin
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from ..utils.helpers import log, console
from ..utils.config import BOPLA_SENSITIVE_KEYS
from ..core.requester import Requester

class BoplaTester:
    def __init__(self, args, session):
        self.args = args
        self.session = session
        self.TIMEOUT = 10

    def run_tests(self, swagger_spec, api_base_url, base_path):
        bopla_results = []
        target_endpoints = self._find_bopla_targets(swagger_spec)

        if not target_endpoints:
            if not self.args.product:
                log("BOPLA: No potential endpoints found to test (POST/PUT/PATCH with JSON body).", level="INFO")
            return bopla_results

        if self.args.product:
            # In product mode, just loop without the progress bar
            for endpoint in target_endpoints:
                self._test_endpoint(endpoint, api_base_url, base_path, bopla_results)
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
                    self._test_endpoint(endpoint, api_base_url, base_path, bopla_results)
                    progress.update(task, advance=1)

        return bopla_results

    def _test_endpoint(self, endpoint, api_base_url, base_path, bopla_results):
        path = endpoint['path']
        method = endpoint['method']
        schema = endpoint['schema']

        if not self.args.product:
            log(f"BOPLA: Testing endpoint {method.upper()} {path}", level="INFO")

        # Build a valid baseline request body
        requester = Requester(api_base_url, self.args, self.session)
        baseline_body_str = requester._build_request_body(schema, 'application/json')
        if not baseline_body_str:
            return

        try:
            baseline_body_obj = json.loads(baseline_body_str)
            # Ensure we are working with a dictionary to inject properties
            if not isinstance(baseline_body_obj, dict):
                return
        except (json.JSONDecodeError, TypeError):
            return

        for key, values in BOPLA_SENSITIVE_KEYS.items():
            for value in values:
                injected_body = baseline_body_obj.copy()
                injected_body[key] = value
                injected_body_str = json.dumps(injected_body)

                attack_url, attack_response = self._send_request(method, api_base_url, base_path, path, injected_body_str)

                if attack_response and 200 <= attack_response.status_code < 300:
                    result = {
                        "method": method.upper(),
                        "url_template": path,
                        "request_body": injected_body_str,
                        "status_code": attack_response.status_code,
                        "vulnerable": True
                    }
                    bopla_results.append(result)

    def _resolve_schema_ref(self, schema, swagger_spec):
        if '$ref' in schema:
            ref_path = schema['$ref'].split('/')
            ref_schema = swagger_spec
            for part in ref_path[1:]: # Skip the '#'
                ref_schema = ref_schema.get(part, {})
            return ref_schema
        return schema

    def _find_bopla_targets(self, swagger_spec):
        targets = []
        for path, methods in swagger_spec.get('paths', {}).items():
            for method, details in methods.items():
                if method.lower() in ['post', 'put', 'patch']:
                    if 'requestBody' in details:
                        content = details['requestBody'].get('content', {})
                        if 'application/json' in content:
                            schema = content['application/json'].get('schema', {})
                            if schema:
                                resolved_schema = self._resolve_schema_ref(schema, swagger_spec)
                                targets.append({'path': path, 'method': method, 'schema': resolved_schema})
        return targets

    def _send_request(self, method, api_base_url, base_path, path_template, body):
        full_path = base_path + path_template
        full_url = urljoin(api_base_url, full_path)

        headers = {'Content-Type': 'application/json'}

        try:
            if self.args.verbose:
                log(f"BOPLA: Sending {method.upper()} request to {full_url} with injected body", level="DEBUG")
            response = self.session.request(method.lower(), full_url, headers=headers, data=body, timeout=self.TIMEOUT)

            log_level = "SUCCESS" if 200 <= response.status_code < 300 else "DEBUG"
            if self.args.verbose:
                log(f"BOPLA: Received status {response.status_code} from {full_url}", level=log_level)

            return full_url, response
        except requests.exceptions.RequestException as e:
            if self.args.verbose:
                log(f"BOPLA request to {full_url} failed: {e}", level="DEBUG")
            return full_url, None
