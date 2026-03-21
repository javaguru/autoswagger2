# autoswagger2/analysis/bfla.py
# Manages BFLA (Broken Function Level Authorization) testing.

import requests
import json
from urllib.parse import urljoin
from ..utils.helpers import log
from ..core.requester import Requester

BFLA_KEYWORDS = ['admin', 'management', 'internal', 'debug', 'config', 'mock', 'test', 'admintest']

class BflaTester:
    def __init__(self, args, session, bola_param=None, bola_id=None):
        self.args = args
        self.session = session
        self.bola_param = bola_param
        self.bola_id = bola_id
        self.TIMEOUT = 10

    def run_tests(self, swagger_spec, api_base_url, base_path):
        bfla_results = []
        target_endpoints = self._find_bfla_targets(swagger_spec)

        if not target_endpoints:
            if not self.args.product:
                log("BFLA: No potential admin endpoints found to test.", level="INFO")
            return bfla_results

        requester = Requester(api_base_url, self.args, self.session)

        for endpoint in target_endpoints:
            path = endpoint['path']
            method = endpoint['method']
            parameters = endpoint['parameters']
            schema = endpoint['schema']

            if not self.args.product:
                log(f"BFLA: Testing endpoint {method.upper()} {path}", level="INFO")

            request_body = None
            if method.lower() in ['post', 'put', 'patch'] and schema:
                request_body = requester._build_request_body(schema, 'application/json')

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
        for path, methods in swagger_spec.get('paths', {}).items():
            if any(keyword in path.lower() for keyword in BFLA_KEYWORDS):
                for method, details in methods.items():
                    schema = None
                    if 'requestBody' in details:
                        content = details['requestBody'].get('content', {})
                        if 'application/json' in content:
                            schema = content['application/json'].get('schema', {})

                    targets.append({
                        'path': path,
                        'method': method,
                        'parameters': details.get('parameters', []),
                        'schema': schema
                    })
        return targets

    def _send_request(self, method, api_base_url, base_path, path_template, parameters, body=None):

        path_with_params_substituted = path_template

        # Substitute path parameters
        for param in parameters:
            if param.get('in') == 'path':
                param_name = param.get('name')
                # Use the provided bola_id if the parameter name matches
                if self.bola_param and self.bola_id and param_name == self.bola_param:
                    value = self.bola_id
                else:
                    value = "1" # Default value for other params

                path_with_params_substituted = path_with_params_substituted.replace(f"{{{param_name}}}", value)

        full_path = base_path + path_with_params_substituted
        full_url = urljoin(api_base_url, full_path)

        headers = {'Content-Type': 'application/json'} if body else {}

        try:
            if self.args.verbose:
                log(f"BFLA: Sending {method.upper()} request to {full_url}", level="DEBUG")
            response = self.session.request(method.lower(), full_url, headers=headers, data=body, timeout=self.TIMEOUT)
            if self.args.verbose:
                log(f"BFLA: Received status {response.status_code} from {full_url}", level="DEBUG")
            return full_url, response
        except requests.exceptions.RequestException as e:
            if self.args.verbose:
                log(f"BFLA request to {full_url} failed: {e}", level="DEBUG")
            return full_url, None

    def _analyze_response(self, response):
        # If we get a successful status code (2xx), it's a strong indicator of BFLA.
        if 200 <= response.status_code < 300:
            return True
        return False
