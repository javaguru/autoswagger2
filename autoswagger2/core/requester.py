# autoswagger2/core/requester.py
# Manages the construction and sending of HTTP requests.

import requests
import json
import time
import re
from itertools import product as itertools_product
from urllib.parse import urljoin, urlencode
from dicttoxml import dicttoxml
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

from ..utils.config import TEST_VALUES
from ..analysis.secrets import detect_sensitive_info
from ..analysis.pii import PiiAnalyzer
from ..utils.helpers import log
from ..utils.validators import ResultValidator
from ..analysis.parameter_analysis import ParameterAnalyzer

from ..discovery.openapi_parser import OpenAPIParser

class Requester:
    def __init__(self, api_base_url, args, session):
        self.api_base_url = api_base_url
        self.args = args
        self.session = session
        self.pii_analyzer = PiiAnalyzer()
        self.validator = ResultValidator()
        self.param_analyzer = ParameterAnalyzer()
        self.TIMEOUT = 10
        self.TOTAL_REQUESTS = 0

    def test_endpoints(self, swagger_spec, base_path):
        all_results = []
        max_workers = min(100, os.cpu_count() * 5)

        parser = OpenAPIParser(swagger_spec, getattr(self.args, 'openapi_version', None))
        openapi_version = parser.version

        if not self.args.product:
            log(f"Detected OpenAPI version: {parser.raw_version}", level="INFO")

        endpoints = parser.extract_all_endpoints()
        webhooks_count = sum(1 for ep in endpoints if ep.get('type') == 'webhook')
        if webhooks_count > 0 and not self.args.product:
            log(f"Found {webhooks_count} webhooks to test", level="INFO")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_endpoint = {}

            for ep in endpoints:
                path = ep['path']
                mthd = ep['method']
                operation = ep['operation']
                ep_type = ep.get('type', 'endpoint')

                if mthd.upper() != 'GET' and not self.args.risk:
                    continue

                parameters = operation.get('parameters', [])

                if 'requestBody' in operation:
                    rb_content = operation['requestBody'].get('content', {})
                    for ct, content_details in rb_content.items():
                        schema = content_details.get('schema', {})
                        request_body = self._build_request_body(schema, ct)

                        if ep_type == 'webhook':
                            webhook_name = ep.get('webhook_name', 'unknown')
                            fut = executor.submit(self._test_webhook, path, mthd, parameters, base_path, request_body, ct, webhook_name)
                            future_to_endpoint[fut] = (mthd, f"[WEBHOOK] {path}", ct)
                        else:
                            fut = executor.submit(self._test_endpoint, path, mthd, parameters, base_path, request_body, ct)
                            future_to_endpoint[fut] = (mthd, path, ct)
                else:
                    if ep_type == 'webhook':
                        webhook_name = ep.get('webhook_name', 'unknown')
                        fut = executor.submit(self._test_webhook, path, mthd, parameters, base_path, None, None, webhook_name)
                        future_to_endpoint[fut] = (mthd, f"[WEBHOOK] {path}", None)
                    else:
                        fut = executor.submit(self._test_endpoint, path, mthd, parameters, base_path, None, None)
                        future_to_endpoint[fut] = (mthd, path, None)

            #  Collect results
            for future in as_completed(future_to_endpoint):
                try:
                    endpoint_results = future.result()
                    if endpoint_results:
                        all_results.extend(endpoint_results)
                except Exception as exc:
                    if self.args.verbose:
                        log(f"Endpoint generated an exception: {exc}", level="DEBUG")

        return all_results

    def _test_webhook(self, expression, method, parameters, base_path, request_body=None, content_type=None, webhook_name=None):
        """Test webhook endpoint (OpenAPI 3.1)"""
        # Webhooks use Runtime Expressions in OpenAPI 3.1
        # Skip unresolved variables like {$request.body#/callbackUrl}
        if expression.startswith('{$'):
            if self.args.verbose:
                log(f"Skipping webhook '{webhook_name}' - unresolved runtime expression: {expression}", level="WARNING")
            return []

        # If it's a full URL, use it directly. Otherwise, assume it's relative to base_path.
        if expression.startswith('http://') or expression.startswith('https://'):
            full_path = expression
            base_url_no_path = "" # full_path already has the domain
        else:
            full_path = base_path + expression
            base_url_no_path = self.api_base_url

        if not self.args.product:
            log(f"Testing webhook '{webhook_name}': {method.upper()} {expression}", level="INFO")

        return self._test_parameter_values(method, base_url_no_path, full_path, parameters, request_body, content_type)

    def _test_endpoint(self, path_template, method, parameters, base_path, request_body=None, content_type=None):
        full_path = base_path + path_template
        return self._test_parameter_values(method, self.api_base_url, full_path, parameters, request_body, content_type)

    def _test_parameter_values(self, method, base_url_no_path, full_path, parameters, request_body, content_type):
        all_responses = []
        value_mapping = {}

        param_info = []
        for param in parameters:
            if param.get('in') in ['path', 'query']:
                param_name = param.get('name')
                schema = param.get('schema', {})
                param_type = param.get('type') or schema.get('type', 'string')
                enum = param.get('enum', None)
                param_info.append({'name': param_name, 'type': param_type, 'enum': enum})

        if not self.args.brute:
            for p_info in param_info:
                values = self._generate_parameter_values(p_info['type'], p_info['enum'])
                value_mapping[p_info['name']] = values[0]

            response = self._send_request(method, base_url_no_path, full_path, parameters, value_mapping, request_body, content_type)
            if response:
                all_responses.append(response)
        else:
            param_value_lists = [self._generate_parameter_values(p['type'], p['enum']) for p in param_info]

            if not param_value_lists:
                 response = self._send_request(method, base_url_no_path, full_path, parameters, {}, request_body, content_type)
                 if response:
                    all_responses.append(response)
            else:
                value_combinations = itertools_product(*param_value_lists)
                for combo in value_combinations:
                    current_value_mapping = {p_info['name']: combo[i] for i, p_info in enumerate(param_info)}
                    response = self._send_request(method, base_url_no_path, full_path, parameters, current_value_mapping, request_body, content_type)
                    if response:
                        all_responses.append(response)

        return all_responses

    def _send_request(self, method, base_url_no_path, full_path, parameters, value_mapping, request_body, content_type):
        self.TOTAL_REQUESTS += 1
        sensitive_params = self.param_analyzer.analyze_parameters(parameters)

        substituted_path = self._substitute_path_parameters(full_path, parameters, value_mapping)
        query_string = self._generate_query_string(parameters, value_mapping)

        if not substituted_path.startswith('/'):
            substituted_path = '/' + substituted_path

        full_url = f"{urljoin(base_url_no_path, substituted_path)}"
        if query_string:
            full_url += f"?{query_string}"

        headers = {'Content-Type': content_type} if content_type else {}
        data = request_body if method.upper() in ['POST', 'PUT', 'PATCH'] else None

        files_payload = None
        data_payload = data
        if content_type == 'multipart/form-data':
            headers.pop('Content-Type', None)
            files_payload = data
            data_payload = None

        max_retries = 3
        response = None
        for attempt in range(max_retries):
            try:
                if self.args.rate > 0:
                    time.sleep(1.0 / self.args.rate)

                response = self.session.request(
                    method, full_url, headers=headers, data=data_payload, files=files_payload,
                    allow_redirects=False, timeout=self.TIMEOUT
                )
                break  # Success, exit retry loop

            except requests.Timeout:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    if self.args.verbose:
                        log(f"Timeout on {method.upper()} {full_url}, retry in {wait_time}s", level="WARNING")
                    time.sleep(wait_time)
                else:
                    if self.args.verbose:
                        log(f"Max retries reached for {method.upper()} {full_url} due to timeout.", level="DEBUG")
                    return None
            except requests.ConnectionError as e:
                if self.args.verbose:
                    log(f"Connection error on {method.upper()} {full_url}: {e}", level="DEBUG")
                return None
            except requests.exceptions.RequestException as e:
                if self.args.verbose:
                    log(f"Error testing {method.upper()} {full_url}: {e}", level="DEBUG")
                return None

        if response is None:
            return None
        status_code = response.status_code

        if status_code in [401, 403] and not self.args.all:
            if self.args.verbose:
                log(f"Skipping endpoint {method.upper()} {full_url} due to status code {status_code}", level="INFO")
            return None

        content_type_header = response.headers.get('Content-Type', '').lower()
        is_binary = any(b in content_type_header for b in ['image', 'octet-stream', 'pdf', 'zip', 'binary', 'download'])
        is_text_based = any(t in content_type_header for t in ['json', 'text', 'xml', 'html', 'javascript', 'yaml']) and not is_binary

        content_text = ''
        pii_detected = False
        pii_data = {}
        sensitive_info = None
        regex_patterns = {}
        debug_info_only = False

        if is_text_based and response.content:
            try:
                content_text = response.content.decode('utf-8', errors='ignore')

                sensitive_info, regex_patterns = detect_sensitive_info(content_text)

                is_short_error = status_code >= 400 and len(content_text) < 150 and sensitive_info and 'Debug Information' in sensitive_info

                if not is_short_error:
                    pii_detected, pii_data = self.pii_analyzer.analyze_content(content_text)
                else:
                    debug_info_only = True

            except Exception:
                pass

        result = self._build_result(method, full_url, full_path, data, status_code, len(response.content), pii_detected, pii_data, sensitive_info, regex_patterns, content_text, response.headers, debug_info_only, sensitive_params)

        if self.args.verbose:
            log(f"{method.upper()} {full_url} returned {status_code}", level="SUCCESS" if status_code == 200 else "WARNING")

        return result

    def _build_result(self, method, url, path_template, data, status_code, content_length, pii_detected, pii_data, sensitive_info, regex_patterns, content_text, response_headers, debug_info_only=False, sensitive_params=None):
        body_for_output = ""
        if data:
            if isinstance(data, bytes):
                try:
                    body_for_output = data.decode('utf-8')
                except UnicodeDecodeError:
                    body_for_output = f"<binary data of length {len(data)} bytes>"
            else:
                body_for_output = str(data)

        result = {
            "method": method.upper(), "url": url, "path_template": path_template, "body": body_for_output,
            "status_code": status_code, "content_length": content_length, "pii_detected": pii_detected,
            "pii_data": None, "pii_detection_details": None, "debug_info_detected": False,
            "interesting_response": False, "regex_patterns_found": regex_patterns or {},
            "response_body": content_text,
            "response_headers": dict(response_headers),
            "sensitive_parameters": sensitive_params or []
        }

        if sensitive_info:
            debug_info = sensitive_info.pop('Debug Information', None)
            if debug_info:
                result['debug_info_detected'] = True
            if sensitive_info and not debug_info_only:
                result['pii_detected'] = True
                for key, values in sensitive_info.items():
                    pii_data.setdefault(key, {'values': set(), 'detection_methods': set()})['values'].update(values)
                    pii_data[key]['detection_methods'].add('regex')

        if pii_data and not debug_info_only:
            norm_data, norm_details = self.validator.validate_finding(pii_data)
            if norm_data:
                result['pii_detected'] = True
                result["pii_data"] = norm_data
                result["pii_detection_details"] = norm_details
            else:
                result['pii_detected'] = False

        result['interesting_response'] = (result['pii_detected'] or result['debug_info_detected'] or bool(result['sensitive_parameters']) or self._is_large_response(content_text))
        return result

    def _generate_parameter_values(self, param_type, enum=None):
        if enum:
            return enum
        return TEST_VALUES.get(param_type, TEST_VALUES["default"])

    def _substitute_path_parameters(self, path, parameters, value_mapping):
        for param in parameters:
            if param.get('in') == 'path':
                param_name = param.get('name')
                value = value_mapping.get(param_name)
                if value is not None:
                    path = re.sub(rf'{{{param_name}}}|:{param_name}|<{param_name}>', str(value), path)
        return path

    def _generate_query_string(self, parameters, value_mapping):
        query_params = {}
        for param in parameters:
            if param.get('in') == 'query':
                param_name = param.get('name')
                value = value_mapping.get(param_name)
                if value is not None:
                    query_params[param_name] = value
        return urlencode(query_params)

    def _is_large_response(self, content):
        try:
            if content.strip().startswith(('{', '[')):
                data = json.loads(content)
                if isinstance(data, list) and len(data) >= 100: return True
                if isinstance(data, dict) and len(data.keys()) >= 100: return True
            elif content.strip().startswith('<'):
                if content.count('<') > 100: return True
        except (json.JSONDecodeError, AttributeError):
            pass
        return False

    def _build_request_body(self, schema, content_type, value_index=0):
        if not schema:
            return None

        body = None
        if 'properties' in schema or schema.get('type') == 'object':
            body = self._build_nested_object(schema, value_index)
        elif 'oneOf' in schema or 'anyOf' in schema or 'allOf' in schema:
            body = self._handle_composite_schemas(schema, value_index)
        elif schema.get('type') == 'array':
            item_schema = schema.get('items', {})
            body = [self._build_array_item(item_schema, value_index)]
        else:
            param_type = schema.get('type', 'string')
            enum = schema.get('enum', None)
            values = self._generate_parameter_values(param_type, enum)
            body = values[value_index % len(values)]

        if content_type == 'application/x-www-form-urlencoded':
            return urlencode(body) if isinstance(body, dict) else body
        elif content_type == 'application/xml':
            return dicttoxml(body).decode() if isinstance(body, dict) else str(body)
        elif content_type == 'application/json':
            return json.dumps(body)
        elif content_type == 'text/plain':
            return str(body)
        elif content_type == 'application/octet-stream':
            return b'\x00\x01\x02'
        elif content_type == 'multipart/form-data':
            return self._build_file_upload_body(schema, content_type, value_index)

        return json.dumps(body)

    def _build_nested_object(self, schema, value_index=0):
        obj = {}
        for key, prop in schema.get('properties', {}).items():
            if '$ref' in prop:
                continue
            if 'oneOf' in prop or 'anyOf' in prop or 'allOf' in prop:
                obj[key] = self._handle_composite_schemas(prop, value_index)
            elif prop.get('type') == 'object':
                obj[key] = self._build_nested_object(prop, value_index)
            elif prop.get('type') == 'array':
                obj[key] = self._build_array_item(prop, value_index)
            else:
                param_type = prop.get('type', 'string')
                enum = prop.get('enum', None)
                values = self._generate_parameter_values(param_type, enum)
                obj[key] = values[value_index % len(values)]
        return obj

    def _handle_composite_schemas(self, schema, value_index=0):
        if 'oneOf' in schema:
            return self._build_nested_object(schema['oneOf'][value_index % len(schema['oneOf'])], value_index)
        elif 'anyOf' in schema:
            return self._build_nested_object(schema['anyOf'][value_index % len(schema['anyOf'])], value_index)
        elif 'allOf' in schema:
            combined_schema = {}
            for sub_schema in schema['allOf']:
                combined_schema.update(sub_schema.get('properties', {}))
            return self._build_nested_object({'properties': combined_schema}, value_index)
        return self._build_nested_object(schema, value_index)

    def _build_array_item(self, item_schema, value_index=0):
        if 'properties' in item_schema or item_schema.get('type') == 'object':
            return self._build_nested_object(item_schema, value_index)
        else:
            param_type = item_schema.get('type', 'string')
            enum = item_schema.get('enum', None)
            values = self._generate_parameter_values(param_type, enum)
            return values[value_index % len(values)]

    def _build_file_upload_body(self, schema, content_type, value_index=0):
        if content_type == 'multipart/form-data':
            return {'file': ('test.txt', b'This is a test file')}
        return None
