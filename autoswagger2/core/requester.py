# autoswagger2/core/requester.py
# Manages the construction and sending of HTTP requests.

import requests
import json
import threading
import time
import re
from urllib.parse import urlencode
from dicttoxml import dicttoxml
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

from ..utils.config import TEST_VALUES
from ..utils.rate_limiter import get_rate_limiter
from ..analysis.secrets import detect_sensitive_info
from ..analysis.pii import PiiAnalyzer
from ..utils.helpers import (
    log,
    is_quiet_output,
    join_base_and_path,
    build_full_url,
    is_same_origin_host,
    build_cross_origin_safe_headers,
)
from ..utils.validators import ResultValidator
from ..analysis.parameter_analysis import ParameterAnalyzer

from ..discovery.openapi_parser import OpenAPIParser, resolve_ref, normalize_schema_type

class Requester:
    def __init__(self, api_base_url, args, session):
        self.api_base_url = api_base_url
        self.auth_origin = api_base_url
        self.args = args
        self.session = session
        self.pii_analyzer = PiiAnalyzer()
        self.validator = ResultValidator()
        self.param_analyzer = ParameterAnalyzer()
        self.TIMEOUT = 10
        self._lock = threading.Lock()
        self.TOTAL_REQUESTS = 0
        self.max_workers = None
        self._current_spec = {}

    def _resolve_max_workers(self, endpoint_count):
        if endpoint_count <= 0:
            return 1
        override = getattr(self, "max_workers", None)
        if not isinstance(override, bool) and isinstance(override, int) and override >= 1:
            workers = override
        else:
            raw_threads = getattr(self.args, "threads", 20)
            if not isinstance(raw_threads, bool) and isinstance(raw_threads, int) and raw_threads >= 1:
                workers = raw_threads
            else:
                workers = 20
        return max(1, min(100, workers, endpoint_count))

    def test_endpoints(self, swagger_spec, base_path):
        all_results = []
        self._current_spec = swagger_spec if isinstance(swagger_spec, dict) else {}

        parser = OpenAPIParser(swagger_spec, getattr(self.args, 'openapi_version', None))

        if not is_quiet_output(self.args):
            log(f"Detected OpenAPI version: {parser.raw_version}", level="INFO")

        endpoints = parser.extract_all_endpoints()
        max_workers = self._resolve_max_workers(len(endpoints))
        webhooks_count = sum(1 for ep in endpoints if ep.get('type') == 'webhook')
        if webhooks_count > 0 and not is_quiet_output(self.args):
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

                parameters = ep.get('parameters') if 'parameters' in ep else parser.parse_parameters(operation)
                parsed_bodies = ep.get('request_bodies') if 'request_bodies' in ep else parser.parse_request_body(operation)

                if parsed_bodies:
                    for ct, content_details in parsed_bodies.items():
                        schema = content_details.get('schema', {})
                        request_body = self._build_request_body(schema, ct, spec_data=self._current_spec)

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

        # If it's a full URL, enforce origin policy and use it directly.
        if expression.lower().startswith(('http://', 'https://')):
            if self.api_base_url and not is_same_origin_host(self.api_base_url, expression):
                if not getattr(self.args, 'allow_external', False):
                    if self.args.verbose:
                        log(f"Skipping external webhook '{webhook_name}': {expression}", level="WARNING")
                    return []
            full_path = expression
            base_url_no_path = "" # full_path already has the domain
        else:
            full_path = join_base_and_path(base_path, expression)
            base_url_no_path = self.api_base_url

        if not is_quiet_output(self.args):
            log(f"Testing webhook '{webhook_name}': {method.upper()} {expression}", level="INFO")

        return self._test_parameter_values(method, base_url_no_path, full_path, parameters, request_body, content_type)

    def _test_endpoint(self, path_template, method, parameters, base_path, request_body=None, content_type=None):
        full_path = join_base_and_path(base_path, path_template)
        return self._test_parameter_values(method, self.api_base_url, full_path, parameters, request_body, content_type)

    def _test_parameter_values(self, method, base_url_no_path, full_path, parameters, request_body, content_type):
        all_responses = []
        value_mapping = {}

        spec = getattr(self, '_current_spec', {})
        param_info = []
        for raw_param in parameters:
            if not isinstance(raw_param, dict):
                continue
            param = resolve_ref(raw_param, spec) if '$ref' in raw_param else raw_param
            if not isinstance(param, dict):
                continue
            if param.get('in') in ['path', 'query']:
                param_name = param.get('name')
                schema = param.get('schema', {})
                if isinstance(schema, dict) and '$ref' in schema:
                    schema = resolve_ref(schema, spec)
                if not isinstance(schema, dict):
                    schema = {}
                param_type = normalize_schema_type(param.get('type') or schema.get('type', 'string'))
                enum = param.get('enum') or schema.get('enum')
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
                # One-parameter-at-a-time linear strategy: O(1 + sum(len(V_i) - 1)) instead of O(prod(len(V_i)))
                baseline_mapping = {p_info['name']: param_value_lists[i][0] for i, p_info in enumerate(param_info)}
                response = self._send_request(method, base_url_no_path, full_path, parameters, baseline_mapping, request_body, content_type)
                if response:
                    all_responses.append(response)

                for i, p_info in enumerate(param_info):
                    for val in param_value_lists[i][1:]:
                        current_value_mapping = baseline_mapping.copy()
                        current_value_mapping[p_info['name']] = val
                        response = self._send_request(method, base_url_no_path, full_path, parameters, current_value_mapping, request_body, content_type)
                        if response:
                            all_responses.append(response)

        return all_responses

    def _send_request(self, method, base_url_no_path, full_path, parameters, value_mapping, request_body, content_type):
        sensitive_params = self.param_analyzer.analyze_parameters(parameters)

        substituted_path = self._substitute_path_parameters(full_path, parameters, value_mapping)
        query_string = self._generate_query_string(parameters, value_mapping)

        full_url = build_full_url(base_url_no_path, substituted_path)
        if query_string:
            full_url += f"{'&' if '?' in full_url else '?'}{query_string}"

        headers = {'Content-Type': content_type} if content_type else {}
        data = request_body if method.upper() in ['POST', 'PUT', 'PATCH'] else None

        files_payload = None
        data_payload = data
        if content_type == 'multipart/form-data':
            headers.pop('Content-Type', None)
            files_payload = data
            data_payload = None

        origin_to_check = getattr(self, 'auth_origin', None) or self.api_base_url
        if origin_to_check and not is_same_origin_host(origin_to_check, full_url):
            if not getattr(self.args, 'allow_external', False):
                if getattr(self.args, 'verbose', False):
                    log(f"Blocked cross-origin request to {full_url}", level="WARNING")
                return None
            headers = build_cross_origin_safe_headers(self.session, headers)

        max_retries = 3
        response = None
        for attempt in range(max_retries):
            try:
                get_rate_limiter(self.args).wait()
                with self._lock:
                    self.TOTAL_REQUESTS += 1

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
        vuln_indicators = []

        if is_text_based and response.content:
            try:
                content_text = response.content.decode('utf-8', errors='ignore')

                sensitive_info, regex_patterns = detect_sensitive_info(content_text)
                vuln_indicators = self._detect_response_anomalies(content_text, content_type_header, value_mapping)

                is_short_error = status_code >= 400 and len(content_text) < 150 and sensitive_info and 'Debug Information' in sensitive_info

                if not is_short_error:
                    pii_detected, pii_data = self.pii_analyzer.analyze_content(content_text)
                else:
                    debug_info_only = True

            except Exception:
                pass

        result = self._build_result(
            method, full_url, full_path, data, status_code, len(response.content),
            pii_detected, pii_data, sensitive_info, regex_patterns, content_text,
            response.headers, debug_info_only, sensitive_params, vuln_indicators=vuln_indicators
        )

        if self.args.verbose:
            log(f"{method.upper()} {full_url} returned {status_code}", level="SUCCESS" if status_code == 200 else "WARNING")

        return result

    def _detect_response_anomalies(self, content_text, content_type_header, value_mapping=None):
        """Detect deterministic passive vulnerability indicators (LFI, SQL errors, reflected HTML XSS)."""
        indicators = []
        if not content_text:
            return indicators

        content_lower = content_text.lower()
        if re.search(r'root:[x*]:0:0:', content_text) or ('[extensions]' in content_lower and '[fonts]' in content_lower):
            indicators.append("Potential File Disclosure (LFI)")

        sql_pattern = (
            r'(?:SQL syntax[^\r\n]{0,80}MySQL|'
            r'Warning:\s+mysql_|'
            r'PostgreSQL[^\r\n]{0,40}ERROR|'
            r'ORA-\d{5}|'
            r'SQLite/JDBCDriver|'
            r'sqlite3\.OperationalError|'
            r'Unclosed quotation mark after the character string|'
            r'SQLSTATE\[[0-9A-Z]{5}\])'
        )
        if re.search(sql_pattern, content_text, re.IGNORECASE):
            indicators.append("SQL/Database Error Leak")

        if 'html' in (content_type_header or '').lower() and isinstance(value_mapping, dict):
            for val in value_mapping.values():
                val_str = str(val)
                val_lower = val_str.lower()
                if ('<script' in val_lower or 'onerror=' in val_lower) and val_str in content_text:
                    indicators.append("Reflected HTML/XSS Indicator")
                    break

        return indicators

    def _build_result(self, method, url, path_template, data, status_code, content_length, pii_detected, pii_data, sensitive_info, regex_patterns, content_text, response_headers, debug_info_only=False, sensitive_params=None, vuln_indicators=None):
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
            "sensitive_parameters": sensitive_params or [],
            "vuln_indicators": vuln_indicators or []
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

        result['interesting_response'] = (
            result['pii_detected']
            or result['debug_info_detected']
            or bool(result['sensitive_parameters'])
            or bool(result['vuln_indicators'])
            or self._is_large_response(content_text)
        )
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
                    path = re.sub(rf'{{{param_name}}}|:{param_name}|<{param_name}>', lambda m: str(value), path)
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

    def _build_request_body(self, schema, content_type, value_index=0, spec_data=None):
        if not schema or not isinstance(schema, dict):
            return None

        spec = spec_data if spec_data is not None else getattr(self, '_current_spec', {})
        seen = frozenset({schema['$ref']}) if isinstance(schema.get('$ref'), str) else frozenset()
        if '$ref' in schema:
            schema = resolve_ref(schema, spec)
        if not schema or not isinstance(schema, dict):
            return None

        schema_type = normalize_schema_type(schema.get('type', '')) if 'type' in schema else ''
        if 'oneOf' in schema or 'anyOf' in schema or 'allOf' in schema:
            body = self._handle_composite_schemas(schema, value_index, seen, 0, spec)
        elif 'properties' in schema or schema_type == 'object':
            body = self._build_nested_object(schema, value_index, seen, 0, spec)
        elif schema_type == 'array':
            item_schema = schema.get('items', {})
            if isinstance(item_schema, dict) and isinstance(item_schema.get('$ref'), str) and item_schema['$ref'] in seen:
                body = []
            else:
                body = [self._build_array_item(item_schema, value_index, seen, 1, spec)]
        else:
            param_type = normalize_schema_type(schema.get('type', 'string'))
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

    def _build_nested_object(self, schema, value_index=0, _seen=frozenset(), _depth=0, spec_data=None):
        if not isinstance(schema, dict) or _depth > 6:
            return {}
        spec = spec_data if spec_data is not None else getattr(self, '_current_spec', {})
        if isinstance(schema.get('$ref'), str):
            ref_str = schema['$ref']
            if ref_str in _seen:
                return {}
            schema = resolve_ref(schema, spec, _seen)
            _seen = _seen | {ref_str}
            if not isinstance(schema, dict):
                return {}

        if ('oneOf' in schema or 'anyOf' in schema or 'allOf' in schema) and 'properties' not in schema:
            return self._handle_composite_schemas(schema, value_index, _seen, _depth, spec)

        obj = {}
        for key, prop in schema.get('properties', {}).items():
            if not isinstance(prop, dict):
                continue
            prop_seen = _seen
            if '$ref' in prop:
                ref_str = prop['$ref']
                if not isinstance(ref_str, str) or ref_str in prop_seen:
                    continue
                prop = resolve_ref(prop, spec, prop_seen)
                if not isinstance(prop, dict) or not prop:
                    continue
                prop_seen = prop_seen | {ref_str}

            prop_type = normalize_schema_type(prop.get('type', '')) if 'type' in prop else ''
            if 'oneOf' in prop or 'anyOf' in prop or 'allOf' in prop:
                obj[key] = self._handle_composite_schemas(prop, value_index, prop_seen, _depth + 1, spec)
            elif prop_type == 'object' or 'properties' in prop:
                obj[key] = self._build_nested_object(prop, value_index, prop_seen, _depth + 1, spec)
            elif prop_type == 'array':
                items_schema = prop.get('items', {})
                if isinstance(items_schema, dict) and isinstance(items_schema.get('$ref'), str) and items_schema['$ref'] in prop_seen:
                    obj[key] = []
                else:
                    obj[key] = [self._build_array_item(items_schema, value_index, prop_seen, _depth + 1, spec)]
            else:
                param_type = normalize_schema_type(prop.get('type', 'string'))
                enum = prop.get('enum', None)
                values = self._generate_parameter_values(param_type, enum)
                obj[key] = values[value_index % len(values)]
        return obj

    def _collect_allof_properties(self, sub_schemas, spec, seen, depth):
        combined_props = {}
        if depth > 6:
            return combined_props
        for sub_schema in sub_schemas:
            if not isinstance(sub_schema, dict):
                continue
            sub_seen = seen
            if isinstance(sub_schema.get('$ref'), str):
                ref_str = sub_schema['$ref']
                if ref_str in sub_seen:
                    continue
                sub_schema = resolve_ref(sub_schema, spec, sub_seen)
                sub_seen = sub_seen | {ref_str}
                if not isinstance(sub_schema, dict):
                    continue
            if 'allOf' in sub_schema and isinstance(sub_schema['allOf'], list):
                combined_props.update(self._collect_allof_properties(sub_schema['allOf'], spec, sub_seen, depth + 1))
            if isinstance(sub_schema.get('properties'), dict):
                combined_props.update(sub_schema['properties'])
        return combined_props

    def _handle_composite_schemas(self, schema, value_index=0, _seen=frozenset(), _depth=0, spec_data=None):
        if not isinstance(schema, dict) or _depth > 6:
            return {}
        spec = spec_data if spec_data is not None else getattr(self, '_current_spec', {})
        if isinstance(schema.get('$ref'), str):
            ref_str = schema['$ref']
            if ref_str in _seen:
                return {}
            schema = resolve_ref(schema, spec, _seen)
            _seen = _seen | {ref_str}
            if not isinstance(schema, dict):
                return {}

        if 'oneOf' in schema and schema['oneOf']:
            selected = schema['oneOf'][value_index % len(schema['oneOf'])]
            return self._build_nested_object(selected, value_index, _seen, _depth + 1, spec)
        elif 'anyOf' in schema and schema['anyOf']:
            selected = schema['anyOf'][value_index % len(schema['anyOf'])]
            return self._build_nested_object(selected, value_index, _seen, _depth + 1, spec)
        elif 'allOf' in schema and isinstance(schema['allOf'], list):
            combined_props = self._collect_allof_properties(schema['allOf'], spec, _seen, _depth + 1)
            return self._build_nested_object({'properties': combined_props}, value_index, _seen, _depth + 1, spec)
        return self._build_nested_object(schema, value_index, _seen, _depth + 1, spec)

    def _build_array_item(self, item_schema, value_index=0, _seen=frozenset(), _depth=0, spec_data=None):
        if not isinstance(item_schema, dict) or _depth > 6:
            return "test"
        spec = spec_data if spec_data is not None else getattr(self, '_current_spec', {})
        if isinstance(item_schema.get('$ref'), str):
            ref_str = item_schema['$ref']
            if ref_str in _seen:
                return {}
            item_schema = resolve_ref(item_schema, spec, _seen)
            _seen = _seen | {ref_str}
            if not isinstance(item_schema, dict):
                return {}

        item_type = normalize_schema_type(item_schema.get('type', '')) if 'type' in item_schema else ''
        if 'oneOf' in item_schema or 'anyOf' in item_schema or 'allOf' in item_schema:
            return self._handle_composite_schemas(item_schema, value_index, _seen, _depth + 1, spec)
        elif 'properties' in item_schema or item_type == 'object':
            return self._build_nested_object(item_schema, value_index, _seen, _depth + 1, spec)
        elif item_type == 'array':
            nested = item_schema.get('items', {})
            return [self._build_array_item(nested, value_index, _seen, _depth + 1, spec)]
        else:
            param_type = normalize_schema_type(item_schema.get('type', 'string'))
            enum = item_schema.get('enum', None)
            values = self._generate_parameter_values(param_type, enum)
            return values[value_index % len(values)]

    def _build_file_upload_body(self, schema, content_type, value_index=0):
        if content_type == 'multipart/form-data':
            return {'file': ('test.txt', b'This is a test file')}
        return None
