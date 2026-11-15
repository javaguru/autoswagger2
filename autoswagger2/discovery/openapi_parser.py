# autoswagger2/discovery/openapi_parser.py
# OpenAPI specifications parser.

from enum import Enum
from typing import Literal
import logging
logger = logging.getLogger(__name__)


def normalize_schema_type(raw_type, default="string"):
    """Normalize OpenAPI 2.0/3.0/3.1 schema type (including 3.1 type arrays)."""
    if isinstance(raw_type, list):
        for candidate in raw_type:
            if isinstance(candidate, str) and candidate and candidate != "null":
                return candidate
        return default
    if isinstance(raw_type, str) and raw_type:
        return raw_type
    return default


def resolve_ref(obj, spec_data, _seen=None):
    """Recursively resolve local JSON Pointer ($ref) references with cycle detection."""
    if not isinstance(obj, dict) or '$ref' not in obj:
        return obj

    ref = obj.get('$ref')
    siblings = {k: v for k, v in obj.items() if k != '$ref'}
    if not isinstance(ref, str) or not ref.startswith('#/') or not isinstance(spec_data, dict):
        return siblings

    seen = frozenset() if _seen is None else _seen
    if ref in seen:
        return siblings

    target = spec_data
    for raw_part in ref[2:].split('/'):
        part = raw_part.replace('~1', '/').replace('~0', '~')
        if isinstance(target, dict) and part in target:
            target = target[part]
        else:
            return siblings

    resolved = resolve_ref(target, spec_data, seen | {ref})
    if not isinstance(resolved, dict):
        return siblings

    if siblings:
        return {**resolved, **siblings}
    return dict(resolved)


def merge_parameters(path_params, op_params, spec_data=None):
    """Merge PathItem and Operation parameters, resolving $ref and overriding on (name, in)."""
    merged = []
    index_by_key = {}

    for raw_list in (path_params, op_params):
        if not isinstance(raw_list, list):
            continue
        for raw_param in raw_list:
            resolved = resolve_ref(raw_param, spec_data) if isinstance(raw_param, dict) else None
            if not isinstance(resolved, dict):
                continue
            if isinstance(resolved.get('schema'), dict) and '$ref' in resolved['schema']:
                resolved = {**resolved, 'schema': resolve_ref(resolved['schema'], spec_data)}
            key = (resolved.get('name'), resolved.get('in'))
            if key in index_by_key and key[0] is not None:
                merged[index_by_key[key]] = resolved
            else:
                index_by_key[key] = len(merged)
                merged.append(resolved)

    return merged


class OpenAPIVersion(Enum):
    SWAGGER_2_0 = "2.0"
    OPENAPI_3_0 = "3.0"
    OPENAPI_3_1 = "3.1"

class OpenAPIParser:
    def __init__(self, spec_data, force_version=None):
        try:
            self.spec_data = spec_data
            if force_version:
                self.raw_version = force_version
            else:
                self.raw_version = self.spec_data.get('openapi') or self.spec_data.get('swagger', 'Unknown')

            self.version = self._detect_version()
        except Exception as e:
            logger.error(f"Failed to initialize OpenAPIParser: {e}")
            raise

    def resolve_ref(self, obj, _seen=None):
        """Resolve a local $ref against this parser's specification data."""
        return resolve_ref(obj, self.spec_data, _seen)

    def _detect_version(self) -> Literal[OpenAPIVersion.SWAGGER_2_0, OpenAPIVersion.OPENAPI_3_0, OpenAPIVersion.OPENAPI_3_1] | None:
        """Detect OpenAPI version from spec"""
        version_to_check = self.raw_version

        if version_to_check == 'Unknown':
            return None
        if version_to_check.startswith('2.0'):
            return OpenAPIVersion.SWAGGER_2_0
        elif version_to_check.startswith('3.0'):
            return OpenAPIVersion.OPENAPI_3_0
        elif version_to_check.startswith('3.1'):
            return OpenAPIVersion.OPENAPI_3_1

        return None

    def extract_all_endpoints(self):
        """Extract all testable endpoints including webhooks"""
        endpoints = []

        # Normal endpoints (all versions)
        endpoints.extend(self._extract_paths())

        # Webhooks (only OpenAPI 3.1)
        if self.version == OpenAPIVersion.OPENAPI_3_1:
            endpoints.extend(self._extract_webhooks())

        return endpoints

    def _extract_paths(self):
        """Extract from paths section"""
        endpoints = []
        paths = self.spec_data.get('paths', {})

        for path, raw_path_item in paths.items():
            if not isinstance(raw_path_item, dict):
                logger.warning(f"Invalid path item for {path}, skipping")
                continue

            path_item = resolve_ref(raw_path_item, self.spec_data)
            if not isinstance(path_item, dict):
                logger.warning(f"Invalid path item for {path}, skipping")
                continue

            for method, operation in path_item.items():
                try:
                    if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'trace']:
                        if not isinstance(operation, dict):
                            logger.warning(f"Invalid operation for {method} {path}, skipping")
                            continue

                        endpoints.append({
                            'path': path,
                            'method': method,
                            'type': 'endpoint',
                            'operation': operation,
                            'parameters': self.parse_parameters(operation, path_item=path_item),
                            'request_bodies': self.parse_request_body(operation, path_item=path_item),
                        })
                except Exception as e:
                    logger.error(f"Error processing {method} {path}: {e}")
                    continue

        return endpoints

    def _extract_webhooks(self):
        """Extract from webhooks section (OpenAPI 3.1 only)"""
        endpoints = []
        webhooks = self.spec_data.get('webhooks', {})

        for webhook_name, webhook_item in webhooks.items():
            if not isinstance(webhook_item, dict):
                continue
            for expression, raw_path_item in webhook_item.items():
                if not isinstance(raw_path_item, dict):
                    continue
                path_item = resolve_ref(raw_path_item, self.spec_data)
                if not isinstance(path_item, dict):
                    continue
                for method, operation in path_item.items():
                    if method.lower() in ['get', 'post', 'put', 'delete', 'patch'] and isinstance(operation, dict):
                        endpoints.append({
                            'path': expression,
                            'method': method,
                            'type': 'webhook',
                            'webhook_name': webhook_name,
                            'operation': operation,
                            'parameters': self.parse_parameters(operation, path_item=path_item),
                            'request_bodies': self.parse_request_body(operation, path_item=path_item),
                            'runtime_expression': True  # Mark as runtime expression
                        })

        return endpoints

    def parse_parameters(self, operation, path_item=None):
        """Parse parameters handling version differences, PathItem merging, and $ref resolution."""
        parameters = []
        path_params = path_item.get('parameters', []) if isinstance(path_item, dict) else []
        op_params = operation.get('parameters', []) if isinstance(operation, dict) else []
        merged = merge_parameters(path_params, op_params, self.spec_data)

        for param in merged:
            schema = resolve_ref(param.get('schema', {}), self.spec_data) if isinstance(param.get('schema'), dict) else {}
            raw_type = param.get('type') or schema.get('type', 'string')
            enum = param.get('enum') or schema.get('enum')

            parsed_param = {
                'name': param.get('name'),
                'in': param.get('in'),
                'required': param.get('required', False),
                'description': param.get('description', ''),
                'type': normalize_schema_type(raw_type),
            }
            if enum is not None:
                parsed_param['enum'] = enum

            # Version-specific parsing
            if self.version != OpenAPIVersion.SWAGGER_2_0 or schema:
                parsed_param['schema'] = schema
                parsed_param['style'] = param.get('style')
                parsed_param['explode'] = param.get('explode')

            parameters.append(parsed_param)

        return parameters

    def parse_request_body(self, operation, consumes=None, path_item=None):
        """Parse OpenAPI 3.x requestBody or Swagger 2.0 body/formData parameters."""
        if not isinstance(operation, dict):
            return None

        if 'requestBody' in operation:
            request_body = resolve_ref(operation.get('requestBody', {}), self.spec_data)
            if not isinstance(request_body, dict) or not request_body:
                return None

            content = request_body.get('content', {})
            parsed_bodies = {}

            for media_type, media_obj in content.items():
                if not isinstance(media_obj, dict):
                    continue
                schema = resolve_ref(media_obj.get('schema', {}), self.spec_data)
                encoding = media_obj.get('encoding', {})  # OpenAPI 3.1
                examples = media_obj.get('examples', {})  # Multiple examples

                parsed_bodies[media_type] = {
                    'schema': schema,
                    'encoding': encoding,
                    'examples': examples,
                    'required': request_body.get('required', False)
                }

            return parsed_bodies or None

        # Swagger 2.0 fallback: in: body / in: formData
        path_params = path_item.get('parameters', []) if isinstance(path_item, dict) else []
        merged = merge_parameters(path_params, operation.get('parameters', []), self.spec_data)
        spec_consumes = self.spec_data.get('consumes') if isinstance(self.spec_data, dict) else None
        consumes_list = operation.get('consumes') or consumes or spec_consumes or ['application/json']

        body_params = [p for p in merged if p.get('in') == 'body']
        if body_params:
            body_param = body_params[0]
            schema = resolve_ref(body_param.get('schema', {}), self.spec_data) if isinstance(body_param.get('schema'), dict) else {}
            return {
                ct: {
                    'schema': schema,
                    'encoding': {},
                    'examples': {},
                    'required': body_param.get('required', False)
                }
                for ct in consumes_list
            }

        form_params = [p for p in merged if p.get('in') == 'formData' and p.get('name')]
        if form_params:
            props = {}
            has_file = False
            for fp in form_params:
                raw_fp_type = fp.get('type', 'string')
                if raw_fp_type == 'file':
                    has_file = True
                prop_entry = {'type': normalize_schema_type(raw_fp_type)}
                if fp.get('enum') is not None:
                    prop_entry['enum'] = fp['enum']
                props[fp['name']] = prop_entry

            if has_file:
                media_type = 'multipart/form-data'
            elif consumes_list and consumes_list[0] in ('application/x-www-form-urlencoded', 'multipart/form-data'):
                media_type = consumes_list[0]
            else:
                media_type = 'application/x-www-form-urlencoded'

            return {
                media_type: {
                    'schema': {'type': 'object', 'properties': props},
                    'encoding': {},
                    'examples': {},
                    'required': any(p.get('required', False) for p in form_params)
                }
            }

        return None
