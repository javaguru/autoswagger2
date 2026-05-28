# autoswagger2/discovery/openapi_parser.py
# OpenAPI specifications parser.

from enum import Enum
from typing import Literal


class OpenAPIVersion(Enum):
    SWAGGER_2_0 = "2.0"
    OPENAPI_3_0 = "3.0"
    OPENAPI_3_1 = "3.1"

class OpenAPIParser:
    def __init__(self, spec_data, force_version=None):
        self.spec_data = spec_data
        if force_version:
            self.raw_version = force_version
        else:
            self.raw_version = self.spec_data.get('openapi') or self.spec_data.get('swagger', 'Unknown')

        self.version = self._detect_version()

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

        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'trace']:
                    endpoints.append({
                        'path': path,
                        'method': method,
                        'type': 'endpoint',
                        'operation': operation
                    })

        return endpoints

    def _extract_webhooks(self):
        """Extract from webhooks section (OpenAPI 3.1 only)"""
        endpoints = []
        webhooks = self.spec_data.get('webhooks', {})

        for webhook_name, webhook_item in webhooks.items():
            for expression, path_item in webhook_item.items():
                for method, operation in path_item.items():
                    if method in ['get', 'post', 'put', 'delete', 'patch']:
                        endpoints.append({
                            'path': expression,
                            'method': method,
                            'type': 'webhook',
                            'webhook_name': webhook_name,
                            'operation': operation,
                            'runtime_expression': True  # Mark as runtime expression
                        })

        return endpoints

    def parse_parameters(self, operation):
        """Parse parameters handling version differences"""
        parameters = []
        params = operation.get('parameters', [])

        for param in params:
            parsed_param = {
                'name': param.get('name'),
                'in': param.get('in'),
                'required': param.get('required', False),
                'description': param.get('description', '')
            }

            # Version-specific parsing
            if self.version == OpenAPIVersion.SWAGGER_2_0:
                parsed_param['type'] = param.get('type', 'string')
            else:  # OpenAPI 3.0 and 3.1
                schema = param.get('schema', {})
                parsed_param['schema'] = schema
                parsed_param['type'] = schema.get('type', 'string')
                parsed_param['style'] = param.get('style')
                parsed_param['explode'] = param.get('explode')

            parameters.append(parsed_param)

        return parameters

    def parse_request_body(self, operation):
        """Parse requestBody with content negotiation"""
        request_body = operation.get('requestBody', {})

        if not request_body:
            return None

        content = request_body.get('content', {})
        parsed_bodies = {}

        for media_type, media_obj in content.items():
            schema = media_obj.get('schema', {})
            encoding = media_obj.get('encoding', {})  # OpenAPI 3.1
            examples = media_obj.get('examples', {})  # Multiple examples

            parsed_bodies[media_type] = {
                'schema': schema,
                'encoding': encoding,
                'examples': examples,
                'required': request_body.get('required', False)
            }

        return parsed_bodies
