# tests/unit/test_openapi_parser.py
from autoswagger2.discovery.openapi_parser import OpenAPIParser, OpenAPIVersion

class TestOpenAPIParser:
    def test_detect_swagger_2_0(self):
        spec = {'swagger': '2.0', 'paths': {}}
        parser = OpenAPIParser(spec)
        assert parser.version == OpenAPIVersion.SWAGGER_2_0

    def test_detect_openapi_3_0(self):
        spec = {'openapi': '3.0.1', 'paths': {}}
        parser = OpenAPIParser(spec)
        assert parser.version == OpenAPIVersion.OPENAPI_3_0

    def test_detect_openapi_3_1(self):
        spec = {'openapi': '3.1.0', 'paths': {}}
        parser = OpenAPIParser(spec)
        assert parser.version == OpenAPIVersion.OPENAPI_3_1

    def test_extract_endpoints_basic(self):
        spec = {
            'openapi': '3.0.1',
            'paths': {
                '/users': {
                    'get': {'operationId': 'listUsers'}
                }
            }
        }
        parser = OpenAPIParser(spec)
        endpoints = parser.extract_all_endpoints()
        assert len(endpoints) == 1
        assert endpoints[0]['path'] == '/users'
        assert endpoints[0]['method'] == 'get'

    def test_extract_webhooks_only_3_1(self):
        spec_2_0 = {'swagger': '2.0', 'webhooks': {'test': {}}}
        parser = OpenAPIParser(spec_2_0)
        endpoints = parser.extract_all_endpoints()
        assert len(endpoints) == 0  # Webhooks ignorés en 2.0

    def test_extract_webhooks_3_1(self):
        spec = {
            'openapi': '3.1.0',
            'paths': {},
            'webhooks': {
                'userCreated': {
                    '{$request.body#/callbackUrl}': {
                        'post': {'operationId': 'handleUserCreated'}
                    }
                }
            }
        }
        parser = OpenAPIParser(spec)
        endpoints = parser.extract_all_endpoints()
        assert len(endpoints) == 1
        assert endpoints[0]['type'] == 'webhook'
        assert endpoints[0]['webhook_name'] == 'userCreated'
