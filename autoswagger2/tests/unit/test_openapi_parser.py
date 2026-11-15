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

    def test_invalid_spec_returns_none(self):
        spec = {}  # Spec empty
        parser = OpenAPIParser(spec)
        assert parser.version is None

    def test_unknown_version(self):
        spec = {'swagger': '1.0'}  #  Unknown version
        parser = OpenAPIParser(spec)
        assert parser.version is None

    def test_force_version_override(self):
        spec = {'swagger': '2.0'}
        parser = OpenAPIParser(spec, force_version='3.1.0')
        assert parser.raw_version == '3.1.0'

    def test_parse_parameters_swagger_2(self, sample_swagger_2_spec):
        spec = sample_swagger_2_spec
        parser = OpenAPIParser(spec)
        operation = spec['paths']['/users/{id}']['get']
        params = parser.parse_parameters(operation)
        assert isinstance(params, list)

    def test_parse_request_body_json(self):
        spec = {
            'openapi': '3.0.1',
            'paths': {}
        }
        parser = OpenAPIParser(spec)
        operation = {
            'requestBody': {
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {'type': 'object'}
                    }
                }
            }
        }
        bodies = parser.parse_request_body(operation)
        assert 'application/json' in bodies
        assert bodies['application/json']['required'] == True

    # AMÉLIORATION 4: Tester multiple endpoints
    def test_extract_multiple_endpoints(self):
        spec = {
            'openapi': '3.0.1',
            'paths': {
                '/users': {'get': {}, 'post': {}},
                '/users/{id}': {'get': {}, 'put': {}, 'delete': {}}
            }
        }
        parser = OpenAPIParser(spec)
        endpoints = parser.extract_all_endpoints()
        assert len(endpoints) == 5
        methods = [ep['method'] for ep in endpoints]
        assert 'get' in methods and 'post' in methods

    def test_resolve_ref_chained_cyclic_and_rfc6901(self):
        spec = {
            'openapi': '3.0.1',
            'components': {
                'schemas': {
                    'Base~Name/Obj': {
                        'type': 'object',
                        'properties': {'id': {'type': 'integer'}}
                    },
                    'Alias': {'$ref': '#/components/schemas/Base~0Name~1Obj'},
                    'Node': {
                        'type': 'object',
                        'properties': {
                            'name': {'type': 'string'},
                            'parent': {'$ref': '#/components/schemas/Node'}
                        }
                    }
                }
            },
            'paths': {}
        }
        parser = OpenAPIParser(spec)
        resolved_alias = parser.resolve_ref({'$ref': '#/components/schemas/Alias'})
        assert resolved_alias['type'] == 'object'
        assert 'id' in resolved_alias['properties']

        resolved_node = parser.resolve_ref({'$ref': '#/components/schemas/Node'})
        assert resolved_node['type'] == 'object'
        assert 'parent' in resolved_node['properties']

    def test_path_item_parameters_merge_and_override(self):
        spec = {
            'openapi': '3.0.1',
            'components': {
                'parameters': {
                    'TenantHeader': {'name': 'X-Tenant', 'in': 'header', 'schema': {'type': 'string'}}
                }
            },
            'paths': {
                '/users/{id}': {
                    'parameters': [
                        {'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}},
                        {'$ref': '#/components/parameters/TenantHeader'}
                    ],
                    'get': {
                        'parameters': [
                            {'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'integer'}}
                        ]
                    }
                }
            }
        }
        parser = OpenAPIParser(spec)
        endpoints = parser.extract_all_endpoints()
        assert len(endpoints) == 1
        params = endpoints[0]['parameters']
        by_name = {p['name']: p for p in params}
        assert by_name['id']['type'] == 'integer'
        assert by_name['X-Tenant']['in'] == 'header'

    def test_parse_swagger2_body_and_formdata(self):
        spec = {
            'swagger': '2.0',
            'definitions': {
                'UserInput': {'type': 'object', 'properties': {'username': {'type': 'string'}}}
            },
            'paths': {
                '/users': {
                    'post': {
                        'consumes': ['application/json'],
                        'parameters': [
                            {'name': 'body', 'in': 'body', 'required': True, 'schema': {'$ref': '#/definitions/UserInput'}}
                        ]
                    }
                },
                '/upload': {
                    'post': {
                        'parameters': [
                            {'name': 'title', 'in': 'formData', 'type': 'string'},
                            {'name': 'doc', 'in': 'formData', 'type': 'file', 'required': True}
                        ]
                    }
                }
            }
        }
        parser = OpenAPIParser(spec)
        endpoints = {ep['path']: ep for ep in parser.extract_all_endpoints()}
        assert 'application/json' in endpoints['/users']['request_bodies']
        assert endpoints['/users']['request_bodies']['application/json']['schema']['properties']['username']['type'] == 'string'
        assert endpoints['/users']['request_bodies']['application/json']['required'] is True
        assert 'multipart/form-data' in endpoints['/upload']['request_bodies']
        assert endpoints['/upload']['request_bodies']['multipart/form-data']['required'] is True

    def test_normalize_openapi_31_nullable_type_list(self):
        spec = {
            'openapi': '3.1.0',
            'paths': {
                '/search': {
                    'get': {
                        'parameters': [
                            {'name': 'count', 'in': 'query', 'schema': {'type': ['integer', 'null']}}
                        ]
                    }
                }
            }
        }
        parser = OpenAPIParser(spec)
        endpoints = parser.extract_all_endpoints()
        assert endpoints[0]['parameters'][0]['type'] == 'integer'
