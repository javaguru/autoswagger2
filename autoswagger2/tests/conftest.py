# tests/conftest.py
import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

@pytest.fixture
def sample_swagger_2_spec():
    return {
        'swagger': '2.0',
        'info': {'title': 'Test API', 'version': '1.0'},
        'paths': {
            '/users': {
                'get': {'operationId': 'listUsers'},
                'post': {'operationId': 'createUser'}
            },
            '/users/{id}': {
                'get': {'operationId': 'getUser'},
                'delete': {'operationId': 'deleteUser'}
            }
        }
    }

@pytest.fixture
def sample_openapi_3_spec():
    return {
        'openapi': '3.0.1',
        'info': {'title': 'Test API', 'version': '1.0'},
        'paths': {
            '/users': {
                'get': {'operationId': 'listUsers'},
                'post': {'operationId': 'createUser'}
            }
        }
    }

@pytest.fixture
def sample_openapi_3_1_spec():
    return {
        'openapi': '3.1.0',
        'info': {'title': 'Test API', 'version': '1.0'},
        'paths': {
            '/users': {'get': {'operationId': 'listUsers'}}
        },
        'webhooks': {
            'userCreated': {
                'https://example.com/webhook': {
                    'post': {'operationId': 'onUserCreated'}
                }
            }
        }
    }

# More specs test
@pytest.fixture
def sample_spec_with_parameters():
    return {
        'openapi': '3.0.1',
        'paths': {
            '/users/{userId}': {
                'get': {
                    'parameters': [
                        {
                            'name': 'userId',
                            'in': 'path',
                            'required': True,
                            'schema': {'type': 'string'}
                        },
                        {
                            'name': 'include_details',
                            'in': 'query',
                            'schema': {'type': 'boolean'}
                        }
                    ]
                }
            }
        }
    }

# Spec with requestBody
@pytest.fixture
def sample_spec_with_request_body():
    return {
        'openapi': '3.0.1',
        'paths': {
            '/users': {
                'post': {
                    'requestBody': {
                        'required': True,
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'name': {'type': 'string'},
                                        'email': {'type': 'string'}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

# Spec complexe
@pytest.fixture
def sample_complex_spec():
    return {
        'openapi': '3.0.1',
        'info': {'title': 'Complex API', 'version': '1.0'},
        'paths': {
            '/admin/users': {'get': {}},
            '/admin/settings': {'post': {}},
            '/users/{id}': {'get': {}, 'put': {}, 'delete': {}}
        }
    }
