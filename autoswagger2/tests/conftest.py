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
