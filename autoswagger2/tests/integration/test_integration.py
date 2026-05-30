# tests/integration/test_integration.py
from autoswagger2.discovery.openapi_parser import OpenAPIParser
from autoswagger2.analysis.secrets import detect_sensitive_info
from autoswagger2.utils.validators import ResultValidator

class TestIntegrationWorkflow:
    def test_full_scan_workflow(self):
        # Spec sensitive data
        spec = {
            'openapi': '3.0.1',
            'paths': {
                '/users/{id}': {'get': {}}
            }
        }

        # Parser
        parser = OpenAPIParser(spec)
        endpoints = parser.extract_all_endpoints()
        assert len(endpoints) == 1

        # Secret detection
        part1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        part2 = "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        part3 = "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        jwt_token = part1 + "." + part2 + "." + part3
        
        response = f"Email: john@acme.com, JWT: {jwt_token}"
        sensitive, _ = detect_sensitive_info(response)
        assert sensitive is not None
        assert 'JWT Token' in sensitive

        # Validation
        validator = ResultValidator()
        result, details = validator.validate_finding({
            'EMAIL_ADDRESS': {'values': {'john@acme.com'}, 'detection_methods': {'presidio'}},
            'JWT Token': {'values': set(sensitive['JWT Token']), 'detection_methods': {'regex'}}
        })
        assert len(result) == 2
        assert details['JWT Token']['confidence'] == 'high'
