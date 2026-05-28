import re

SENSITIVE_PARAM_PATTERNS = {
    "credentials": r"(?i)(password|secret|token|credential|passphrase|pin_code|auth_token)",
    "api_keys": r"(?i)(apikey|api_key|access_key|client_secret|client_id)",
    "session_tokens": r"(?i)(session_id|sessionid|csrf_token|jwt|bearer|refresh_token|oauth)",
    "pii_basic": r"(?i)(email|phone|address|dob|birth_date|first_name|last_name)",
    "pii_ids": r"(?i)(ssn|social_security|passport|driver_license|national_id)",
    "financial": r"(?i)(credit_card|cc_num|cvv|cvc|iban|routing_number|account_number|billing_address)",
    "health": r"(?i)(patient_id|insurance_number|medical_record)",
}

class ParameterAnalyzer:
    def __init__(self):
        self.compiled_patterns = {
            category: re.compile(pattern) 
            for category, pattern in SENSITIVE_PARAM_PATTERNS.items()
        }

    def analyze_parameters(self, parameters):
        """
        Analyzes a list of parameters (OpenAPI format) and returns a list of sensitive parameters.
        Returns: list of dicts {'name': param_name, 'in': location, 'category': category}
        """
        sensitive_params = []
        for param in parameters:
            param_name = param.get('name', '')
            param_in = param.get('in', 'unknown')
            
            for category, pattern in self.compiled_patterns.items():
                if pattern.search(param_name):
                    sensitive_params.append({
                        'name': param_name,
                        'in': param_in,
                        'category': category
                    })
                    break
                    
        return sensitive_params
