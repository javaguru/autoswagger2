# autoswagger2/utils/validators.py
# Normalises and validates findings.

class ResultValidator:
    def __init__(self):
        # List of common false positives in test / mock environments
        self.false_positives = [
            "example.com", "test@test.com", "dummy", "placeholder", "string",
            "123456789", "000000000", "111111111", "999999999",
            "password", "secret", "undefined", "null"
        ]

    def validate_finding(self, pii_data):
        """
        Normalizes and validates results to avoid false positives,
        eliminate duplicates, and enrich metadata.
        """
        if not pii_data:
            return None, None

        normalized_data = {}
        detection_details = {}

        for finding_type, details in pii_data.items():
            raw_values = details.get('values', set())
            methods = details.get('detection_methods', set())

            valid_values = []
            for val in raw_values:
                val_str = str(val).strip()
                
                # Checks for false positives
                is_fp = any(fp in val_str.lower() for fp in self.false_positives)
                
                # Eliminates strings that are too short or false positives
                if not is_fp and len(val_str) >= 3:
                    # Eliminates duplicates (while preserving appearance order)
                    if val_str not in valid_values:
                        valid_values.append(val_str)

            if valid_values:
                # Limit to 3 examples to avoid cluttering reports
                normalized_data[finding_type] = valid_values[:3]
                
                # Enriches the metadata
                is_critical = 'regex' in methods
                detection_details[finding_type] = {
                    "detection_methods": list(methods),
                    "confidence": "high" if is_critical else "medium",
                    "category": "Secret/Credential" if is_critical else "PII/Data",
                    "count": len(valid_values)
                }

        return normalized_data if normalized_data else None, detection_details if detection_details else None
