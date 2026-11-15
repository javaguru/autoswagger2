# autoswagger2/utils/validators.py
# Normalises and validates findings.

import re


class ResultValidator:
    def __init__(self):
        # List of common false positives in test / mock environments (PII / Presidio)
        self.false_positives = [
            "example@example.com", "user@example.com", "test@example.com",
            "noreply@example.com", "test@test.com", "admin@admin.com",
            "test.example.com", "dummy", "placeholder", "string",
            "123456789", "000000000", "111111111", "999999999",
            "password", "secret", "undefined", "null", "test",
            "demo", "mock", "sample", "fixture", "stub",
            "127.0.0.1", "localhost", "0.0.0.0",
            "user123", "admin123", "test123", "demo123"
        ]
        # Narrower list for regex-based secret findings so credentials/URIs using localhost/password/secret aren't discarded
        self.regex_false_positives = [
            "example@example.com", "user@example.com", "test@example.com",
            "placeholder", "dummy", "0000000000", "1111111111", "aaaaaaaaaa"
        ]

    def _is_false_positive(self, val_str, is_critical):
        val_lower = val_str.lower()
        if is_critical:
            return any(fp in val_lower for fp in self.regex_false_positives)

        fp_set = set(self.false_positives)
        if val_lower in fp_set:
            return True

        tokens = set(re.findall(r"[a-z0-9@.+-]+", val_lower))
        if tokens & fp_set:
            return True

        for fp in self.false_positives:
            if ("." in fp or "@" in fp) and (
                val_lower.endswith(f"@{fp}") or val_lower.endswith(f".{fp}")
            ):
                return True
        return False

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
            is_critical = 'regex' in methods

            valid_values = []
            for val in raw_values:
                val_str = str(val).strip()

                # Checks for false positives
                is_fp = self._is_false_positive(val_str, is_critical)

                # Eliminates strings that are too short or false positives
                if not is_fp and len(val_str) >= 3:
                    # Eliminates duplicates (while preserving appearance order)
                    if val_str not in valid_values:
                        valid_values.append(val_str)

            if valid_values:
                # Limit to 3 examples to avoid cluttering reports
                normalized_data[finding_type] = valid_values[:3]

                # Enriches the metadata
                detection_details[finding_type] = {
                    "detection_methods": list(methods),
                    "confidence": "high" if is_critical else "medium",
                    "category": "Secret/Credential" if is_critical else "PII/Data",
                    "count": len(valid_values)
                }

        return normalized_data if normalized_data else None, detection_details if detection_details else None
