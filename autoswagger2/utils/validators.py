# autoswagger2/utils/validators.py
# Normalises and validates findings.

class ResultValidator:
    def __init__(self):
        # Liste de faux positifs courants dans les environnements de test / mock
        self.false_positives = [
            "example.com", "test@test.com", "dummy", "placeholder", "string",
            "123456789", "000000000", "111111111", "999999999",
            "password", "secret", "undefined", "null"
        ]

    def validate_finding(self, pii_data):
        """
        Normalise et valide les résultats pour éviter faux positifs,
        éliminer les duplicatas et enrichir les métadonnées.
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
                
                # Vérifie les faux positifs
                is_fp = any(fp in val_str.lower() for fp in self.false_positives)
                
                # Élimine les chaînes trop courtes ou les faux positifs
                if not is_fp and len(val_str) >= 3:
                    # Élimine les duplicatas (tout en gardant l'ordre d'apparition)
                    if val_str not in valid_values:
                        valid_values.append(val_str)

            if valid_values:
                # On limite à 3 exemples pour ne pas surcharger les rapports
                normalized_data[finding_type] = valid_values[:3]
                
                # Enrichit les métadonnées
                is_critical = 'regex' in methods
                detection_details[finding_type] = {
                    "detection_methods": list(methods),
                    "confidence": "high" if is_critical else "medium",
                    "category": "Secret/Credential" if is_critical else "PII/Data",
                    "count": len(valid_values)
                }

        return normalized_data if normalized_data else None, detection_details if detection_details else None
