# tests/unit/test_validators.py
from autoswagger2.utils.validators import ResultValidator

class TestResultValidator:
    def setup_method(self):
        self.validator = ResultValidator()

    def test_eliminate_false_positive_email(self):
        pii_data = {
            'EMAIL_ADDRESS': {
                'values': {'test@test.com'},  # False positive
                'detection_methods': {'presidio'}
            }
        }
        result, details = self.validator.validate_finding(pii_data)
        assert result is None  # Filtered out

    def test_keep_real_email(self):
        pii_data = {
            'EMAIL_ADDRESS': {
                'values': {'john.doe@acme.com'},
                'detection_methods': {'presidio'}
            }
        }
        result, details = self.validator.validate_finding(pii_data)
        assert 'EMAIL_ADDRESS' in result
        assert 'john.doe@acme.com' in result['EMAIL_ADDRESS']

    def test_eliminate_duplicates(self):
        pii_data = {
            'EMAIL_ADDRESS': {
                'values': {'user@acme.com', 'user@acme.com'},
                'detection_methods': {'presidio'}
            }
        }
        result, details = self.validator.validate_finding(pii_data)
        assert len(result['EMAIL_ADDRESS']) == 1

    def test_limit_to_3_examples(self):
        pii_data = {
            'EMAIL_ADDRESS': {
                'values': {f'user{i}@acme.com' for i in range(10)},
                'detection_methods': {'presidio'}
            }
        }
        result, details = self.validator.validate_finding(pii_data)
        assert len(result['EMAIL_ADDRESS']) == 3

    def test_confidence_scoring(self):
        # Regex findings = high confidence
        pii_data_regex = {
            'JWT': {
                'values': {'ey...'},
                'detection_methods': {'regex'}
            }
        }
        _, details = self.validator.validate_finding(pii_data_regex)
        assert details['JWT']['confidence'] == 'high'

        # Presidio findings = medium confidence
        pii_data_presidio = {
            'EMAIL_ADDRESS': {
                'values': {'user@acme.com'},
                'detection_methods': {'presidio'}
            }
        }
        _, details = self.validator.validate_finding(pii_data_presidio)
        assert details['EMAIL_ADDRESS']['confidence'] == 'medium'
