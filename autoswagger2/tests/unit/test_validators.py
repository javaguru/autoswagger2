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

    # mixed findings
    def test_mixed_findings_confidence(self):
        pii_data = {
            'JWT': {
                'values': {'ey...'},
                'detection_methods': {'regex'}  # high
            },
            'EMAIL_ADDRESS': {
                'values': {'user@acme.com'},
                'detection_methods': {'presidio'}  # medium
            }
        }
        result, details = self.validator.validate_finding(pii_data)
        assert details['JWT']['confidence'] == 'high'
        assert details['EMAIL_ADDRESS']['confidence'] == 'medium'

    # Test edge case - short value
    def test_eliminate_short_values(self):
        pii_data = {
            'PERSON': {
                'values': {'ab', 'abc'},  # 'ab' < 3 chars
                'detection_methods': {'presidio'}
            }
        }
        result, details = self.validator.validate_finding(pii_data)
        assert 'ab' not in result['PERSON']
        assert 'abc' in result['PERSON']

    # None input
    def test_none_pii_data(self):
        result, details = self.validator.validate_finding(None)
        assert result is None
        assert details is None

    # empty findings
    def test_empty_pii_data(self):
        result, details = self.validator.validate_finding({})
        assert result is None

    # SECRET
    def test_secret_category(self):
        pii_data = {
            'AWS_KEY': {
                'values': {'AKIAIOSFODNN7EXAMPLE'},
                'detection_methods': {'regex'}
            }
        }
        _, details = self.validator.validate_finding(pii_data)
        assert details['AWS_KEY']['category'] == 'Secret/Credential'
