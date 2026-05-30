# tests/unit/test_parameter_analysis.py
from autoswagger2.analysis.parameter_analysis import ParameterAnalyzer

class TestParameterAnalyzer:
    def setup_method(self):
        self.analyzer = ParameterAnalyzer()

    def test_detect_password_param(self):
        parameters = [
            {'name': 'password', 'in': 'query'},
            {'name': 'username', 'in': 'query'}
        ]
        sensitive = self.analyzer.analyze_parameters(parameters)
        assert len(sensitive) == 1
        assert sensitive[0]['category'] == 'credentials'

    def test_detect_api_key_param(self):
        parameters = [
            {'name': 'api_key', 'in': 'query'}
        ]
        sensitive = self.analyzer.analyze_parameters(parameters)
        assert len(sensitive) == 1
        assert sensitive[0]['category'] == 'api_keys'

    def test_detect_credit_card_param(self):
        parameters = [
            {'name': 'credit_card', 'in': 'body'}
        ]
        sensitive = self.analyzer.analyze_parameters(parameters)
        assert len(sensitive) == 1
        assert sensitive[0]['category'] == 'financial'
