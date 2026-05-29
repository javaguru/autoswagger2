import sys
import os
sys.path.append(os.getcwd())

from autoswagger2.analysis.secrets import detect_sensitive_info
from autoswagger2.utils.validators import ResultValidator

content = '{"AKIAQWERTYUIOPASDF":"AKIAQWERTYUIOPASDF","name":"Joe","age":25}'
pii_data = {}
sensitive_info, _ = detect_sensitive_info(content)
print('sensitive_info:', sensitive_info)
if sensitive_info:
    for key, values in sensitive_info.items():
        pii_data.setdefault(key, {'values': set(), 'detection_methods': set()})['values'].update(values)
        pii_data[key]['detection_methods'].add('regex')

validator = ResultValidator()
norm_data, norm_details = validator.validate_finding(pii_data)
print('norm_data:', norm_data)
