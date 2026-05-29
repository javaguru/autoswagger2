import sys, os
sys.path.append(os.getcwd())
from autoswagger2.analysis.pii import PiiAnalyzer

analyzer = PiiAnalyzer()
content = '[{"productId":"prod-0","name":" Product Name 0","price":19.99}]'
detected, data = analyzer.analyze_content(content)
print("detected:", detected)
print("data:", data)
