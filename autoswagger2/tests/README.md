# AutoSwagger2 Tests

## Running Tests

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=autoswagger2 --cov-report=html

# Run specific test file
python -m pytest autoswagger2/tests/unit/test_openapi_parser.py

# Run with verbose output
python -m pytest -v
```
