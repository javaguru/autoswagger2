# tests/unit/test_finder.py
import argparse
import requests
from unittest.mock import MagicMock
from autoswagger2.discovery.finder import SpecFinder

# --- Mocks for requests.Session ---
class MockResponse:
    def __init__(self, text, status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}

class MockSession:
    def __init__(self, url_map):
        self.url_map = url_map
        self.history = []

    def get(self, url, **kwargs):
        self.history.append(url)
        if url in self.url_map:
            return self.url_map[url]
        return MockResponse("Not Found", 404)

# --- Embedded swaggerDoc extraction tests ---
def test_extract_embedded_swagger_doc_valid_json():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    finder = SpecFinder("http://localhost", args, session)

    js_content = """
    window.onload = function() {
      var options = {
        "swaggerDoc": {
          "openapi": "3.1.1",
          "info": {
            "title": "Catalogue apprentissage",
            "version": "1.0.0"
          },
          "paths": {}
        }
      };
    };
    """
    spec = finder._extract_embedded_swagger_doc(js_content)
    assert spec is not None
    assert spec["openapi"] == "3.1.1"
    assert spec["info"]["title"] == "Catalogue apprentissage"

def test_extract_embedded_swagger_doc_valid_js_literal():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    finder = SpecFinder("http://localhost", args, session)

    js_content = """
    window.onload = function() {
      var options = {
        swaggerDoc: {
          openapi: '3.0.0',
          info: {
            title: 'Single quoted info'
          },
          paths: {}
        }
      };
    };
    """
    spec = finder._extract_embedded_swagger_doc(js_content)
    assert spec is not None
    assert spec["openapi"] == "3.0.0"
    assert spec["info"]["title"] == "Single quoted info"

def test_extract_embedded_swagger_doc_no_match():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    finder = SpecFinder("http://localhost", args, session)

    js_content = "var a = 123;"
    spec = finder._extract_embedded_swagger_doc(js_content)
    assert spec is None

# --- Mocked HTTP SpecFinder tests ---

# --- Mocked HTTP SpecFinder tests ---

def test_fetch_swagger_spec_direct_json():
    args = argparse.Namespace(verbose=True, product=False)
    url_map = {
        "http://localhost/direct-swagger.json": MockResponse('{"openapi": "3.0.0", "paths": {}}')
    }
    session = MockSession(url_map)
    finder = SpecFinder("http://localhost/direct-swagger.json", args, session)
    finder.cache.get_cached_spec = lambda url: None  # Disable file-system cache interference

    spec = finder._fetch_swagger_spec("http://localhost/direct-swagger.json")
    assert spec is not None
    assert spec["openapi"] == "3.0.0"
    assert "http://localhost/direct-swagger.json" in session.history

def test_fetch_swagger_spec_recursive_list():
    args = argparse.Namespace(verbose=True, product=False)
    url_map = {
        "http://localhost/api/specs": MockResponse('[{"url": "/recursive-swagger.json"}]'),
        "http://localhost/recursive-swagger.json": MockResponse('{"swagger": "2.0", "paths": {}}')
    }
    session = MockSession(url_map)
    finder = SpecFinder("http://localhost/api/specs", args, session)
    finder.cache.get_cached_spec = lambda url: None  # Disable file-system cache interference

    spec = finder._fetch_swagger_spec("http://localhost/api/specs")
    assert spec is not None
    assert spec["swagger"] == "2.0"
    assert "http://localhost/api/specs" in session.history
    assert "http://localhost/recursive-swagger.json" in session.history

def test_parse_swagger_ui_page_with_script():
    args = argparse.Namespace(verbose=True, product=False)
    html_content = """
    <html>
      <head>
        <script src="swagger-ui-init.js"></script>
      </head>
      <body>Swagger UI Page</body>
    </html>
    """
    js_content = 'var options = { "swaggerDoc": {"openapi": "3.1.0", "paths": {}} };'
    url_map = {
        "http://localhost/ui-page/": MockResponse(html_content),
        "http://localhost/ui-page/swagger-ui-init.js": MockResponse(js_content)
    }
    session = MockSession(url_map)
    finder = SpecFinder("http://localhost/ui-page/", args, session)
    finder.cache.get_cached_spec = lambda url: None  # Disable file-system cache interference

    spec, spec_url = finder._parse_swagger_ui_page("http://localhost/ui-page/")
    assert spec is not None
    assert spec["openapi"] == "3.1.0"
    assert spec_url == "http://localhost/ui-page/swagger-ui-init.js"

def test_extract_spec_from_variable_url():
    args = argparse.Namespace(verbose=True, product=False)
    js_content = 'const specUrl = "var-swagger.json";'
    url_map = {
        "http://localhost/docs/var-swagger.json": MockResponse('{"openapi": "3.0.1", "paths": {}}')
    }
    session = MockSession(url_map)
    finder = SpecFinder("http://localhost/docs/", args, session)
    finder.cache.get_cached_spec = lambda url: None  # Disable file-system cache interference

    spec, spec_url = finder._extract_spec_from_content(js_content, "http://localhost/docs/")
    assert spec is not None
    assert spec["openapi"] == "3.0.1"
    assert spec_url == "http://localhost/docs/var-swagger.json"

def test_discover_from_base_direct_spec():
    args = argparse.Namespace(verbose=True, product=False)
    url_map = {
        "http://localhost/discover/openapi.json": MockResponse('{"openapi": "3.0.0", "paths": {}}')
    }
    session = MockSession(url_map)
    finder = SpecFinder("http://localhost/discover", args, session)
    finder.cache.get_cached_spec = lambda url: None  # Disable file-system cache interference

    spec, spec_url = finder._discover_from_base("http://localhost/discover")
    assert spec is not None
    assert spec_url == "http://localhost/discover/openapi.json"

def test_find_multi_phase_workflow_success():
    args = argparse.Namespace(verbose=True, product=False)
    url_map = {
        "http://localhost/workflow/openapi.json": MockResponse('{"openapi": "3.1.0", "paths": {}}')
    }
    session = MockSession(url_map)
    finder = SpecFinder("http://localhost/workflow/", args, session)
    finder.cache.get_cached_spec = lambda url: None  # Disable file-system cache interference

    spec, spec_url = finder.find()
    assert spec is not None
    assert spec["openapi"] == "3.1.0"
    assert spec_url == "http://localhost/workflow/openapi.json"

def test_fetch_swagger_spec_exceptions():
    args = argparse.Namespace(verbose=True, product=False)
    class ErrorSession:
        def get(self, url, **kwargs):
            raise requests.exceptions.ConnectionError("Connection Failed")

    finder = SpecFinder("http://localhost/exception", args, ErrorSession())
    finder.cache.get_cached_spec = lambda url: None  # Disable file-system cache interference
    spec = finder._fetch_swagger_spec("http://localhost/exception")
    assert spec is None

def test_fetch_swagger_spec_cached():
    args = argparse.Namespace(verbose=True, product=False)
    session = requests.Session()
    finder = SpecFinder("http://localhost/cached", args, session)
    
    # Mock cache to return a spec
    cached_spec = {"swagger": "2.0", "paths": {}}
    finder.cache.get_cached_spec = lambda url: cached_spec
    
    spec = finder._fetch_swagger_spec("http://localhost/cached")
    assert spec == cached_spec

def test_extract_embedded_swagger_doc_escapes_and_errors():
    args = argparse.Namespace(verbose=True, product=False)
    session = requests.Session()
    finder = SpecFinder("http://localhost", args, session)

    # Test escape sequences inside strings
    js_content = 'var config = { "swaggerDoc": {"name": "hello\\\\world", "description": "quote\\""} };'
    extracted = finder._extract_embedded_swagger_doc(js_content)
    assert extracted is not None
    assert extracted["name"] == "hello\\world"

    # Test YAML error / parse exception fallback returning None
    # Providing unbalanced JSON/YAML that starts parsing but fails
    js_content_bad = 'var config = { "swaggerDoc": {"name": ::::invalid} };'
    extracted_bad = finder._extract_embedded_swagger_doc(js_content_bad)
    assert extracted_bad is None

def test_find_root_fallback_discovery():
    args = argparse.Namespace(verbose=True, product=False)
    
    # We want a request to http://localhost/sub/path to fail,
    # but the root fallback discovery to http://localhost to succeed.
    class MockSessionWithFallback:
        def __init__(self):
            self.history = []
        def get(self, url, **kwargs):
            self.history.append(url)
            resp = MagicMock()
            if url == "http://localhost/openapi.json":
                resp.status_code = 200
                resp.text = '{"openapi": "3.0.0", "paths": {}}'
                resp.headers = {"Content-Type": "application/json"}
            else:
                resp.status_code = 404
                resp.text = "Not Found"
                resp.headers = {}
            return resp

    session = MockSessionWithFallback()
    # Initial base URL is a subpath
    finder = SpecFinder("http://localhost/sub/path", args, session)
    finder.cache.get_cached_spec = lambda url: None
    
    spec, spec_url = finder.find()
    assert spec is not None
    assert spec["openapi"] == "3.0.0"
    assert spec_url == "http://localhost/openapi.json"
    assert "http://localhost/openapi.json" in session.history

def test_extract_spec_petstore_filter():
    args = argparse.Namespace(verbose=True, product=False)
    session = requests.Session()
    finder = SpecFinder("http://localhost", args, session)

    # Petstore example URL should be skipped if base_url is not petstore
    content_petstore = 'const specUrl = "http://petstore.swagger.io/v2/swagger.json";'
    spec, spec_url = finder._extract_spec_from_content(content_petstore, "http://localhost")
    assert spec is None
    assert spec_url is None

    # SwaggerUI config with petstore should be skipped
    content_ui_petstore = 'SwaggerUI({ url: "http://petstore.swagger.io/v2/swagger.json" })'
    spec, spec_url = finder._extract_spec_from_content(content_ui_petstore, "http://localhost")
    assert spec is None
    assert spec_url is None

def test_parse_swagger_ui_page_script_exception():
    args = argparse.Namespace(verbose=True, product=False)
    
    class ExceptionSession:
        def get(self, url, **kwargs):
            resp = MagicMock()
            if url == "http://localhost/swagger-ui":
                resp.status_code = 200
                resp.text = '<html><head><script src="app.js"></script></head><body>swagger</body></html>'
                resp.headers = {"Content-Type": "text/html"}
                return resp
            else:
                # Simulates exception downloading the script file app.js
                raise requests.exceptions.RequestException("Network failed for script")

    finder = SpecFinder("http://localhost/swagger-ui", args, ExceptionSession())
    finder.cache.get_cached_spec = lambda url: None
    
    # Verify it handles the script exception gracefully and returns None (or falls back)
    spec, spec_url = finder._parse_swagger_ui_page("http://localhost/swagger-ui")
    assert spec is None

