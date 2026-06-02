# tests/unit/test_finder.py
import argparse
import requests
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
