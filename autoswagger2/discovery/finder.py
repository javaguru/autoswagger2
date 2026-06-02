# autoswagger2/discovery/finder.py
# Manages the discovery of OpenAPI specifications.

import requests
import yaml
import json
import re
from urllib.parse import urljoin, urlparse
from ..utils.helpers import log
from ..utils.config import SWAGGER_UI_PATHS, DIRECT_SPEC_PATHS
from ..utils.cache import SpecCache

class SpecFinder:
    def __init__(self, base_url, args, session):
        self.base_url = base_url
        self.args = args
        self.session = session
        self.TIMEOUT = 10
        self.cache = SpecCache()

    def find(self):
        """
        Main method to find the OpenAPI spec using a multi-phase approach.
        """
        parsed_input_url = urlparse(self.base_url)

        # Phase 1: Direct URL Analysis
        if not self.args.product:
            log(f"Attempting to fetch spec directly from provided URL: {self.base_url}", level="INFO")
        swagger_spec = self._fetch_swagger_spec(self.base_url)
        if swagger_spec:
            return swagger_spec, self.base_url

        if not self.args.product:
            log(f"Provided URL is not a spec file. Attempting to parse as a Swagger UI page...", level="INFO")
        swagger_spec, spec_url = self._parse_swagger_ui_page(self.base_url)
        if swagger_spec:
            return swagger_spec, spec_url

        # Phase 2: Context-Aware Discovery
        if not self.args.product:
            log(f"Could not find spec from provided URL. Starting discovery within path: {parsed_input_url.path}", level="INFO")
        swagger_spec, spec_url = self._discover_from_base(self.base_url)
        if swagger_spec:
            return swagger_spec, spec_url

        # Phase 3: Root Fallback Discovery
        discovery_root_url = f"{parsed_input_url.scheme}://{parsed_input_url.netloc}"
        if self.base_url.rstrip('/') != discovery_root_url:
            if not self.args.product:
                log(f"Discovery within path failed. Falling back to discovery from server root...", level="INFO")
            swagger_spec, spec_url = self._discover_from_base(discovery_root_url)
            if swagger_spec:
                return swagger_spec, spec_url

        return None, None

    def _discover_from_base(self, base_url):
        """
        Attempts to discover a spec from a given base URL by checking common UI and direct spec paths.
        """
        base_url_with_slash = base_url if base_url.endswith('/') else base_url + '/'

        # First, check for common UI pages
        for pth in SWAGGER_UI_PATHS:
            swagger_ui_url = urljoin(base_url_with_slash, pth.lstrip('/'))
            if self.args.verbose:
                log(f"Checking for Swagger UI at {swagger_ui_url}", level="DEBUG")
            spec, spec_url = self._parse_swagger_ui_page(swagger_ui_url)
            if spec:
                return spec, spec_url

        # If no UI page is found, check for direct spec files
        for pth in DIRECT_SPEC_PATHS:
            current_spec_url = urljoin(base_url_with_slash, pth.lstrip('/'))
            if self.args.verbose:
                log(f"Attempting to fetch spec from direct path: {current_spec_url}", level="DEBUG")
            spec = self._fetch_swagger_spec(current_spec_url)
            if spec:
                if not self.args.product:
                    log(f"Spec identified via direct path detection: {current_spec_url}", level="INFO")
                return spec, current_spec_url

        return None, None

    def _fetch_swagger_spec(self, url, is_recursive_call=False):
        cached_spec = self.cache.get_cached_spec(url)
        if cached_spec:
            if self.args.verbose:
                log(f"Loaded spec from cache for {url}", level="DEBUG")
            return cached_spec

        if self.args.verbose:
            log(f"Fetching Swagger/OpenAPI spec from {url}", level="DEBUG")
        try:
            resp = self.session.get(url, timeout=self.TIMEOUT)
            if resp.status_code != 200:
                if self.args.verbose:
                    ctype = resp.headers.get('Content-Type', '').lower()
                    log(f"Invalid response from {url}: {resp.status_code}, Content-Type: {ctype}", level="WARNING")
                return None

            content_text = resp.text
            spec = None

            try:
                spec = json.loads(content_text)
            except json.JSONDecodeError:
                try:
                    spec = yaml.safe_load(content_text)
                except yaml.YAMLError as perr:
                    # Fallback: check if it's a JavaScript file containing embedded swaggerDoc
                    spec = self._extract_embedded_swagger_doc(content_text)
                    if not spec:
                        if self.args.verbose:
                            log(f"Failed to parse content from {url} as either JSON, YAML, or embedded swaggerDoc. YAML Error: {perr}", level="DEBUG")
                        return None

            if spec:
                if isinstance(spec, dict) and ('openapi' in spec or 'swagger' in spec or 'paths' in spec):
                    if self.args.verbose:
                        log(f"Successfully loaded spec from {url}.", level="SUCCESS")
                    self.cache.cache_spec(url, spec)
                    return spec
                elif isinstance(spec, list) and not is_recursive_call and spec and isinstance(spec[0], dict) and 'url' in spec[0]:
                    if self.args.verbose:
                        log(f"URL {url} returned a list of spec groups. Following the first one.", level="DEBUG")
                    spec_path = spec[0]['url']
                    parsed_original_url = urlparse(url)
                    base_server_url = f"{parsed_original_url.scheme}://{parsed_original_url.netloc}"
                    full_spec_url = urljoin(base_server_url, spec_path)
                    return self._fetch_swagger_spec(full_spec_url, is_recursive_call=True)

            if self.args.verbose:
                log(f"Content from {url} does not appear to be a valid spec file or group.", level="DEBUG")
            return None

        except requests.exceptions.RequestException as e:
            if self.args.verbose:
                log(f"Error fetching Swagger/OpenAPI spec from {url}: {e}", level="DEBUG")
        return None

    def _extract_embedded_swagger_doc(self, js_content):
        """
        Attempts to extract a balanced JSON/YAML block assigned to the 'swaggerDoc' property
        inside JavaScript init files (such as swagger-ui-init.js).
        """
        match = re.search(r'["\']?swaggerDoc["\']?\s*:\s*(\{)', js_content)
        if not match:
            return None

        start_idx = match.start(1)
        brace_count = 0
        in_string = False
        string_char = None
        escaped = False

        for i in range(start_idx, len(js_content)):
            char = js_content[i]

            if escaped:
                escaped = False
                continue

            if char == '\\':
                escaped = True
                continue

            if char in ('"', "'", "`"):
                if not in_string:
                    in_string = True
                    string_char = char
                elif string_char == char:
                    in_string = False
                    string_char = None
                continue

            if in_string:
                continue

            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    json_str = js_content[start_idx : i + 1]
                    try:
                        return json.loads(json_str)
                    except json.JSONDecodeError:
                        try:
                            return yaml.safe_load(json_str)
                        except Exception:
                            return None
        return None

    def _extract_spec_from_content(self, content, base_url):
        # 1. Try to extract embedded swaggerDoc directly (e.g. swagger-ui-init.js)
        embedded_spec = self._extract_embedded_swagger_doc(content)
        if embedded_spec and isinstance(embedded_spec, dict) and ('openapi' in embedded_spec or 'swagger' in embedded_spec or 'paths' in embedded_spec):
            if self.args.verbose:
                log(f"Found embedded swaggerDoc directly in content of {base_url}", level="DEBUG")
            return embedded_spec, base_url

        spec_var_match = re.search(r'(?:const|var|let)\s+\w+(?:Url|URL)?\s*=\s*["\']([^"\']*(?:swagger|openapi)\.(?:json|yaml|yml))["\']', content)
        if spec_var_match:
            spec_path = spec_var_match.group(1)
            full_spec_url = urljoin(base_url, spec_path)
            is_petstore_example = "petstore.swagger.io" in full_spec_url and "petstore.swagger.io" not in urlparse(base_url).netloc
            if not is_petstore_example:
                if self.args.verbose:
                    log(f"Found potential spec URL in variable: {full_spec_url}", level="DEBUG")
                spec = self._fetch_swagger_spec(full_spec_url)
                if spec:
                    return spec, full_spec_url

        swagger_ui_config_match = re.search(r'SwaggerUI(?:Bundle)?\s*\(([\s\S]*?)\)', content)
        if swagger_ui_config_match:
            config_block = swagger_ui_config_match.group(1)
            spec_url_match = re.search(r'["\']?url["\']?\s*:\s*["\']([^"]+)["\']', config_block)
            if spec_url_match:
                spec_path = spec_url_match.group(1)
                full_spec_url = urljoin(base_url, spec_path)
                is_petstore_example = "petstore.swagger.io" in full_spec_url and "petstore.swagger.io" not in urlparse(base_url).netloc
                if not is_petstore_example:
                    if self.args.verbose:
                        log(f"Found 'url' in SwaggerUI config: {full_spec_url}", level="DEBUG")
                    spec = self._fetch_swagger_spec(full_spec_url)
                    if spec:
                        return spec, full_spec_url

        return None, None

    def _parse_swagger_ui_page(self, page_url):
        if self.args.verbose:
            log(f"Parsing potential Swagger UI page: {page_url}", level="DEBUG")
        try:
            r = self.session.get(page_url, allow_redirects=True, timeout=self.TIMEOUT)
            if r.status_code == 200 and ('swagger' in r.text.lower() or 'openapi' in r.text.lower()):
                if self.args.verbose:
                    log(f"Content at {page_url} looks like a Swagger UI page.", level="DEBUG")

                js_files = re.findall(r'<script\s+src=["\']([^"\']+\.js)["\']', r.text, re.IGNORECASE)
                for jsf in js_files:
                    jsu = urljoin(page_url, jsf)
                    try:
                        js_resp = self.session.get(jsu, timeout=self.TIMEOUT)
                        if js_resp.status_code == 200:
                            spec, spec_url = self._extract_spec_from_content(js_resp.text, jsu)
                            if spec:
                                return spec, spec_url
                    except requests.exceptions.RequestException:
                        continue

                spec, spec_url = self._extract_spec_from_content(r.text, page_url)
                if spec:
                    return spec, spec_url
        except requests.exceptions.RequestException as e:
            if self.args.verbose:
                log(f"Error checking Swagger UI page at {page_url}: {e}", level="DEBUG")
        return None, None
