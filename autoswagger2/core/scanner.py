# autoswagger2/core/scanner.py
# The main orchestrator for the scan.

import time
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from ..discovery.finder import SpecFinder
from ..discovery.hidden_finder import HiddenEndpointFinder
from ..discovery.shadow_version_finder import ShadowVersionFinder
from .requester import Requester
from ..reporting.reporter import Reporter
from ..reporting.diff_engine import DiffEngine, SCORE_TO_LABEL
from ..analysis.bola import BolaTester
from ..analysis.bfla import BflaTester
from ..analysis.bopla import BoplaTester
from ..analysis.urc import UrcTester
from ..utils.config import HTTP_METHODS, SAFE_HTTP_METHODS
from ..utils.helpers import log, console, print_banner, is_quiet_output, is_same_origin_host

class Scanner:
    def __init__(self, urls, args, session):
        self.urls = urls
        self.args = args
        self.session = session
        self.reporter = Reporter(args)
        self._lock = threading.Lock()
        self._per_url_workers = self._get_max_workers()
        self.all_results = []
        self.bola_results = []
        self.bfla_results = []
        self.bopla_results = []
        self.urc_results = []
        self.processed_specs = {} # To store specs for BOLA/BFLA testing
        self.stats = {
            "unique_hosts_provided": len(set(urlparse(u).netloc for u in urls)),
            "active_hosts": 0,
            "hosts_with_valid_spec": 0,
            "hosts_with_valid_endpoint": 0,
            "hosts_with_pii": 0,
            "pii_detection_methods": set(),
            "percentage_hosts_with_endpoint": 0,
            "regexes_found": set()
        }
        if getattr(args, "hidden", False) is True:
            self.stats["undocumented_endpoints_found"] = 0
        if getattr(args, "shadow_versions", False) is True:
            self.stats["shadow_endpoints_found"] = 0
        self.diff_report = None
        self.exit_code = 0
        self.TOTAL_REQUESTS = 0

    def _get_max_workers(self):
        raw_threads = getattr(self.args, "threads", 20)
        if isinstance(raw_threads, bool) or not isinstance(raw_threads, int) or raw_threads < 1:
            return 20
        return min(100, raw_threads)

    def _add_request_count(self, component):
        count = getattr(component, "TOTAL_REQUESTS", 0)
        if isinstance(count, int) and not isinstance(count, bool):
            with self._lock:
                self.TOTAL_REQUESTS += count

    def run(self):
        if not is_quiet_output(self.args):
            print_banner()

        start_time = time.time()
        configured_workers = self._get_max_workers()
        url_count = len(self.urls) if self.urls else 1
        max_workers = max(1, min(configured_workers, url_count))
        self._per_url_workers = max(1, configured_workers // max_workers)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futs = {executor.submit(self.process_url, url): url for url in self.urls}
            if not is_quiet_output(self.args):
                with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TimeElapsedColumn(),
                        console=console,
                        redirect_stdout=True,
                        redirect_stderr=True
                ) as progress:
                    task = progress.add_task("Processing URLs", total=len(futs))
                    for fut in as_completed(futs):
                        try:
                            fut.result()
                        except Exception as exc:
                            if self.args.verbose:
                                log(f"Error processing URL {futs[fut]}: {exc}", level="DEBUG")
                        progress.update(task, advance=1)
            else:
                for fut in as_completed(futs):
                    try:
                        fut.result()
                    except Exception as exc:
                        if self.args.verbose:
                            log(f"Error processing URL {futs[fut]}: {exc}", level="DEBUG")

        bola_param, bola_id = None, None
        if self.args.bola_id:
            try:
                bola_param, bola_id = self.args.bola_id.split('=', 1)
            except ValueError:
                 log("Invalid format for --bola-id. Please use 'paramName=yourId'.", level="CRITICAL")

        # --- BFLA Testing ---
        if self.args.test_bfla:
            bfla_tester = BflaTester(self.args, self.session, bola_param, bola_id)
            for spec_url, spec_data in self.processed_specs.items():
                swagger_spec = spec_data['spec']
                parsed_spec_url = urlparse(spec_url)
                api_base_url = spec_data.get('api_base_url') or f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"
                base_path = spec_data['base_path']
                results = bfla_tester.run_tests(swagger_spec, api_base_url, base_path)
                self.bfla_results.extend(results)
            self._add_request_count(bfla_tester)

        # --- BOPLA Testing ---
        if self.args.test_bopla:
            bopla_tester = BoplaTester(self.args, self.session, bola_param, bola_id)
            for spec_url, spec_data in self.processed_specs.items():
                swagger_spec = spec_data['spec']
                parsed_spec_url = urlparse(spec_url)
                api_base_url = spec_data.get('api_base_url') or f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"
                base_path = spec_data['base_path']
                results = bopla_tester.run_tests(swagger_spec, api_base_url, base_path)
                self.bopla_results.extend(results)
            self._add_request_count(bopla_tester)

        # --- BOLA Testing ---
        if self.args.bola and bola_param and bola_id:
            bola_tester = BolaTester(self.args, self.session)
            for spec_url, spec_data in self.processed_specs.items():
                swagger_spec = spec_data['spec']
                target_endpoints = self._find_bola_targets(swagger_spec, bola_param)

                if target_endpoints:
                    parsed_spec_url = urlparse(spec_url)
                    api_base_url = spec_data.get('api_base_url') or f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"
                    base_path = spec_data['base_path']

                    results = bola_tester.run_tests(target_endpoints, bola_param, bola_id, api_base_url, base_path)
                    self.bola_results.extend(results)
            self._add_request_count(bola_tester)

        # --- URC Testing ---
        if self.args.test_urc:
            urc_tester = UrcTester(self.args, self.session)
            for spec_url, spec_data in self.processed_specs.items():
                swagger_spec = spec_data['spec']
                parsed_spec_url = urlparse(spec_url)
                api_base_url = spec_data.get('api_base_url') or f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"
                base_path = spec_data['base_path']
                results = urc_tester.run_tests(swagger_spec, api_base_url, base_path)
                self.urc_results.extend(results)
            self._add_request_count(urc_tester)

        end_time = time.time()
        self._calculate_stats(start_time, end_time)

        diff_path = getattr(self.args, "diff", None)
        if isinstance(diff_path, str) and diff_path.strip():
            try:
                diff_engine = DiffEngine()
                baseline_data = diff_engine.load_baseline(diff_path.strip())
                self.diff_report = diff_engine.compute_diff(
                    baseline_data,
                    self.all_results,
                    bola_results=self.bola_results,
                    bfla_results=self.bfla_results,
                    bopla_results=self.bopla_results,
                    urc_results=self.urc_results,
                )
                self.reporter.diff_report = self.diff_report
            except Exception as exc:
                if not is_quiet_output(self.args):
                    log(f"Failed to compute baseline diff against {diff_path}: {exc}", level="WARNING")

        self.reporter.print_results(self.all_results, self.stats, self.bola_results, self.bfla_results, self.bopla_results, self.urc_results)

        fail_on = getattr(self.args, "fail_on", None)
        if isinstance(fail_on, str) and fail_on.strip():
            should_fail, max_score, match_count = DiffEngine.evaluate_fail_on(
                fail_on,
                self.all_results,
                bola_results=self.bola_results,
                bfla_results=self.bfla_results,
                bopla_results=self.bopla_results,
                urc_results=self.urc_results,
                diff_report=self.diff_report,
            )
            if should_fail:
                self.exit_code = 1
                if not is_quiet_output(self.args):
                    scope_note = "new/regressed finding(s)" if self.diff_report is not None else "finding(s)"
                    log(
                        f"CI gate triggered (--fail-on {fail_on}): {match_count} {scope_note} at or above '{fail_on}' (max severity: {SCORE_TO_LABEL.get(max_score, 'unknown')}).",
                        level="CRITICAL",
                    )

    def process_url(self, base_url):
        with self._lock:
            self.stats["active_hosts"] += 1
        finder = SpecFinder(base_url, self.args, self.session)
        try:
            swagger_spec, spec_url = finder.find()
        finally:
            self._add_request_count(finder)

        if swagger_spec:
            if spec_url and not is_same_origin_host(base_url, spec_url) and not getattr(self.args, "allow_external", False):
                if getattr(self.args, "verbose", False):
                    log(f"Ignoring cross-origin spec URL {spec_url} for {base_url}", level="WARNING")
                return

            base_path = self._get_base_path(swagger_spec, spec_url)

            if not is_quiet_output(self.args):
                log(f"Scanning endpoints with base path: {base_path or '/'}", level="INFO")

            parsed_target_url = urlparse(base_url)
            api_base_url = self._resolve_api_base_url(swagger_spec, spec_url, base_url)
            target_origin = (
                f"{parsed_target_url.scheme}://{parsed_target_url.netloc}"
                if parsed_target_url.scheme and parsed_target_url.netloc
                else api_base_url
            )

            with self._lock:
                self.stats["hosts_with_valid_spec"] += 1
                self.processed_specs[spec_url] = {
                    'spec': swagger_spec,
                    'base_path': base_path,
                    'api_base_url': api_base_url,
                    'auth_origin': target_origin,
                }

            requester = Requester(api_base_url, self.args, self.session)
            requester.auth_origin = target_origin
            requester.max_workers = getattr(self, "_per_url_workers", self._get_max_workers())

            hidden_results = []
            if getattr(self.args, "hidden", False) is True:
                hidden_finder = HiddenEndpointFinder(
                    api_base_url=api_base_url,
                    base_path=base_path,
                    args=self.args,
                    session=self.session,
                    auth_origin=target_origin,
                    spec_url=spec_url,
                )
                hidden_finder.max_workers = requester.max_workers
                try:
                    hidden_results = hidden_finder.discover(swagger_spec)
                finally:
                    self._add_request_count(hidden_finder)

            shadow_results = []
            if getattr(self.args, "shadow_versions", False) is True:
                excluded_paths = {r.get("path_template") for r in hidden_results if r.get("path_template")}
                shadow_finder = ShadowVersionFinder(
                    api_base_url=api_base_url,
                    base_path=base_path,
                    args=self.args,
                    session=self.session,
                    auth_origin=target_origin,
                    spec_url=spec_url,
                )
                shadow_finder.max_workers = requester.max_workers
                try:
                    shadow_results = shadow_finder.discover_shadow_versions(
                        swagger_spec, excluded_paths=excluded_paths
                    )
                finally:
                    self._add_request_count(shadow_finder)

            try:
                documented_results = requester.test_endpoints(swagger_spec, base_path)
            finally:
                self._add_request_count(requester)

            results = hidden_results + shadow_results + (documented_results or [])
            if results:
                self._record_endpoint_results(
                    results,
                    undocumented_count=len(hidden_results),
                    shadow_count=len(shadow_results),
                )
        else:
            if not is_quiet_output(self.args):
                log(f"No spec found for {base_url}.", level="INFO")
            if getattr(self.args, "hidden", False) is True:
                parsed_target_url = urlparse(base_url)
                if parsed_target_url.scheme in ("http", "https") and parsed_target_url.netloc:
                    api_base_url = f"{parsed_target_url.scheme}://{parsed_target_url.netloc}"
                    fallback_base_path = parsed_target_url.path.rstrip("/")
                    if fallback_base_path == "/":
                        fallback_base_path = ""
                    hidden_finder = HiddenEndpointFinder(
                        api_base_url=api_base_url,
                        base_path=fallback_base_path,
                        args=self.args,
                        session=self.session,
                        auth_origin=api_base_url,
                    )
                    hidden_finder.max_workers = getattr(self, "_per_url_workers", self._get_max_workers())
                    try:
                        hidden_results = hidden_finder.discover(None)
                    finally:
                        self._add_request_count(hidden_finder)
                    if hidden_results:
                        self._record_endpoint_results(hidden_results, undocumented_count=len(hidden_results))

    def _record_endpoint_results(self, results, undocumented_count=0, shadow_count=0):
        host_has_pii = False
        pii_types = set()
        regex_values = set()
        for rr in results:
            if rr.get('pii_detected'):
                host_has_pii = True
                pii_details = rr.get('pii_detection_details')
                if isinstance(pii_details, dict):
                    pii_types.update(pii_details.keys())

                regex_patterns = rr.get('regex_patterns_found')
                if isinstance(regex_patterns, dict):
                    regex_values.update(regex_patterns.values())

        with self._lock:
            self.all_results.extend(results)
            self.stats["hosts_with_valid_endpoint"] += 1
            if host_has_pii:
                self.stats["hosts_with_pii"] += 1
            if undocumented_count and "undocumented_endpoints_found" in self.stats:
                self.stats["undocumented_endpoints_found"] += undocumented_count
            if shadow_count and "shadow_endpoints_found" in self.stats:
                self.stats["shadow_endpoints_found"] += shadow_count
            self.stats["pii_detection_methods"].update(pii_types)
            self.stats["regexes_found"].update(regex_values)

    def _expand_server_url(self, server_entry):
        if not isinstance(server_entry, dict):
            return '/'
        url = server_entry.get('url', '/')
        if not isinstance(url, str):
            return '/'
        variables = server_entry.get('variables')
        if isinstance(variables, dict):
            for var_name, var_def in variables.items():
                if isinstance(var_def, dict) and 'default' in var_def:
                    url = url.replace(f"{{{var_name}}}", str(var_def['default']))
        return url

    def _resolve_api_base_url(self, swagger_spec, spec_url, base_url):
        parsed_target_url = urlparse(base_url)
        target_origin = (
            f"{parsed_target_url.scheme}://{parsed_target_url.netloc}"
            if parsed_target_url.scheme and parsed_target_url.netloc
            else base_url
        )
        if spec_url:
            parsed_spec_url = urlparse(spec_url)
            spec_origin = (
                f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"
                if parsed_spec_url.scheme and parsed_spec_url.netloc
                else target_origin
            )
            default_origin = target_origin if not is_same_origin_host(base_url, spec_url) else spec_origin
        else:
            default_origin = target_origin

        candidate = None
        servers = swagger_spec.get('servers') if isinstance(swagger_spec, dict) else None
        if isinstance(servers, list) and servers:
            server_url = self._expand_server_url(servers[0])
            parsed_server = urlparse(server_url)
            if parsed_server.scheme in ('http', 'https') and parsed_server.netloc and '{' not in parsed_server.netloc:
                candidate = f"{parsed_server.scheme}://{parsed_server.netloc}"
        elif isinstance(swagger_spec, dict) and isinstance(swagger_spec.get('host'), str):
            raw_host = swagger_spec['host'].strip()
            if raw_host and '{' not in raw_host:
                schemes = swagger_spec.get('schemes')
                default_scheme = urlparse(default_origin).scheme or 'https'
                if isinstance(schemes, list):
                    valid_schemes = [s for s in schemes if isinstance(s, str) and s.lower() in ('http', 'https')]
                    scheme = valid_schemes[0].lower() if valid_schemes else default_scheme
                else:
                    scheme = default_scheme
                candidate = f"{scheme}://{raw_host}"

        if candidate:
            if is_same_origin_host(default_origin, candidate) or getattr(self.args, 'allow_external', False):
                return candidate
            if getattr(self.args, 'verbose', False):
                log(f"Ignoring cross-origin server URL {candidate} for {default_origin} (use --allow-external to enable).", level="WARNING")

        return default_origin

    def _get_base_path(self, swagger_spec, spec_url):
        base_path = '/'
        if 'servers' in swagger_spec and isinstance(swagger_spec['servers'], list) and swagger_spec['servers']:
            server_url = self._expand_server_url(swagger_spec['servers'][0])
            base_path = urlparse(server_url).path or '/'
        elif isinstance(swagger_spec.get('basePath'), str) and swagger_spec['basePath']:
            base_path = swagger_spec['basePath']

        if base_path == '/':
            path = urlparse(spec_url).path
            if '/' in path.strip('/'):
                common_spec_dirs = ['/v1', '/v2', '/v3', '/api', '/docs', '/api-docs']
                for common_dir in common_spec_dirs:
                    if common_dir in path:
                        base_path = path.split(common_dir)[0]
                        break

        if base_path.endswith('/') and len(base_path) > 1:
            base_path = base_path[:-1]
        if base_path == '/':
            return ''
        return base_path

    def _find_bola_targets(self, swagger_spec, bola_param):
        targets = []
        is_risk = bool(getattr(self.args, "risk", False))
        for path, methods in swagger_spec.get('paths', {}).items():
            if not isinstance(methods, dict):
                continue
            if f"{{{bola_param}}}" in path:
                for method, details in methods.items():
                    method_lower = method.lower()
                    if method_lower not in HTTP_METHODS or not isinstance(details, dict):
                        continue
                    if method_lower not in SAFE_HTTP_METHODS and not is_risk:
                        if getattr(self.args, "verbose", False):
                            log(f"Skipping unsafe BOLA method {method.upper()} {path} (use -risk to include).", level="INFO")
                        continue
                    targets.append({'path': path, 'method': method})
        return targets

    def _calculate_stats(self, start_time, end_time):
        scan_duration = end_time - start_time

        if self.stats["active_hosts"] > 0:
            self.stats["percentage_hosts_with_endpoint"] = round(
                (self.stats["hosts_with_valid_endpoint"] / self.stats["active_hosts"]) * 100, 2
            )

        self.stats["total_requests_sent"] = self.TOTAL_REQUESTS
        if scan_duration > 0:
            self.stats["average_requests_per_second"] = round(self.TOTAL_REQUESTS / scan_duration, 2)
        else:
            self.stats["average_requests_per_second"] = 0

        self.stats["pii_detection_methods"] = list(self.stats["pii_detection_methods"])
        self.stats["regexes_found"] = list(self.stats["regexes_found"])
