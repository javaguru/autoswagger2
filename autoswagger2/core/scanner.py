# autoswagger2/core/scanner.py
# The main orchestrator for the scan.

import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from ..discovery.finder import SpecFinder
from .requester import Requester
from ..reporting.reporter import Reporter
from ..analysis.bola import BolaTester
from ..analysis.bfla import BflaTester
from ..analysis.bopla import BoplaTester
from ..analysis.urc import UrcTester
from ..utils.helpers import log, console, print_banner

class Scanner:
    def __init__(self, urls, args, session):
        self.urls = urls
        self.args = args
        self.session = session
        self.reporter = Reporter(args)
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
        self.TOTAL_REQUESTS = 0

    def run(self):
        if not self.args.product:
            print_banner()

        start_time = time.time()
        max_workers = min(100, os.cpu_count() * 5, len(self.urls)) if self.urls else 1

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futs = {executor.submit(self.process_url, url): url for url in self.urls}
            if not self.args.product:
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
                api_base_url = f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"
                base_path = spec_data['base_path']
                results = bfla_tester.run_tests(swagger_spec, api_base_url, base_path)
                self.bfla_results.extend(results)

        # --- BOPLA Testing ---
        if self.args.test_bopla:
            bopla_tester = BoplaTester(self.args, self.session)
            for spec_url, spec_data in self.processed_specs.items():
                swagger_spec = spec_data['spec']
                parsed_spec_url = urlparse(spec_url)
                api_base_url = f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"
                base_path = spec_data['base_path']
                results = bopla_tester.run_tests(swagger_spec, api_base_url, base_path)
                self.bopla_results.extend(results)

        # --- BOLA Testing ---
        if self.args.bola and bola_param and bola_id:
            bola_tester = BolaTester(self.args, self.session)
            for spec_url, spec_data in self.processed_specs.items():
                swagger_spec = spec_data['spec']
                target_endpoints = self._find_bola_targets(swagger_spec, bola_param)

                if target_endpoints:
                    parsed_spec_url = urlparse(spec_url)
                    api_base_url = f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"
                    base_path = spec_data['base_path']

                    results = bola_tester.run_tests(target_endpoints, bola_param, bola_id, api_base_url, base_path)
                    self.bola_results.extend(results)

        # --- URC Testing ---
        if self.args.test_urc:
            urc_tester = UrcTester(self.args, self.session)
            for spec_url, spec_data in self.processed_specs.items():
                swagger_spec = spec_data['spec']
                parsed_spec_url = urlparse(spec_url)
                api_base_url = f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"
                base_path = spec_data['base_path']
                results = urc_tester.run_tests(swagger_spec, api_base_url, base_path)
                self.urc_results.extend(results)

        end_time = time.time()
        self._calculate_stats(start_time, end_time)
        self.reporter.print_results(self.all_results, self.stats, self.bola_results, self.bfla_results, self.bopla_results, self.urc_results)

    def process_url(self, base_url):
        self.stats["active_hosts"] += 1
        finder = SpecFinder(base_url, self.args, self.session)
        swagger_spec, spec_url = finder.find()

        if swagger_spec:
            self.stats["hosts_with_valid_spec"] += 1

            base_path = self._get_base_path(swagger_spec, spec_url)
            self.processed_specs[spec_url] = {'spec': swagger_spec, 'base_path': base_path}

            if not self.args.product:
                log(f"Scanning endpoints with base path: {base_path}", level="INFO")

            parsed_spec_url = urlparse(spec_url)
            api_base_url = f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"

            requester = Requester(api_base_url, self.args, self.session)
            results = requester.test_endpoints(swagger_spec, base_path)
            self.TOTAL_REQUESTS += requester.TOTAL_REQUESTS

            if results:
                self.all_results.extend(results)
                self.stats["hosts_with_valid_endpoint"] += 1
                for rr in results:
                    if rr.get('pii_detected'):
                        self.stats["hosts_with_pii"] = 1
                        pii_details = rr.get('pii_detection_details')
                        if isinstance(pii_details, dict):
                            for pii_type in pii_details.keys():
                                self.stats["pii_detection_methods"].add(pii_type)

                        regex_patterns = rr.get('regex_patterns_found')
                        if isinstance(regex_patterns, dict):
                            for pattern in regex_patterns.values():
                                self.stats["regexes_found"].add(pattern)
        else:
            log(f"No spec found for {base_url}.", level="INFO")

    def _get_base_path(self, swagger_spec, spec_url):
        base_path = '/'
        if 'servers' in swagger_spec and isinstance(swagger_spec['servers'], list) and swagger_spec['servers']:
            server_url = swagger_spec['servers'][0].get('url', '/')
            base_path = urlparse(server_url).path
        elif 'basePath' in swagger_spec:
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
        return base_path

    def _find_bola_targets(self, swagger_spec, bola_param):
        targets = []
        for path, methods in swagger_spec.get('paths', {}).items():
            if f"{{{bola_param}}}" in path:
                for method, details in methods.items():
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
