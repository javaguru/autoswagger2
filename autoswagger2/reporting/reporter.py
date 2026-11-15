# autoswagger2/reporting/reporter.py
# Manages the display of results.

from rich.table import Table
from rich.console import Console
import html as html_lib
import json

from ..utils.helpers import log

class Reporter:
    def __init__(self, args):
        self.args = args
        self.console = Console()

    def _get_severity_score(self, severity_str):
        levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return levels.get(severity_str.lower(), 0) if severity_str else 0

    def _eval_endpoint_severity(self, result):
        if result.get('pii_detected'):
            details = result.get('pii_detection_details') or {}
            for k, v in details.items():
                if 'regex' in v.get('detection_methods', []):
                    return 4 # critical (secrets)
            return 3 # high (pii)
        if result.get('vuln_indicators'):
            return 3 # high
        if result.get('debug_info_detected'):
            return 2 # medium
        if result.get('interesting_response'):
            return 2 # medium
        if result.get('status_code', 0) < 400:
            return 1 # low
        return 0 # info

    def _filter_by_severity(self, all_results, bola_results, bfla_results, bopla_results, urc_results):
        if not hasattr(self.args, 'severity') or not self.args.severity:
            return all_results, bola_results, bfla_results, bopla_results, urc_results
            
        min_score = self._get_severity_score(self.args.severity)
        
        filtered_results = [r for r in all_results if r and self._eval_endpoint_severity(r) >= min_score]
        
        filt_bola = [r for r in (bola_results or []) if (4 if r.get('vulnerable') else 0) >= min_score] if bola_results else None
        filt_bfla = [r for r in (bfla_results or []) if (4 if r.get('vulnerable') else 0) >= min_score] if bfla_results else None
        filt_bopla = [r for r in (bopla_results or []) if (4 if r.get('vulnerable') else 0) >= min_score] if bopla_results else None
        filt_urc = [r for r in (urc_results or []) if (3 if r.get('vulnerable') else 0) >= min_score] if urc_results else None
        
        return filtered_results, filt_bola, filt_bfla, filt_bopla, filt_urc


    def _result_priority(self, r):
        status = r.get('status_code', 0)
        status_int = status if isinstance(status, int) else 0
        is_2xx = 1 if 200 <= status_int < 300 else 0
        is_non_error = 1 if 0 < status_int < 400 else 0
        severity = self._eval_endpoint_severity(r)
        has_pii = 1 if r.get('pii_detected') else 0
        has_debug = 1 if r.get('debug_info_detected') else 0
        has_sens_params = 1 if r.get('sensitive_parameters') else 0
        content_len = r.get('content_length', 0)
        return (severity, has_pii, is_2xx, has_debug, has_sens_params, is_non_error, content_len)

    def print_results(self, all_results, stats, bola_results=None, bfla_results=None, bopla_results=None, urc_results=None):
        """
        Groups, filters, and prints the final results in the specified format.
        """
        all_results, bola_results, bfla_results, bopla_results, urc_results = self._filter_by_severity(
            all_results, bola_results, bfla_results, bopla_results, urc_results
        )

        grouped_results = {}
        for r in all_results:
            if r:
                key = (r['method'], r['path_template'])
                existing = grouped_results.get(key)
                if not existing or self._result_priority(r) > self._result_priority(existing):
                    grouped_results[key] = r

        final_results = list(grouped_results.values())
        final_results.sort(key=self._result_priority, reverse=True)

        if self.args.product:
            self._print_product_json(final_results, stats, bola_results, bfla_results, bopla_results, urc_results)
        elif self.args.json:
            self._print_json(final_results, stats, bola_results, bfla_results, bopla_results, urc_results)
        elif getattr(self.args, 'csv', False):
            self.export_csv(final_results, bola_results, bfla_results, bopla_results, urc_results)
        elif getattr(self.args, 'sarif', False):
            self.export_sarif(final_results, bola_results, bfla_results, bopla_results, urc_results)
        elif getattr(self.args, 'html', False):
            self.export_html(final_results, stats, bola_results, bfla_results, bopla_results, urc_results)
        else:
            self._print_table(final_results, stats)
            if bola_results:
                self._print_bola_table(bola_results)
            if bfla_results:
                self._print_bfla_table(bfla_results)
            if bopla_results:
                self._print_bopla_table(bopla_results)
            if urc_results:
                self._print_urc_table(urc_results)

    def _print_table(self, final_results, stats):
        """
        Prints the results in a formatted table using Rich.
        """
        if self.args.all:
            final_results = [rr for rr in final_results if rr['status_code'] not in [401, 403]]
        else:
            final_results = [
                rr for rr in final_results
                if rr['status_code'] == 200 or (rr.get('undocumented') is True and rr['status_code'] not in [401, 403, 404])
            ]

        if not final_results:
            log("No valid API responses found.", level="INFO")
        else:
            table = Table(title="API Endpoints", show_lines=False)
            table.add_column("Method", style="cyan", no_wrap=True)
            table.add_column("URL", style="green", overflow="fold")
            table.add_column("Status Code", style="green")
            table.add_column("Content Length", style="yellow")
            table.add_column("PII/Secret", style="red")
            table.add_column("Debug Info", style="yellow")
            if self.args.risk:
                table.add_column("Body", style="bright_blue", overflow="fold")

            has_details_column = any(
                r.get('pii_detected')
                or r.get('vuln_indicators')
                or (r.get('status_code', 0) >= 400 and r.get('debug_info_detected'))
                or r.get('sensitive_parameters')
                for r in final_results
            )
            if has_details_column:
                table.add_column("Response / PII Details", style="green", overflow="fold")

            for rr in final_results:
                pii_status = "[bold red]Yes[/bold red]" if rr.get('pii_detected') else "No"
                debug_status = "[bold yellow]Yes[/bold yellow]" if rr.get('debug_info_detected') else "No"
                has_finding = rr.get('pii_detected') or rr.get('vuln_indicators') or rr.get('debug_info_detected') or rr.get('sensitive_parameters')
                method_display = f"[bright_cyan]{rr['method']}[/bright_cyan]" if has_finding else rr['method']
                status_code_display = f"[bright_green]{str(rr['status_code'])}[/bright_green]" if has_finding else str(rr['status_code'])
                url_to_display = rr['url']
                if len(url_to_display) > 200:
                    url_to_display = url_to_display[:200] + '(...)'
                url_display = f"[bright_red]{url_to_display}[/bright_red]" if rr.get('pii_detected') else f"[red]{url_to_display}[/red]" if rr.get('debug_info_detected') else url_to_display

                row = [method_display, url_display, status_code_display, f"{rr['content_length']:,}", pii_status, debug_status]
                if self.args.risk:
                    row.append(rr['body'] if rr['body'] else "")

                if has_details_column:
                    details_content = ""
                    full_preview = rr.get('response_body', '')
                    truncated_preview = (full_preview[:197] + '...') if len(full_preview) > 200 else full_preview

                    if rr.get('pii_detected') and rr.get('pii_data'):
                        pii_types = ', '.join(rr['pii_data'].keys())
                        
                        # Extract matched values for clarity
                        matched_values = []
                        for vals in rr['pii_data'].values():
                            matched_values.extend(vals)
                        matched_str = ', '.join(matched_values)
                        if len(matched_str) > 100:
                            matched_str = matched_str[:97] + '...'
                            
                        details_content += f"[bold]Type(s):[/bold] {pii_types}\n[bold]Match(es):[/bold] {matched_str}\n[bold]Preview:[/bold] {truncated_preview}"
                    elif rr.get('debug_info_detected'):
                        details_content += f"[yellow]{truncated_preview}[/yellow]"

                    if rr.get('vuln_indicators'):
                        if details_content:
                            details_content += "\n"
                        details_content += "[bold red]Vuln Indicators:[/bold red] " + ", ".join(rr['vuln_indicators'])
                        if (
                            rr.get('undocumented') is True
                            and truncated_preview
                            and not (rr.get('pii_detected') and rr.get('pii_data'))
                            and not rr.get('debug_info_detected')
                        ):
                            details_content += f"\n[bold]Preview:[/bold] {truncated_preview}"
                        
                    if rr.get('sensitive_parameters'):
                        param_strs = []
                        for sp in rr['sensitive_parameters']:
                            if sp['in'] in ['query', 'path']:
                                param_strs.append(f"[red]CWE-598: {sp['category']} in {sp['in']} ({sp['name']})[/red]")
                            else:
                                param_strs.append(f"[yellow]{sp['category']} in {sp['in']} ({sp['name']})[/yellow]")
                        if details_content:
                            details_content += "\n"
                        details_content += "[bold]Sensitive Params:[/bold] " + ", ".join(param_strs)
                        
                    row.append(details_content)

                table.add_row(*row)
            self.console.print(table)

        if self.args.stats:
            self.print_stats(stats)

    def _print_bola_table(self, bola_results):
        if not bola_results:
            log("No BOLA vulnerabilities found.", level="INFO")
            return

        table = Table(title="BOLA Test Results", show_lines=True)
        table.add_column("Method", style="cyan")
        table.add_column("Endpoint", style="green")
        table.add_column("Baseline ID", style="magenta")
        table.add_column("Attack ID", style="magenta")
        table.add_column("Baseline Status", style="blue")
        table.add_column("Attack Status", style="blue")
        table.add_column("Result", style="red")

        for res in bola_results:
            result_text = "[bold green]Not Vulnerable[/bold green]"
            if res['vulnerable']:
                result_text = "[bold red]VULNERABLE[/bold red]"

            table.add_row(
                res['method'],
                res['url_template'],
                str(res['baseline_id']),
                str(res['attack_id']),
                str(res['baseline_status']),
                str(res['attack_status']),
                result_text
            )
        self.console.print(table)

    def _print_bfla_table(self, bfla_results):
        if not bfla_results:
            log("No BFLA vulnerabilities found.", level="INFO")
            return

        table = Table(title="BFLA Test Results", show_lines=True)
        table.add_column("Method", style="cyan")
        table.add_column("Endpoint", style="green")
        table.add_column("Request Body", style="bright_blue")
        table.add_column("Status Code", style="blue")
        table.add_column("Result", style="red")

        for res in bfla_results:
            result_text = "[bold green]Likely Not Vulnerable[/bold green]"
            if res['vulnerable']:
                result_text = "[bold red]VULNERABLE[/bold red]"

            table.add_row(
                res['method'],
                res['url_template'],
                res['request_body'] if res['request_body'] else "",
                str(res['status_code']),
                result_text
            )
        self.console.print(table)

    def _print_bopla_table(self, bopla_results):
        if not bopla_results:
            log("No BOPLA vulnerabilities found.", level="INFO")
            return

        table = Table(title="BOPLA Test Results", show_lines=True)
        table.add_column("Method", style="cyan")
        table.add_column("Endpoint", style="green")
        table.add_column("Request Body", style="bright_blue")
        table.add_column("Status Code", style="blue")
        table.add_column("Result", style="red")

        for res in bopla_results:
            result_text = "[bold red]VULNERABLE[/bold red]" if res['vulnerable'] else "[bold green]Not Vulnerable[/bold green]"
            table.add_row(
                res['method'],
                res['url_template'],
                res['request_body'],
                str(res['status_code']),
                result_text
            )
        self.console.print(table)

    def _print_urc_table(self, urc_results):
        if not urc_results:
            log("No potential URC vulnerabilities found.", level="INFO")
            return

        table = Table(title="Unrestricted Resource Consumption (URC) Test Results", show_lines=True)
        table.add_column("Method", style="cyan")
        table.add_column("Endpoint", style="green")
        table.add_column("Parameter", style="magenta")
        table.add_column("Attack Value", style="magenta")
        table.add_column("Response Time (ms)", style="blue")
        table.add_column("Content Length", style="yellow")
        table.add_column("Status Code", style="blue")
        table.add_column("Result", style="red")

        for res in urc_results:
            result_text = "[bold red]POTENTIALLY VULNERABLE[/bold red]" if res['vulnerable'] else "[bold green]Likely Not Vulnerable[/bold green]"
            table.add_row(
                res['method'],
                res['url_template'],
                res['parameter'],
                str(res['attack_value']),
                str(res['response_time_ms']),
                f"{res['content_length']:,}",
                str(res['status_code']),
                result_text
            )
        self.console.print(table)

    def _format_endpoint_details(self, r):
        details_parts = []
        if r.get('pii_data'):
            details_parts.append("PII: " + ', '.join(r['pii_data'].keys()))
        if r.get('vuln_indicators'):
            details_parts.append("Vuln: " + ', '.join(r['vuln_indicators']))
        if r.get('sensitive_parameters'):
            sp_str = ', '.join([f"{sp['category']} in {sp['in']} ({sp['name']})" for sp in r['sensitive_parameters']])
            details_parts.append("Params: " + sp_str)
        return details_parts

    def _collect_active_vuln_findings(self, bola_results=None, bfla_results=None, bopla_results=None, urc_results=None):
        findings = []
        for res in (bola_results or []):
            if res and res.get('vulnerable'):
                findings.append({
                    "category": "BOLA",
                    "rule_id": "BOLA-Vulnerability",
                    "level": "error",
                    "method": res.get('method', ''),
                    "endpoint": res.get('url_template', ''),
                    "status": res.get('attack_status', ''),
                    "content_length": res.get('attack_length', ''),
                    "details": f"BOLA Vulnerable (baseline={res.get('baseline_id', '')}, attack={res.get('attack_id', '')})",
                })
        for res in (bfla_results or []):
            if res and res.get('vulnerable'):
                findings.append({
                    "category": "BFLA",
                    "rule_id": "BFLA-Vulnerability",
                    "level": "error",
                    "method": res.get('method', ''),
                    "endpoint": res.get('url_template', ''),
                    "status": res.get('status_code', ''),
                    "content_length": "",
                    "details": "BFLA Vulnerable (exposed privileged/admin endpoint)",
                })
        for res in (bopla_results or []):
            if res and res.get('vulnerable'):
                findings.append({
                    "category": "BOPLA",
                    "rule_id": "BOPLA-Vulnerability",
                    "level": "error",
                    "method": res.get('method', ''),
                    "endpoint": res.get('url_template', ''),
                    "status": res.get('status_code', ''),
                    "content_length": "",
                    "details": f"BOPLA Vulnerable (property={res.get('injected_property', 'mass-assignment')}, body={res.get('request_body', '')})",
                })
        for res in (urc_results or []):
            if res and res.get('vulnerable'):
                findings.append({
                    "category": "URC",
                    "rule_id": "URC-Vulnerability",
                    "level": "warning",
                    "method": res.get('method', ''),
                    "endpoint": res.get('url_template', ''),
                    "status": res.get('status_code', ''),
                    "content_length": res.get('content_length', ''),
                    "details": f"URC Vulnerable (param={res.get('parameter', '')}, value={res.get('attack_value', '')}, time_ms={res.get('response_time_ms', '')})",
                })
        return findings

    def export_csv(self, final_results, bola_results=None, bfla_results=None, bopla_results=None, urc_results=None):
        import csv
        outfile = getattr(self.args, 'out', None) or "autoswagger_report.csv"
        active_vulns = self._collect_active_vuln_findings(bola_results, bfla_results, bopla_results, urc_results)
        with open(outfile, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Method", "URL", "Status Code", "Content Length", "PII/Secret Detected", "Debug Info Detected", "Details"])
            for r in final_results:
                pii_detected = "Yes" if r.get('pii_detected') else "No"
                debug_detected = "Yes" if r.get('debug_info_detected') else "No"
                details = ' | '.join(self._format_endpoint_details(r))
                writer.writerow([r['method'], r['url'], r['status_code'], r['content_length'], pii_detected, debug_detected, details])
            for item in active_vulns:
                writer.writerow([
                    item['method'],
                    item['endpoint'],
                    item['status'],
                    item['content_length'],
                    "No",
                    "No",
                    item['details'],
                ])
        log(f"Results exported to CSV: {outfile}", level="SUCCESS")

    def export_sarif(self, final_results, bola_results=None, bfla_results=None, bopla_results=None, urc_results=None):
        outfile = getattr(self.args, 'out', None) or "autoswagger_report.sarif"
        sarif_results = []
        for r in final_results:
            if r.get('pii_detected') or r.get('vuln_indicators') or r.get('debug_info_detected') or r.get('sensitive_parameters'):
                rule_id = (
                    "PII-Secret-Detected" if r.get('pii_detected')
                    else "Vulnerability-Indicator" if r.get('vuln_indicators')
                    else "Sensitive-Params" if r.get('sensitive_parameters')
                    else "Debug-Info-Leak"
                )
                details_parts = self._format_endpoint_details(r)
                details = ' | '.join(details_parts) if details_parts else "Sensitive Data"
                
                sarif_results.append({
                    "ruleId": rule_id,
                    "level": "error" if (r.get('pii_detected') or r.get('vuln_indicators')) else "warning",
                    "message": { "text": f"{rule_id}: {details}" },
                    "locations": [{ "physicalLocation": { "artifactLocation": { "uri": r['url'] } } }]
                })

        for item in self._collect_active_vuln_findings(bola_results, bfla_results, bopla_results, urc_results):
            sarif_results.append({
                "ruleId": item['rule_id'],
                "level": item['level'],
                "message": {"text": f"{item['rule_id']} [{item['method']} {item['endpoint']}] (status {item['status']}): {item['details']}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(item['endpoint'])}}}]
            })

        sarif_log = {
            "version": "2.1.0",
            "$schema": "http://json.schemastore.org/sarif-2.1.0-rtm.5",
            "runs": [{
                "tool": { "driver": { "name": "AutoSwagger2", "version": "2.0" } },
                "results": sarif_results
            }]
        }
        with open(outfile, 'w', encoding='utf-8') as f:
            json.dump(sarif_log, f, indent=2)
        log(f"Results exported to SARIF: {outfile}", level="SUCCESS")

    def export_html(self, final_results, stats, bola_results=None, bfla_results=None, bopla_results=None, urc_results=None):
        outfile = getattr(self.args, 'out', None) or "autoswagger_report.html"
        html = "<html><head><meta charset='utf-8'><title>AutoSwagger2 Report</title>"
        html += "<style>body{font-family:sans-serif;} table { border-collapse: collapse; width: 100%; margin-top:20px;} th, td { border: 1px solid #ddd; padding: 8px; text-align: left; } th { background-color: #f2f2f2; } .crit { color: red; font-weight: bold; } .warn { color: orange; font-weight: bold; }</style>"
        html += "</head><body><h2>AutoSwagger2 Security Scan Report</h2>"
        html += "<table><tr><th>Method</th><th>URL</th><th>Status</th><th>PII/Secrets</th><th>Debug Info</th><th>Details</th></tr>"
        for r in final_results:
            pii_val = "<span class='crit'>Yes</span>" if r.get('pii_detected') else "No"
            debug_val = "<span class='warn'>Yes</span>" if r.get('debug_info_detected') else "No"
            details = html_lib.escape(' | '.join(self._format_endpoint_details(r)), quote=True)
            safe_method = html_lib.escape(str(r.get('method', '')), quote=True)
            safe_url = html_lib.escape(str(r.get('url', '')), quote=True)
            safe_status = html_lib.escape(str(r.get('status_code', '')), quote=True)
            html += f"<tr><td>{safe_method}</td><td>{safe_url}</td><td>{safe_status}</td><td>{pii_val}</td><td>{debug_val}</td><td>{details}</td></tr>"
        html += "</table>"

        active_vulns = self._collect_active_vuln_findings(bola_results, bfla_results, bopla_results, urc_results)
        if active_vulns:
            html += "<h3>Active Vulnerability Findings (BOLA / BFLA / BOPLA / URC)</h3>"
            html += "<table><tr><th>Category</th><th>Method</th><th>Endpoint</th><th>Status</th><th>Details</th></tr>"
            for item in active_vulns:
                safe_cat = html_lib.escape(str(item['category']), quote=True)
                safe_mthd = html_lib.escape(str(item['method']), quote=True)
                safe_ep = html_lib.escape(str(item['endpoint']), quote=True)
                safe_st = html_lib.escape(str(item['status']), quote=True)
                safe_det = html_lib.escape(str(item['details']), quote=True)
                html += f"<tr><td class='crit'>{safe_cat}</td><td>{safe_mthd}</td><td>{safe_ep}</td><td>{safe_st}</td><td>{safe_det}</td></tr>"
            html += "</table>"

        html += "</body></html>"
        with open(outfile, 'w', encoding='utf-8') as f:
            f.write(html)
        log(f"Results exported to HTML: {outfile}", level="SUCCESS")

    def _print_json(self, final_results, stats, bola_results=None, bfla_results=None, bopla_results=None, urc_results=None):
        output = {"results": final_results}
        if bola_results:
            output["bola_findings"] = bola_results
        if bfla_results:
            output["bfla_findings"] = bfla_results
        if bopla_results:
            output["bopla_findings"] = bopla_results
        if urc_results:
            output["urc_findings"] = urc_results
        if self.args.stats:
            output["stats"] = stats
        self.console.print_json(data=output)

    def _print_product_json(self, all_results, stats, bola_results=None, bfla_results=None, bopla_results=None, urc_results=None):
        final_results = [r for r in all_results if r and (r.get('pii_detected') or r.get('interesting_response'))]

        clean_final_results = []
        for r in final_results:
            clean_res = {k: v for k, v in r.items() if k != 'path_template'}
            if not clean_res['body']:
                del clean_res['body']
            clean_final_results.append(clean_res)

        output = {"results": clean_final_results}
        if bola_results:
            output["bola_findings"] = [res for res in bola_results if res['vulnerable']]
        if bfla_results:
            output["bfla_findings"] = [res for res in bfla_results if res['vulnerable']]
        if bopla_results:
            output["bopla_findings"] = [res for res in bopla_results if res['vulnerable']]
        if urc_results:
            output["urc_findings"] = [res for res in urc_results if res['vulnerable']]
        if self.args.stats:
            output["stats"] = stats
        self.console.print_json(data=output)

    def print_stats(self, stats):
        stats_table = Table(title="Scan Statistics", show_lines=False)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="bright_cyan")

        formatted_stats = stats.copy()
        formatted_stats["percentage_hosts_with_endpoint"] = f"{formatted_stats['percentage_hosts_with_endpoint']}%"
        formatted_stats["pii_detection_methods"] = ', '.join(formatted_stats["pii_detection_methods"])
        formatted_stats["regexes_found"] = ', '.join(formatted_stats["regexes_found"])

        for k, v in formatted_stats.items():
            if isinstance(v, float):
                v = f"{v:.2f}"
            elif isinstance(v, int):
                v = f"{v:,}"
            stats_table.add_row(k.replace('_',' ').title(), str(v))

        self.console.print(stats_table)
