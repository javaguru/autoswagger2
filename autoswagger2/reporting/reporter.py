# autoswagger2/reporting/reporter.py
# Manages the display of results.

from rich.table import Table
from rich.console import Console
import json

from ..utils.helpers import log

class Reporter:
    def __init__(self, args):
        self.args = args
        self.console = Console()

    def print_results(self, all_results, stats, bola_results=None, bfla_results=None, bopla_results=None, urc_results=None):
        """
        Groups, filters, and prints the final results in the specified format.
        """
        grouped_results = {}
        for r in all_results:
            if r:
                key = (r['method'], r['path_template'])
                existing = grouped_results.get(key)
                if not existing or r['content_length'] > existing['content_length']:
                    grouped_results[key] = r

        final_results = list(grouped_results.values())
        final_results.sort(key=lambda x: (-x['content_length'], not x.get('pii_detected', False)))

        if self.args.product:
            self._print_product_json(final_results, stats, bola_results, bfla_results, bopla_results, urc_results)
        elif self.args.json:
            self._print_json(final_results, stats, bola_results, bfla_results, bopla_results, urc_results)
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
            final_results = [rr for rr in final_results if rr['status_code'] == 200]

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

            has_details_column = any(r.get('pii_detected') or (r.get('status_code') >= 400 and r.get('debug_info_detected')) for r in final_results)
            if has_details_column:
                table.add_column("Response / PII Details", style="green", overflow="fold")

            for rr in final_results:
                pii_status = "[bold red]Yes[/bold red]" if rr.get('pii_detected') else "No"
                debug_status = "[bold yellow]Yes[/bold yellow]" if rr.get('debug_info_detected') else "No"
                has_finding = rr.get('pii_detected') or rr.get('debug_info_detected')
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
                        details_content = f"[bold]Type(s):[/bold] {pii_types}\n[bold]Preview:[/bold] {truncated_preview}"
                    elif rr.get('debug_info_detected'):
                        details_content = f"[yellow]{truncated_preview}[/yellow]"
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
