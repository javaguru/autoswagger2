import pytest
import os
import json
from argparse import Namespace
from unittest.mock import MagicMock, patch
from autoswagger2.reporting.reporter import Reporter

def test_get_severity_score():
    reporter = Reporter(Namespace())
    assert reporter._get_severity_score("critical") == 4
    assert reporter._get_severity_score("HIGH") == 3
    assert reporter._get_severity_score("medium") == 2
    assert reporter._get_severity_score("low") == 1
    assert reporter._get_severity_score("info") == 0
    assert reporter._get_severity_score("unknown") == 0

def test_eval_endpoint_severity():
    reporter = Reporter(Namespace())
    # Critical PII with regex
    assert reporter._eval_endpoint_severity({"pii_detected": True, "pii_detection_details": {"secret": {"detection_methods": ["regex"]}}}) == 4
    # High PII no regex
    assert reporter._eval_endpoint_severity({"pii_detected": True, "pii_detection_details": {"email": {"detection_methods": ["presidio"]}}}) == 3
    # Medium debug info
    assert reporter._eval_endpoint_severity({"debug_info_detected": True}) == 2
    # Medium interesting response
    assert reporter._eval_endpoint_severity({"interesting_response": True}) == 2
    # Low status < 400
    assert reporter._eval_endpoint_severity({"status_code": 200}) == 1
    # Info otherwise
    assert reporter._eval_endpoint_severity({"status_code": 500}) == 0

def test_filter_by_severity():
    args = Namespace(severity="high")
    reporter = Reporter(args)
    
    all_results = [
        {"pii_detected": True, "pii_detection_details": {"secret": {"detection_methods": ["regex"]}}}, # critical -> keep
        {"status_code": 200} # low -> filter out
    ]
    bola_results = [{"vulnerable": True}, {"vulnerable": False}]
    bfla_results = [{"vulnerable": True}]
    bopla_results = [{"vulnerable": False}]
    urc_results = [{"vulnerable": True}]
    
    f_all, f_bola, f_bfla, f_bopla, f_urc = reporter._filter_by_severity(
        all_results, bola_results, bfla_results, bopla_results, urc_results
    )
    
    assert len(f_all) == 1
    assert len(f_bola) == 1  # vulnerable is critical (4) >= high (3)
    assert len(f_bfla) == 1  # vulnerable is critical (4) >= high (3)
    assert len(f_bopla) == 0 # not vulnerable is 0 < high
    assert len(f_urc) == 1   # vulnerable is high (3) >= high (3)

def test_export_csv(tmp_path):
    outfile = tmp_path / "report.csv"
    args = Namespace(out=str(outfile))
    reporter = Reporter(args)
    
    final_results = [
        {
            "method": "GET",
            "url": "http://example.com/api",
            "status_code": 200,
            "content_length": 123,
            "pii_detected": True,
            "pii_data": {"email": ["test@example.com"]},
            "sensitive_parameters": [{"category": "email", "in": "query", "name": "email"}]
        }
    ]
    reporter.export_csv(final_results)
    assert outfile.exists()
    content = outfile.read_text(encoding="utf-8")
    assert "GET,http://example.com/api,200,123,Yes,No" in content

def test_export_sarif(tmp_path):
    outfile = tmp_path / "report.sarif"
    args = Namespace(out=str(outfile))
    reporter = Reporter(args)
    
    final_results = [
        {
            "method": "GET",
            "url": "http://example.com/api",
            "status_code": 200,
            "content_length": 123,
            "pii_detected": True,
            "pii_data": {"email": ["test@example.com"]},
            "sensitive_parameters": [{"category": "email", "in": "query", "name": "email"}]
        }
    ]
    reporter.export_sarif(final_results)
    assert outfile.exists()
    with open(outfile, 'r') as f:
        data = json.load(f)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1

def test_export_html(tmp_path):
    outfile = tmp_path / "report.html"
    args = Namespace(out=str(outfile))
    reporter = Reporter(args)
    
    final_results = [
        {
            "method": "GET",
            "url": "http://example.com/api",
            "status_code": 200,
            "content_length": 123,
            "pii_detected": True,
            "pii_data": {"email": ["test@example.com"]}
        }
    ]
    reporter.export_html(final_results, {})
    assert outfile.exists()
    content = outfile.read_text(encoding="utf-8")
    assert "AutoSwagger2 Report" in content
    assert "GET" in content

def test_print_json(capsys):
    args = Namespace(json=True, stats=True, product=False)
    reporter = Reporter(args)
    final_results = [{"method": "GET", "url": "http://example.com/api", "status_code": 200, "content_length": 123, "body": None, "path_template": "/api"}]
    stats = {"hosts": 1}
    reporter.print_results(final_results, stats, bola_results=[{"vulnerable": True}])
    captured = capsys.readouterr()
    assert "results" in captured.out or "bola_findings" in captured.out

def test_print_product_json(capsys):
    args = Namespace(product=True, json=False, csv=False, sarif=False, html=False, stats=True)
    reporter = Reporter(args)
    final_results = [
        {
            "method": "GET",
            "url": "http://example.com/api",
            "status_code": 200,
            "content_length": 123,
            "pii_detected": True,
            "interesting_response": True,
            "body": None,
            "path_template": "/api"
        }
    ]
    stats = {"hosts": 1}
    reporter.print_results(final_results, stats, bola_results=[{"vulnerable": True}])
    captured = capsys.readouterr()
    assert "results" in captured.out

def test_print_tables(capsys):
    args = Namespace(product=False, json=False, csv=False, sarif=False, html=False, all=True, stats=True, risk=True)
    reporter = Reporter(args)
    final_results = [
        {
            "method": "GET",
            "url": "http://example.com/api",
            "status_code": 200,
            "content_length": 123,
            "pii_detected": True,
            "pii_data": {"email": ["test@example.com"]},
            "sensitive_parameters": [{"category": "email", "in": "query", "name": "email"}],
            "response_body": "test response",
            "body": "request body",
            "path_template": "/api"
        }
    ]
    stats = {
        "percentage_hosts_with_endpoint": 100.0,
        "pii_detection_methods": {"regex"},
        "regexes_found": {"pattern"}
    }
    reporter.print_results(
        final_results,
        stats,
        bola_results=[{"vulnerable": True, "method": "GET", "url_template": "/api/{id}", "baseline_id": 1, "attack_id": 2, "baseline_status": 200, "attack_status": 200}],
        bfla_results=[{"vulnerable": True, "method": "GET", "url_template": "/admin", "request_body": "", "status_code": 200}],
        bopla_results=[{"vulnerable": True, "method": "GET", "url_template": "/profile", "request_body": "", "status_code": 200}],
        urc_results=[{"vulnerable": True, "method": "GET", "url_template": "/search", "parameter": "q", "attack_value": "A"*1000, "response_time_ms": 1500, "content_length": 1000, "status_code": 200}]
    )
    captured = capsys.readouterr()
    assert "API Endpoints" in captured.out
    assert "BOLA Test Results" in captured.out
    assert "BFLA Test Results" in captured.out
    assert "BOPLA Test Results" in captured.out
    assert "Unrestricted Resource Consumption" in captured.out
    assert "Scan Statistics" in captured.out
