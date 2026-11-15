# autoswagger2/reporting/diff_engine.py
# Compares current scan findings against a JSON baseline and evaluates CI/CD severity gates.

import json
import os

SEVERITY_SCORES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SCORE_TO_LABEL = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def eval_result_severity_score(result):
    if not isinstance(result, dict):
        return 0
    if result.get("pii_detected"):
        details = result.get("pii_detection_details") or {}
        if isinstance(details, dict):
            for val in details.values():
                if isinstance(val, dict) and "regex" in val.get("detection_methods", []):
                    return 4
        return 3
    if result.get("vuln_indicators"):
        return 3
    if result.get("debug_info_detected"):
        return 2
    if result.get("interesting_response"):
        return 2
    if isinstance(result.get("status_code"), int) and result.get("status_code", 0) < 400:
        return 1
    return 0


class DiffEngine:
    """Computes regressions, new exposures, and resolved findings against a saved JSON baseline."""

    @staticmethod
    def load_baseline(filepath):
        if not isinstance(filepath, str) or not filepath.strip() or not os.path.isfile(filepath):
            raise FileNotFoundError(f"Baseline file not found: {filepath}")

        with open(filepath, "rb") as f:
            raw = f.read()

        text = None
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = raw.decode("utf-16")
        else:
            for enc in ("utf-8-sig", "utf-16"):
                try:
                    text = raw.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
        if text is None:
            text = raw.decode("utf-8", errors="replace")

        data = json.loads(text)
        if isinstance(data, list):
            return {"results": data}
        if isinstance(data, dict):
            return data
        raise ValueError("Baseline JSON must be an object or array of results.")

    @staticmethod
    def _endpoint_key(item):
        method = str(item.get("method", "GET")).upper()
        raw_url = str(item.get("url", ""))
        clean_url = raw_url.split("?", 1)[0].rstrip("/")
        return (method, clean_url)

    @staticmethod
    def _summarize_endpoint(item):
        parts = []
        if item.get("pii_detected"):
            pii_keys = list((item.get("pii_data") or {}).keys())
            parts.append(f"PII/Secret ({', '.join(pii_keys)})" if pii_keys else "PII/Secret")
        if item.get("vuln_indicators"):
            parts.append(", ".join(str(x) for x in item["vuln_indicators"]))
        if item.get("debug_info_detected"):
            parts.append("Debug Info")
        return "; ".join(parts) if parts else f"HTTP {item.get('status_code', '')}"

    @staticmethod
    def _active_vuln_set(bola_list=None, bfla_list=None, bopla_list=None, urc_list=None):
        vulns = {}
        for cat, items, score in (
            ("BOLA", bola_list or [], 4),
            ("BFLA", bfla_list or [], 4),
            ("BOPLA", bopla_list or [], 4),
            ("URC", urc_list or [], 3),
        ):
            for entry in items:
                if isinstance(entry, dict) and entry.get("vulnerable"):
                    key = (
                        cat,
                        str(entry.get("method", "")).upper(),
                        str(entry.get("url_template", "")),
                    )
                    vulns[key] = {
                        "category": cat,
                        "method": key[1],
                        "endpoint": key[2],
                        "severity": SCORE_TO_LABEL[score],
                        "severity_score": score,
                    }
        return vulns

    def compute_diff(
        self,
        baseline_data,
        current_results,
        bola_results=None,
        bfla_results=None,
        bopla_results=None,
        urc_results=None,
    ):
        base_map = {}
        for item in baseline_data.get("results", []) or []:
            if isinstance(item, dict) and item.get("url"):
                k = self._endpoint_key(item)
                if k not in base_map or eval_result_severity_score(item) > eval_result_severity_score(base_map[k]):
                    base_map[k] = item

        curr_map = {}
        for item in current_results or []:
            if isinstance(item, dict) and item.get("url"):
                k = self._endpoint_key(item)
                if k not in curr_map or eval_result_severity_score(item) > eval_result_severity_score(curr_map[k]):
                    curr_map[k] = item

        new_endpoints = []
        removed_endpoints = []
        regressions = []
        resolved_issues = []

        for key, curr in curr_map.items():
            if key not in base_map:
                score = eval_result_severity_score(curr)
                new_endpoints.append(
                    {
                        "method": key[0],
                        "url": curr.get("url", key[1]),
                        "status_code": curr.get("status_code"),
                        "severity": SCORE_TO_LABEL[score],
                        "severity_score": score,
                        "details": self._summarize_endpoint(curr),
                    }
                )
                continue

            prev = base_map[key]
            reg_reasons = []
            res_reasons = []

            prev_sc = prev.get("status_code", 0) or 0
            curr_sc = curr.get("status_code", 0) or 0
            if prev_sc >= 400 and 200 <= curr_sc < 300:
                reg_reasons.append(f"Became accessible (HTTP {prev_sc} -> {curr_sc})")
            elif 200 <= prev_sc < 300 and curr_sc >= 400:
                res_reasons.append(f"Restricted (HTTP {prev_sc} -> {curr_sc})")

            prev_pii_keys = set((prev.get("pii_data") or {}).keys())
            curr_pii_keys = set((curr.get("pii_data") or {}).keys())
            if not prev.get("pii_detected") and curr.get("pii_detected"):
                added = ", ".join(sorted(curr_pii_keys)) if curr_pii_keys else "PII/Secret"
                reg_reasons.append(f"New PII/Secret exposed ({added})")
            elif curr_pii_keys - prev_pii_keys:
                reg_reasons.append(f"Additional PII/Secret types ({', '.join(sorted(curr_pii_keys - prev_pii_keys))})")
            elif prev.get("pii_detected") and not curr.get("pii_detected"):
                res_reasons.append("PII/Secret exposure resolved")

            if not prev.get("debug_info_detected") and curr.get("debug_info_detected"):
                reg_reasons.append("New Debug Info leak")
            elif prev.get("debug_info_detected") and not curr.get("debug_info_detected"):
                res_reasons.append("Debug Info leak resolved")

            prev_ind = set(prev.get("vuln_indicators") or [])
            curr_ind = set(curr.get("vuln_indicators") or [])
            added_ind = sorted(curr_ind - prev_ind)
            fixed_ind = sorted(prev_ind - curr_ind)
            if added_ind:
                reg_reasons.append(f"New indicator(s): {', '.join(added_ind)}")
            if fixed_ind:
                res_reasons.append(f"Resolved indicator(s): {', '.join(fixed_ind)}")

            if reg_reasons:
                score = eval_result_severity_score(curr)
                regressions.append(
                    {
                        "method": key[0],
                        "url": curr.get("url", key[1]),
                        "status_code": curr_sc,
                        "severity": SCORE_TO_LABEL[score],
                        "severity_score": score,
                        "reasons": reg_reasons,
                    }
                )
            elif res_reasons:
                resolved_issues.append(
                    {
                        "method": key[0],
                        "url": curr.get("url", key[1]),
                        "status_code": curr_sc,
                        "reasons": res_reasons,
                    }
                )

        for key, prev in base_map.items():
            if key not in curr_map:
                removed_endpoints.append(
                    {
                        "method": key[0],
                        "url": prev.get("url", key[1]),
                        "status_code": prev.get("status_code"),
                    }
                )

        base_vulns = self._active_vuln_set(
            baseline_data.get("bola_findings"),
            baseline_data.get("bfla_findings"),
            baseline_data.get("bopla_findings"),
            baseline_data.get("urc_findings"),
        )
        curr_vulns = self._active_vuln_set(bola_results, bfla_results, bopla_results, urc_results)
        new_active_vulns = [val for key, val in curr_vulns.items() if key not in base_vulns]

        return {
            "summary": {
                "new_endpoints_count": len(new_endpoints),
                "regressions_count": len(regressions),
                "new_active_vulns_count": len(new_active_vulns),
                "resolved_issues_count": len(resolved_issues),
                "removed_endpoints_count": len(removed_endpoints),
                "has_regressions": bool(new_endpoints or regressions or new_active_vulns),
            },
            "new_endpoints": new_endpoints,
            "regressions": regressions,
            "new_active_vulns": new_active_vulns,
            "resolved_issues": resolved_issues,
            "removed_endpoints": removed_endpoints,
        }

    @classmethod
    def evaluate_fail_on(
        cls,
        threshold_str,
        current_results,
        bola_results=None,
        bfla_results=None,
        bopla_results=None,
        urc_results=None,
        diff_report=None,
    ):
        if not isinstance(threshold_str, str) or not threshold_str.strip():
            return False, 0, 0

        min_score = SEVERITY_SCORES.get(threshold_str.strip().lower(), 0)
        if min_score <= 0:
            return False, 0, 0

        scores = []
        if isinstance(diff_report, dict):
            for item in diff_report.get("new_endpoints", []):
                scores.append(item.get("severity_score", 0))
            for item in diff_report.get("regressions", []):
                scores.append(item.get("severity_score", 0))
            for item in diff_report.get("new_active_vulns", []):
                scores.append(item.get("severity_score", 0))
        else:
            seen_keys = {}
            for res in current_results or []:
                if isinstance(res, dict):
                    key = (res.get("method"), res.get("path_template") or res.get("url"))
                    sc = eval_result_severity_score(res)
                    if key not in seen_keys or sc > seen_keys[key]:
                        seen_keys[key] = sc
            scores.extend(seen_keys.values())
            for entry in cls._active_vuln_set(bola_results, bfla_results, bopla_results, urc_results).values():
                scores.append(entry["severity_score"])

        matching = [s for s in scores if s >= min_score]
        max_score = max(scores) if scores else 0
        return bool(matching), max_score, len(matching)
