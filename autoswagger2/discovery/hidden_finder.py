# autoswagger2/discovery/hidden_finder.py
# Discovers undocumented API routes (e.g., Spring @Hidden endpoints) omitted from OpenAPI specs.

import json
import os
import re
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode, urlparse

import requests

from ..analysis.pii import PiiAnalyzer
from ..analysis.secrets import detect_sensitive_info
from ..core.requester import Requester
from ..utils.config import (
    COMMON_API_PREFIXES,
    DIRECT_SPEC_PATHS,
    HIDDEN_ENDPOINT_WORDS,
    SWAGGER_UI_PATHS,
)
from ..utils.helpers import (
    build_cross_origin_safe_headers,
    build_full_url,
    is_quiet_output,
    is_same_origin_host,
    join_base_and_path,
    log,
)
from ..utils.rate_limiter import get_rate_limiter
from ..utils.validators import ResultValidator

CANARY_SLUG = "asw2_notfound_9f8e7d6c"
VERSION_SEG_RE = re.compile(r"^v\d+(?:\.\d+)*$", re.IGNORECASE)
PARAM_SEG_RE = re.compile(r"\{[^{}/]+\}|:[a-zA-Z_][a-zA-Z0-9_]*|<[^<>/]+>")
DYNAMIC_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\b\d{10,13}\b"
)
NAMESPACE_SEGMENTS = {
    "api",
    "rest",
    "mock",
    "public",
    "private",
    "internal",
    "gateway",
    "services",
    "service",
    "webapi",
    "app",
}
DEFAULT_QUERY_PARAMS = (
    "msg",
    "message",
    "text",
    "input",
    "q",
    "value",
    "data",
    "name",
)
MISSING_PARAM_PATTERNS = (
    re.compile(r"Required (?:request |\w+ )?parameter ['\"]([a-zA-Z0-9_.-]{1,40})['\"]", re.IGNORECASE),
    re.compile(r"['\"]([a-zA-Z0-9_.-]{1,40})['\"] is (?:required|missing)", re.IGNORECASE),
    re.compile(r'"loc"\s*:\s*\[\s*"query"\s*,\s*"([a-zA-Z0-9_.-]{1,40})"\s*\]', re.IGNORECASE),
)
TYPE_MISMATCH_PATTERNS = (
    "methodargumenttypemismatchexception",
    "failed to convert value of type",
    "type mismatch",
    "invalid uuid",
    "input should be a valid integer",
)


class HiddenEndpointFinder:
    """Probes context-aware prefixes with a dictionary to inventory undocumented API routes."""

    def __init__(self, api_base_url, base_path, args, session, auth_origin=None, spec_url=None):
        self.api_base_url = api_base_url
        self.base_path = base_path or ""
        self.auth_origin = auth_origin or api_base_url
        self.spec_url = spec_url
        self.args = args
        self.session = session
        self.TIMEOUT = 10
        self._lock = threading.Lock()
        self.TOTAL_REQUESTS = 0
        self.max_workers = None
        self.pii_analyzer = PiiAnalyzer()
        self.validator = ResultValidator()
        self._requester_helper = Requester(api_base_url, args, session)

    def _resolve_max_workers(self, task_count):
        if task_count <= 0:
            return 1
        override = getattr(self, "max_workers", None)
        if not isinstance(override, bool) and isinstance(override, int) and override >= 1:
            workers = override
        else:
            raw_threads = getattr(self.args, "threads", 20)
            if not isinstance(raw_threads, bool) and isinstance(raw_threads, int) and raw_threads >= 1:
                workers = raw_threads
            else:
                workers = 20
        return max(1, min(100, workers, task_count))

    def _load_wordlist(self):
        words = []
        seen = set()

        def _add_word(raw_word):
            if not isinstance(raw_word, str):
                return
            cleaned = raw_word.strip().strip("/")
            if not cleaned or cleaned.startswith("#"):
                return
            if ".." in cleaned or "://" in cleaned or any(ch.isspace() for ch in cleaned):
                return
            if cleaned not in seen:
                seen.add(cleaned)
                words.append(cleaned)

        custom_path = getattr(self.args, "hidden_wordlist", None)
        if isinstance(custom_path, str) and custom_path.strip():
            custom_path = custom_path.strip()
            if os.path.isfile(custom_path):
                try:
                    with open(custom_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            _add_word(line)
                except OSError as exc:
                    if not is_quiet_output(self.args):
                        log(f"Unable to read --hidden-wordlist {custom_path}: {exc}", level="WARNING")
            else:
                if not is_quiet_output(self.args):
                    log(f"Hidden wordlist file not found: {custom_path}. Using built-in dictionary.", level="WARNING")

        for builtin_word in HIDDEN_ENDPOINT_WORDS:
            _add_word(builtin_word)

        return words

    def _collect_documented_routes(self, swagger_spec):
        documented_static = set()
        documented_param_regexes = []

        def _norm_path(p):
            cleaned = "/" + (p or "").strip("/")
            return cleaned if cleaned != "/" else "/"

        if isinstance(self.spec_url, str) and self.spec_url:
            spec_path = urlparse(self.spec_url).path
            if spec_path:
                documented_static.add(_norm_path(spec_path))

        for doc_ui_or_spec in (*SWAGGER_UI_PATHS, *DIRECT_SPEC_PATHS):
            documented_static.add(_norm_path(doc_ui_or_spec))
            if self.base_path:
                documented_static.add(_norm_path(join_base_and_path(self.base_path, doc_ui_or_spec)))

        if not isinstance(swagger_spec, dict):
            return documented_static, documented_param_regexes

        paths_obj = swagger_spec.get("paths")
        if isinstance(paths_obj, dict):
            for raw_path in paths_obj.keys():
                if not isinstance(raw_path, str) or not raw_path:
                    continue
                full_doc_path = _norm_path(join_base_and_path(self.base_path, raw_path))
                if PARAM_SEG_RE.search(full_doc_path):
                    parts = PARAM_SEG_RE.split(full_doc_path)
                    escaped_parts = [re.escape(part) for part in parts]
                    regex_str = "^" + "[^/]+".join(escaped_parts) + "$"
                    try:
                        documented_param_regexes.append(re.compile(regex_str))
                    except re.error:
                        pass
                else:
                    documented_static.add(full_doc_path)

        return documented_static, documented_param_regexes

    @staticmethod
    def _combine_prefix(base_prefix, extra_prefix):
        clean_base = "/" + base_prefix.strip("/") if (base_prefix and base_prefix.strip("/")) else ""
        clean_extra = "/" + extra_prefix.strip("/") if (extra_prefix and extra_prefix.strip("/")) else ""
        if not clean_extra:
            return clean_base
        if not clean_base:
            return clean_extra
        if clean_base == clean_extra or clean_base.endswith(clean_extra):
            return clean_base
        if clean_extra.startswith(clean_base + "/"):
            return clean_extra

        base_segs = [s for s in clean_base.strip("/").split("/") if s]
        extra_segs = [s for s in clean_extra.strip("/").split("/") if s]

        if any(VERSION_SEG_RE.match(s) for s in base_segs) and any(VERSION_SEG_RE.match(s) for s in extra_segs):
            return None
        if base_segs and extra_segs and base_segs[-1].lower() == extra_segs[0].lower():
            merged = base_segs + extra_segs[1:]
            return "/" + "/".join(merged)
        return f"{clean_base}{clean_extra}"

    def _derive_prefixes(self, swagger_spec):
        clean_base = "/" + self.base_path.strip("/") if (self.base_path and self.base_path.strip("/")) else ""
        prefixes = []
        seen = set()

        def _add_prefix(p):
            if p is None:
                return
            norm = "/" + p.strip("/") if (p and p.strip("/")) else ""
            if norm not in seen:
                seen.add(norm)
                prefixes.append(norm)

        # 1. Extract context-aware directory prefixes from OpenAPI paths
        if isinstance(swagger_spec, dict) and isinstance(swagger_spec.get("paths"), dict):
            raw_paths = [p for p in swagger_spec["paths"].keys() if isinstance(p, str) and p.strip("/")]
            prefix_counts = Counter()

            for raw_path in raw_paths:
                segs = [s for s in raw_path.strip("/").split("/") if s]
                static_segs = []
                had_param = False
                for seg in segs:
                    if PARAM_SEG_RE.search(seg):
                        had_param = True
                        break
                    static_segs.append(seg)

                if had_param:
                    # Drop the collection noun right before {param} unless it is a version/namespace
                    if static_segs and not (
                        VERSION_SEG_RE.match(static_segs[-1])
                        or static_segs[-1].lower() in NAMESPACE_SEGMENTS
                    ):
                        dir_segs = static_segs[:-1]
                    else:
                        dir_segs = static_segs
                else:
                    dir_segs = static_segs[:-1]

                for depth in range(1, min(3, len(dir_segs)) + 1):
                    rel_prefix = "/" + "/".join(dir_segs[:depth])
                    prefix_counts[rel_prefix] += 1

            version_or_ns = []
            shared_dirs = []
            min_shared_count = 1 if len(raw_paths) <= 5 else 2

            for rel_p, count in prefix_counts.items():
                last_seg = rel_p.rsplit("/", 1)[-1]
                if VERSION_SEG_RE.match(last_seg):
                    version_or_ns.append((0, -count, len(rel_p), rel_p))
                elif last_seg.lower() in NAMESPACE_SEGMENTS:
                    version_or_ns.append((1, -count, len(rel_p), rel_p))
                elif count >= min_shared_count:
                    shared_dirs.append((-count, len(rel_p), rel_p))

            version_or_ns.sort()
            shared_dirs.sort()

            spec_selected = [item[3] for item in version_or_ns] + [item[2] for item in shared_dirs]
            for rel_p in spec_selected[:6]:
                _add_prefix(self._combine_prefix(clean_base, rel_p))

        # 2. Base path itself (and parent if base_path ended with a version segment like /api/v1)
        _add_prefix(clean_base)
        if clean_base:
            base_segs = [s for s in clean_base.strip("/").split("/") if s]
            if base_segs and VERSION_SEG_RE.match(base_segs[-1]):
                parent = "/" + "/".join(base_segs[:-1]) if len(base_segs) > 1 else ""
                _add_prefix(parent)

        # 3. Standard API / version prefixes under base_path
        for common in COMMON_API_PREFIXES:
            _add_prefix(self._combine_prefix(clean_base, common))

        return prefixes

    def _send_raw(self, method, full_path, query_params=None, body=None, content_type=None):
        full_url = build_full_url(self.api_base_url, full_path)
        if query_params:
            qs = urlencode(query_params)
            if qs:
                full_url += f"{'&' if '?' in full_url else '?'}{qs}"

        headers = {"Content-Type": content_type} if content_type else {}
        origin_to_check = self.auth_origin or self.api_base_url
        if origin_to_check and not is_same_origin_host(origin_to_check, full_url):
            if not getattr(self.args, "allow_external", False):
                if getattr(self.args, "verbose", False):
                    log(f"Blocked cross-origin hidden probe to {full_url}", level="WARNING")
                return full_url, None
            headers = build_cross_origin_safe_headers(self.session, headers)

        max_retries = 2
        for attempt in range(max_retries):
            try:
                get_rate_limiter(self.args).wait()
                with self._lock:
                    self.TOTAL_REQUESTS += 1

                response = self.session.request(
                    method,
                    full_url,
                    headers=headers,
                    data=body,
                    allow_redirects=False,
                    timeout=self.TIMEOUT,
                )
                return full_url, response
            except requests.Timeout:
                if attempt < max_retries - 1:
                    time.sleep(1)
                else:
                    return full_url, None
            except requests.exceptions.RequestException:
                return full_url, None
        return full_url, None

    @staticmethod
    def _normalize_body_for_comparison(text, slug):
        if not text:
            return ""
        norm = text
        if slug:
            norm = norm.replace(slug, "<ASW2_SLUG>")
        norm = DYNAMIC_TS_RE.sub("<TS>", norm)
        return norm.strip()

    @staticmethod
    def _extract_json_keys(text):
        if not text or not text.lstrip().startswith("{"):
            return None
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return tuple(sorted(str(k) for k in parsed.keys()))
        except (json.JSONDecodeError, ValueError):
            pass
        return None

    def _probe_canary(self, full_prefix):
        canary_path = f"{full_prefix}/{CANARY_SLUG}" if full_prefix else f"/{CANARY_SLUG}"
        _, resp = self._send_raw("GET", canary_path)
        if resp is None:
            return None

        ct = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
        raw_bytes = resp.content or b""
        text = ""
        if len(raw_bytes) <= 262144:
            try:
                text = raw_bytes.decode("utf-8", errors="ignore")
            except Exception:
                text = ""

        norm_text = self._normalize_body_for_comparison(text, CANARY_SLUG)
        return {
            "status_code": resp.status_code,
            "content_type": ct,
            "content_length": len(raw_bytes),
            "norm_len": len(norm_text),
            "norm_sample": norm_text[:500],
            "json_keys": self._extract_json_keys(text),
        }

    def _is_soft_404_or_canary_match(self, response, word, canary_sig):
        ct = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
        raw_bytes = response.content or b""
        text = ""
        if len(raw_bytes) <= 262144:
            try:
                text = raw_bytes.decode("utf-8", errors="ignore")
            except Exception:
                text = ""

        # Check explicit soft-404 envelopes on 2xx responses
        if 200 <= response.status_code < 300 and text:
            stripped = text.lstrip()
            if stripped.startswith("{"):
                try:
                    data = json.loads(stripped)
                    if isinstance(data, dict):
                        status_val = data.get("status")
                        code_val = data.get("code")
                        err_msg = str(data.get("error") or data.get("message") or "").lower()
                        if (
                            status_val in (401, 403, 404, "404", "not_found", "NOT_FOUND")
                            or code_val in (401, 403, 404, "404", "NOT_FOUND")
                            or (data.get("success") is False and ("not found" in err_msg or "no static resource" in err_msg))
                            or ("no static resource" in err_msg)
                        ):
                            return True
                except (json.JSONDecodeError, ValueError):
                    pass
            elif "html" in ct:
                title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    title_lower = title_match.group(1).lower()
                    if "404" in title_lower or "not found" in title_lower:
                        return True

        if not canary_sig:
            return False

        if response.status_code != canary_sig["status_code"]:
            return False

        if ct != canary_sig["content_type"]:
            return False

        norm_text = self._normalize_body_for_comparison(text, word)
        norm_len = len(norm_text)
        canary_norm_len = canary_sig["norm_len"]

        if norm_text == canary_sig["norm_sample"] and norm_len <= 500:
            return True

        cand_keys = self._extract_json_keys(text)
        if cand_keys is not None and cand_keys == canary_sig["json_keys"]:
            canary_sample = canary_sig["norm_sample"]
            try:
                cand_obj = json.loads(norm_text)
                can_obj = json.loads(canary_sample)
                if isinstance(cand_obj, dict) and isinstance(can_obj, dict) and cand_obj == can_obj:
                    return True
            except (json.JSONDecodeError, ValueError):
                pass
            if len(cand_keys) >= 3 and norm_len > 80:
                tolerance = max(16, int(0.05 * max(canary_norm_len, 1)))
                if abs(norm_len - canary_norm_len) <= tolerance:
                    return True

        if "html" in ct:
            tolerance = max(64, int(0.10 * max(canary_norm_len, 1)))
            if abs(norm_len - canary_norm_len) <= tolerance:
                return True

        if not text and len(raw_bytes) == canary_sig["content_length"]:
            return True

        return False

    @staticmethod
    def _extract_missing_query_params(content_text):
        params = []
        seen = set()
        if content_text:
            for pattern in MISSING_PARAM_PATTERNS:
                for match in pattern.findall(content_text):
                    if match and match not in seen:
                        seen.add(match)
                        params.append(match)
        for default_p in DEFAULT_QUERY_PARAMS:
            if default_p not in seen:
                seen.add(default_p)
                params.append(default_p)
        return params[:10]

    def _build_hidden_result(self, method, full_url, full_path, body, response, extra_indicators=None):
        status_code = response.status_code
        content_type_header = response.headers.get("Content-Type", "").lower()
        is_binary = any(b in content_type_header for b in ("image", "octet-stream", "pdf", "zip", "binary", "download"))
        is_text_based = (
            any(t in content_type_header for t in ("json", "text", "xml", "html", "javascript", "yaml"))
            or not content_type_header
        ) and not is_binary

        content_text = ""
        pii_detected = False
        pii_data = {}
        sensitive_info = None
        regex_patterns = {}
        debug_info_only = False
        vuln_indicators = []

        if is_text_based and response.content:
            try:
                content_text = response.content.decode("utf-8", errors="ignore")
                sensitive_info, regex_patterns = detect_sensitive_info(content_text)
                vuln_indicators = self._requester_helper._detect_response_anomalies(
                    content_text, content_type_header, None
                )
                is_short_error = (
                    status_code >= 400
                    and len(content_text) < 150
                    and sensitive_info
                    and "Debug Information" in sensitive_info
                )
                if not is_short_error:
                    pii_detected, pii_data = self.pii_analyzer.analyze_content(content_text)
                else:
                    debug_info_only = True
            except Exception:
                pass

        indicators = ["Undocumented Endpoint (@Hidden)"]
        if extra_indicators:
            for item in extra_indicators:
                if item and item not in indicators:
                    indicators.append(item)
        for item in vuln_indicators:
            if item not in indicators:
                indicators.append(item)

        result = self._requester_helper._build_result(
            method,
            full_url,
            full_path,
            body,
            status_code,
            len(response.content or b""),
            pii_detected,
            pii_data,
            sensitive_info,
            regex_patterns,
            content_text,
            response.headers,
            debug_info_only,
            sensitive_params=[],
            vuln_indicators=indicators,
        )
        result["undocumented"] = True
        result["interesting_response"] = True
        return result

    def _probe_candidate(self, word, full_path, canary_sig, documented_param_regexes):
        matches_param_template = any(rx.match(full_path) for rx in documented_param_regexes)
        full_url, resp = self._send_raw("GET", full_path)
        if resp is None:
            return None

        sc = resp.status_code
        if sc in (401, 403, 404, 410, 429, 501, 502, 503, 504) or 300 <= sc < 400:
            return None

        if matches_param_template and sc >= 400:
            return None

        if self._is_soft_404_or_canary_match(resp, word, canary_sig):
            return None

        # 1. Accessible 2xx undocumented endpoint
        if 200 <= sc < 300:
            return self._build_hidden_result("GET", full_url, full_path, None, resp)

        # 2. 400 / 422 on GET when canary was not 400/422 -> likely missing @RequestParam
        if sc in (400, 422) and (not canary_sig or canary_sig["status_code"] not in (400, 422)):
            err_text = (resp.content or b"").decode("utf-8", errors="ignore")
            err_lower = err_text.lower()
            if any(pat in err_lower for pat in TYPE_MISMATCH_PATTERNS):
                return None

            query_names = self._extract_missing_query_params(err_text)
            query_map = {name: "test" for name in query_names}
            retry_url, retry_resp = self._send_raw("GET", full_path, query_params=query_map)
            if (
                retry_resp is not None
                and 200 <= retry_resp.status_code < 300
                and not self._is_soft_404_or_canary_match(retry_resp, word, canary_sig)
            ):
                return self._build_hidden_result("GET", retry_url, full_path, None, retry_resp)

            looks_like_route_validation = (
                "json" in resp.headers.get("Content-Type", "").lower()
                or "parameter" in err_lower
                or "required" in err_lower
                or bool(getattr(self.args, "all", False))
            )
            if looks_like_route_validation:
                return self._build_hidden_result(
                    "GET",
                    full_url,
                    full_path,
                    None,
                    resp,
                    extra_indicators=[f"Requires Parameters/Input (HTTP {sc})"],
                )
            return None

        # 3. 405 Method Not Allowed -> endpoint exists for non-GET HTTP method(s)
        if sc == 405 and (not canary_sig or canary_sig["status_code"] != 405):
            allow_hdr = resp.headers.get("Allow", "")
            allowed_methods = [
                m.strip().upper()
                for m in allow_hdr.split(",")
                if m.strip().upper() in ("POST", "PUT", "PATCH", "DELETE")
            ]

            if bool(getattr(self.args, "risk", False)):
                methods_to_try = allowed_methods[:2] if allowed_methods else ["POST"]
                json_probe_body = json.dumps({"message": "test", "text": "test", "input": "test", "data": "test"})
                for alt_method in methods_to_try:
                    alt_url, alt_resp = self._send_raw(
                        alt_method,
                        full_path,
                        body=json_probe_body,
                        content_type="application/json",
                    )
                    sent_body = json_probe_body
                    if alt_resp is not None and alt_resp.status_code == 415:
                        alt_url, alt_resp = self._send_raw(
                            alt_method,
                            full_path,
                            body="test",
                            content_type="text/plain",
                        )
                        sent_body = "test"

                    if (
                        alt_resp is not None
                        and alt_resp.status_code not in (401, 403, 404, 405, 410, 501, 502, 503, 504)
                        and not self._is_soft_404_or_canary_match(alt_resp, word, canary_sig)
                    ):
                        return self._build_hidden_result(alt_method, alt_url, full_path, sent_body, alt_resp)

            method_hint = (
                f"Allowed Methods: {', '.join(allowed_methods)}"
                if allowed_methods
                else "HTTP 405 (use -risk to test non-GET)"
            )
            return self._build_hidden_result(
                "GET",
                full_url,
                full_path,
                None,
                resp,
                extra_indicators=[method_hint],
            )

        # 4. 500 Internal Server Error -> keep if debug/PII leaked or -all enabled
        if sc == 500 and (not canary_sig or canary_sig["status_code"] != 500):
            candidate_res = self._build_hidden_result("GET", full_url, full_path, None, resp)
            if (
                candidate_res.get("pii_detected")
                or candidate_res.get("debug_info_detected")
                or bool(getattr(self.args, "all", False))
            ):
                return candidate_res

        return None

    def discover(self, swagger_spec=None):
        words = self._load_wordlist()
        if not words:
            return []

        documented_static, documented_param_regexes = self._collect_documented_routes(swagger_spec)
        prefixes = self._derive_prefixes(swagger_spec)
        if not prefixes:
            prefixes = [""]

        if not is_quiet_output(self.args):
            log(
                f"Probing {len(words)} dictionary route(s) across {len(prefixes)} prefix(es) for undocumented (@Hidden) endpoints...",
                level="INFO",
            )

        # Step 1: Establish per-prefix canary baselines for soft-404 / catch-all filtering
        canary_by_prefix = {}
        canary_workers = self._resolve_max_workers(len(prefixes))
        with ThreadPoolExecutor(max_workers=canary_workers) as executor:
            fut_to_prefix = {executor.submit(self._probe_canary, pfx): pfx for pfx in prefixes}
            for fut in as_completed(fut_to_prefix):
                pfx = fut_to_prefix[fut]
                try:
                    canary_sig = fut.result()
                    if canary_sig is not None:
                        canary_by_prefix[pfx] = canary_sig
                except Exception:
                    pass

        if not canary_by_prefix:
            return []

        # Step 2: Build deduplicated candidate list excluding documented routes
        candidates = []
        seen_paths = set()
        for pfx in prefixes:
            if pfx not in canary_by_prefix:
                continue
            pfx_last_seg = pfx.rsplit("/", 1)[-1].lower() if pfx else ""
            for word in words:
                word_first_seg = word.split("/", 1)[0].lower()
                if pfx_last_seg and pfx_last_seg == word_first_seg:
                    continue
                full_path = f"{pfx}/{word}" if pfx else f"/{word}"
                norm_full_path = "/" + full_path.strip("/")
                if norm_full_path in seen_paths or norm_full_path in documented_static:
                    continue
                seen_paths.add(norm_full_path)
                candidates.append((pfx, word, norm_full_path))

        if not candidates:
            return []

        # Step 3: Probe candidates concurrently
        discovered = []
        probe_workers = self._resolve_max_workers(len(candidates))
        with ThreadPoolExecutor(max_workers=probe_workers) as executor:
            fut_to_cand = {
                executor.submit(
                    self._probe_candidate,
                    word,
                    full_path,
                    canary_by_prefix[pfx],
                    documented_param_regexes,
                ): (idx, full_path)
                for idx, (pfx, word, full_path) in enumerate(candidates)
            }
            indexed_results = []
            for fut in as_completed(fut_to_cand):
                idx, full_path = fut_to_cand[fut]
                try:
                    res = fut.result()
                    if res is not None:
                        indexed_results.append((idx, res))
                except Exception as exc:
                    if getattr(self.args, "verbose", False):
                        log(f"Hidden endpoint probe error on {full_path}: {exc}", level="DEBUG")

        indexed_results.sort(key=lambda item: item[0])
        discovered = [item[1] for item in indexed_results]

        if not is_quiet_output(self.args):
            if discovered:
                for res in discovered:
                    lvl = "SUCCESS" if 200 <= res["status_code"] < 300 else "WARNING"
                    log(
                        f"Undocumented endpoint detected: {res['method']} {res['url']} (HTTP {res['status_code']})",
                        level=lvl,
                    )
                log(f"Found {len(discovered)} undocumented (@Hidden) endpoint(s).", level="SUCCESS")
            else:
                log("No undocumented (@Hidden) endpoints detected.", level="INFO")

        return discovered
