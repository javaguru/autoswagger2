# autoswagger2/discovery/shadow_version_finder.py
# Discovers undocumented sibling/zombie API versions (e.g., /v1, /v0, /beta) derived from OpenAPI paths.

from concurrent.futures import ThreadPoolExecutor, as_completed
import re

from ..utils.helpers import is_quiet_output, join_base_and_path, log
from .hidden_finder import HiddenEndpointFinder, PARAM_SEG_RE

PATH_VERSION_RE = re.compile(r"(^|/)(v(\d+)(?:\.\d+)*|beta|alpha)(?=/|$)", re.IGNORECASE)


class ShadowVersionFinder(HiddenEndpointFinder):
    """Probes deprecated or unreleased sibling API versions derived from documented OpenAPI paths."""

    @staticmethod
    def _candidate_versions_for(ver_token, ver_num_str):
        token_lower = ver_token.lower()
        if token_lower in ("beta", "alpha"):
            return ["v1", "v2", "v0"]
        try:
            num = int(ver_num_str)
        except (TypeError, ValueError):
            return []

        if num <= 0:
            return ["v1", "v2", "beta"]
        if num == 1:
            return ["v0", "v2", "beta"]

        older = [f"v{k}" for k in range(num - 1, max(0, num - 4), -1)]
        candidates = older + ["v0", f"v{num + 1}", "beta"]
        deduped = []
        for c in candidates:
            if c.lower() != token_lower and c not in deduped:
                deduped.append(c)
        return deduped

    def _generate_shadow_candidates(self, swagger_spec, documented_static, documented_param_regexes, excluded_paths=None):
        if not isinstance(swagger_spec, dict) or not isinstance(swagger_spec.get("paths"), dict):
            return []

        excluded = set(excluded_paths or ())
        candidates = []
        seen_shadow_paths = set()

        for raw_path, path_item in swagger_spec["paths"].items():
            if not isinstance(raw_path, str) or not raw_path or not isinstance(path_item, dict):
                continue

            full_doc_path = "/" + join_base_and_path(self.base_path, raw_path).strip("/")
            match = PATH_VERSION_RE.search(full_doc_path)
            if not match:
                continue

            orig_ver = match.group(2)
            ver_num_str = match.group(3)
            ver_start, ver_end = match.span(2)

            substituted_doc_path = PARAM_SEG_RE.sub("1", full_doc_path)
            sub_match = PATH_VERSION_RE.search(substituted_doc_path)
            if not sub_match:
                continue
            sub_ver_start, sub_ver_end = sub_match.span(2)

            sibling_versions = self._candidate_versions_for(orig_ver, ver_num_str)
            for sib_ver in sibling_versions:
                shadow_path = (
                    substituted_doc_path[:sub_ver_start]
                    + sib_ver
                    + substituted_doc_path[sub_ver_end:]
                )
                norm_shadow = "/" + shadow_path.strip("/")
                if (
                    norm_shadow in seen_shadow_paths
                    or norm_shadow in documented_static
                    or norm_shadow in excluded
                    or any(rx.match(norm_shadow) for rx in documented_param_regexes)
                ):
                    continue

                shadow_prefix = full_doc_path[:ver_start] + sib_ver
                norm_prefix = "/" + shadow_prefix.strip("/") if shadow_prefix.strip("/") else ""
                tail_slug = norm_shadow[len(norm_prefix):].lstrip("/") or sib_ver

                seen_shadow_paths.add(norm_shadow)
                candidates.append(
                    {
                        "shadow_prefix": norm_prefix,
                        "shadow_path": norm_shadow,
                        "tail_slug": tail_slug,
                        "orig_ver": orig_ver,
                        "shadow_ver": sib_ver,
                        "documented_path": raw_path,
                    }
                )

        return candidates

    def discover_shadow_versions(self, swagger_spec, excluded_paths=None):
        documented_static, documented_param_regexes = self._collect_documented_routes(swagger_spec)
        candidates = self._generate_shadow_candidates(
            swagger_spec, documented_static, documented_param_regexes, excluded_paths=excluded_paths
        )
        if not candidates:
            if not is_quiet_output(self.args):
                log("No versioned OpenAPI paths eligible for --shadow-versions probing.", level="INFO")
            return []

        unique_prefixes = list(dict.fromkeys(c["shadow_prefix"] for c in candidates))
        if not is_quiet_output(self.args):
            log(
                f"Probing {len(candidates)} shadow/zombie version route(s) across {len(unique_prefixes)} version prefix(es)...",
                level="INFO",
            )

        canary_by_prefix = {}
        with ThreadPoolExecutor(max_workers=self._resolve_max_workers(len(unique_prefixes))) as executor:
            fut_to_pfx = {executor.submit(self._probe_canary, pfx): pfx for pfx in unique_prefixes}
            for fut in as_completed(fut_to_pfx):
                pfx = fut_to_pfx[fut]
                try:
                    sig = fut.result()
                    if sig is not None:
                        canary_by_prefix[pfx] = sig
                except Exception:
                    pass

        if not canary_by_prefix:
            return []

        active_candidates = [c for c in candidates if c["shadow_prefix"] in canary_by_prefix]
        if not active_candidates:
            return []

        indexed_results = []
        with ThreadPoolExecutor(max_workers=self._resolve_max_workers(len(active_candidates))) as executor:
            fut_to_cand = {
                executor.submit(
                    self._probe_candidate,
                    c["tail_slug"],
                    c["shadow_path"],
                    canary_by_prefix[c["shadow_prefix"]],
                    documented_param_regexes,
                ): (idx, c)
                for idx, c in enumerate(active_candidates)
            }
            for fut in as_completed(fut_to_cand):
                idx, c = fut_to_cand[fut]
                try:
                    res = fut.result()
                    if res is not None:
                        shadow_label = f"Shadow/Zombie API Version ({c['shadow_ver']} sibling of {c['orig_ver']})"
                        indicators = [
                            shadow_label if item == "Undocumented Endpoint (@Hidden)" else item
                            for item in res.get("vuln_indicators", [])
                        ]
                        if shadow_label not in indicators:
                            indicators.insert(0, shadow_label)
                        res["vuln_indicators"] = indicators
                        res["shadow_version"] = {
                            "from_version": c["orig_ver"],
                            "shadow_version": c["shadow_ver"],
                            "documented_path": c["documented_path"],
                        }
                        indexed_results.append((idx, res))
                except Exception as exc:
                    if getattr(self.args, "verbose", False):
                        log(f"Shadow version probe error on {c['shadow_path']}: {exc}", level="DEBUG")

        indexed_results.sort(key=lambda item: item[0])
        discovered = [item[1] for item in indexed_results]

        if not is_quiet_output(self.args):
            if discovered:
                for res in discovered:
                    lvl = "SUCCESS" if 200 <= res["status_code"] < 300 else "WARNING"
                    log(
                        f"Shadow API version detected: {res['method']} {res['url']} (HTTP {res['status_code']})",
                        level=lvl,
                    )
                log(f"Found {len(discovered)} shadow/zombie API endpoint(s).", level="SUCCESS")
            else:
                log("No shadow/zombie API versions detected.", level="INFO")

        return discovered
