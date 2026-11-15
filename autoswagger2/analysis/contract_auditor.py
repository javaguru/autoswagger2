# autoswagger2/analysis/contract_auditor.py
# Audits runtime API behavior against the OpenAPI specification contract (OWASP API2 & API3).

from collections.abc import Mapping
import json
import re

from ..discovery.openapi_parser import resolve_ref
from ..utils.helpers import build_cross_origin_safe_headers

SENSITIVE_FIELD_KEYWORDS = (
    "password",
    "passwd",
    "pwd",
    "hash",
    "secret",
    "token",
    "apikey",
    "api_key",
    "private",
    "ssn",
    "iban",
    "credit",
    "card",
    "cvv",
    "pin",
    "salt",
    "role",
    "admin",
    "privilege",
    "permission",
    "internal",
)

AUTH_HEADER_NAMES = {
    "authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "proxy-authorization",
}


class ContractAuditor:
    """Detects OpenAPI authentication drift (API2) and undocumented response fields (API3)."""

    def __init__(self, args, session):
        self.args = args
        self.session = session

    def has_session_credentials(self):
        if getattr(self.args, "api_key", None) or getattr(self.args, "api_key_src", None):
            return True
        custom_key_hdr = getattr(self.args, "key_header", None)
        session_headers = getattr(self.session, "headers", None)
        if isinstance(session_headers, Mapping):
            for key in session_headers.keys():
                key_lower = str(key).lower()
                if key_lower in AUTH_HEADER_NAMES:
                    return True
                if isinstance(custom_key_hdr, str) and custom_key_hdr.strip():
                    if key_lower == custom_key_hdr.strip().lower():
                        return True
        session_cookies = getattr(self.session, "cookies", None)
        if session_cookies and len(session_cookies) > 0:
            return True
        return False

    @staticmethod
    def get_required_security_schemes(operation, spec_data):
        """
        Returns a list of required OpenAPI security scheme names for the operation,
        or an empty list if anonymous access is permitted or no security is declared.
        """
        if isinstance(operation, dict) and "security" in operation:
            sec_reqs = operation.get("security")
        elif isinstance(spec_data, dict):
            sec_reqs = spec_data.get("security")
        else:
            sec_reqs = None

        if not isinstance(sec_reqs, list) or len(sec_reqs) == 0:
            return []

        schemes = []
        seen = set()
        for req in sec_reqs:
            if not isinstance(req, dict):
                continue
            # An empty requirement object `{}` in OpenAPI explicitly makes auth optional
            if len(req) == 0:
                return []
            for scheme_name in req.keys():
                if scheme_name and scheme_name not in seen:
                    seen.add(scheme_name)
                    schemes.append(str(scheme_name))
        return schemes

    @staticmethod
    def is_soft_auth_failure(content_text, content_type_header=""):
        if not content_text:
            return False
        stripped = content_text.lstrip()
        if stripped.startswith("{"):
            try:
                data = json.loads(stripped)
                if isinstance(data, dict):
                    status_val = data.get("status")
                    code_val = data.get("code")
                    err_str = str(data.get("error") or data.get("message") or "").lower()
                    if (
                        status_val in (401, 403, "401", "403", "unauthorized", "forbidden")
                        or code_val in (401, 403, "401", "403", "UNAUTHORIZED", "FORBIDDEN")
                        or data.get("authenticated") is False
                        or (
                            data.get("success") is False
                            and any(w in err_str for w in ("unauth", "forbid", "denied", "login", "token"))
                        )
                    ):
                        return True
            except (json.JSONDecodeError, ValueError):
                pass
        if "html" in (content_type_header or "").lower():
            if re.search(r'<input[^>]+type=["\']?password', content_text, re.IGNORECASE) or re.search(
                r"<title[^>]*>[^<]*(?:login|sign\s*in)[^<]*</title>", content_text, re.IGNORECASE
            ):
                return True
        return False

    @staticmethod
    def _extract_response_schema(operation, status_code, spec_data):
        if not isinstance(operation, dict):
            return None
        responses = operation.get("responses")
        if not isinstance(responses, dict) or not responses:
            return None

        resp_obj = None
        for candidate_key in (str(status_code), "2XX", "2xx"):
            if candidate_key in responses:
                resp_obj = responses[candidate_key]
                break

        if not isinstance(resp_obj, dict):
            return None
        resp_obj = resolve_ref(resp_obj, spec_data)
        if not isinstance(resp_obj, dict):
            return None

        # OpenAPI 3.x: responses[code].content[media_type].schema
        content = resp_obj.get("content")
        if isinstance(content, dict) and content:
            media_obj = None
            if "application/json" in content:
                media_obj = content["application/json"]
            else:
                for ct, obj in content.items():
                    if "json" in str(ct).lower():
                        media_obj = obj
                        break
                if media_obj is None and "*/*" in content:
                    media_obj = content["*/*"]
            if isinstance(media_obj, dict) and isinstance(media_obj.get("schema"), dict):
                return media_obj["schema"]
            return None

        # Swagger 2.0: responses[code].schema
        if isinstance(resp_obj.get("schema"), dict):
            return resp_obj["schema"]
        return None

    def find_undocumented_response_fields(self, operation, status_code, content_text, content_type_header, spec_data):
        if not content_text:
            return []
        ct_lower = (content_type_header or "").lower()
        stripped = content_text.lstrip()
        if "json" not in ct_lower and not stripped.startswith(("{", "[")):
            return []

        schema = self._extract_response_schema(operation, status_code, spec_data)
        if not isinstance(schema, dict) or not schema:
            return []

        try:
            payload = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return []

        found = self._diff_value_against_schema(payload, schema, spec_data, prefix="", seen=frozenset(), depth=0)
        deduped = []
        seen_paths = set()
        for path in found:
            if path not in seen_paths:
                seen_paths.add(path)
                deduped.append(path)
        return deduped

    def _diff_value_against_schema(self, value, schema, spec_data, prefix="", seen=frozenset(), depth=0):
        if depth > 4 or value is None or not isinstance(schema, dict) or not schema:
            return []

        if isinstance(schema.get("$ref"), str):
            ref_str = schema["$ref"]
            if ref_str in seen:
                return []
            schema = resolve_ref(schema, spec_data, seen)
            seen = seen | {ref_str}
            if not isinstance(schema, dict) or not schema:
                return []

        # Handle allOf by merging all sub-schema properties
        if isinstance(schema.get("allOf"), list) and schema["allOf"]:
            merged_props = {}
            if isinstance(schema.get("properties"), dict):
                merged_props.update(schema["properties"])
            for sub in schema["allOf"]:
                if not isinstance(sub, dict):
                    continue
                sub_seen = seen
                if isinstance(sub.get("$ref"), str):
                    r_str = sub["$ref"]
                    if r_str in sub_seen:
                        continue
                    sub = resolve_ref(sub, spec_data, sub_seen)
                    sub_seen = sub_seen | {r_str}
                if not isinstance(sub, dict):
                    continue
                if sub.get("additionalProperties") is True or isinstance(sub.get("additionalProperties"), dict):
                    return []
                if isinstance(sub.get("properties"), dict):
                    merged_props.update(sub["properties"])
            if not merged_props:
                return []
            synthetic = {"type": "object", "properties": merged_props}
            return self._diff_value_against_schema(value, synthetic, spec_data, prefix, seen, depth + 1)

        # Handle oneOf / anyOf polymorphically (union of allowed properties if no single branch matches cleanly)
        composite_key = "oneOf" if isinstance(schema.get("oneOf"), list) else ("anyOf" if isinstance(schema.get("anyOf"), list) else None)
        if composite_key and schema[composite_key]:
            union_props = {}
            if isinstance(schema.get("properties"), dict):
                union_props.update(schema["properties"])
            for branch in schema[composite_key]:
                branch_diffs = self._diff_value_against_schema(value, branch, spec_data, prefix, seen, depth + 1)
                if not branch_diffs:
                    return []
                resolved_branch = resolve_ref(branch, spec_data, seen) if isinstance(branch, dict) else {}
                if isinstance(resolved_branch, dict):
                    if resolved_branch.get("additionalProperties") is True or isinstance(resolved_branch.get("additionalProperties"), dict):
                        return []
                    if isinstance(resolved_branch.get("properties"), dict):
                        union_props.update(resolved_branch["properties"])
            if union_props and isinstance(value, dict):
                synthetic = {"type": "object", "properties": union_props}
                return self._diff_value_against_schema(value, synthetic, spec_data, prefix, seen, depth + 1)
            return []

        if isinstance(value, list):
            items_schema = schema.get("items")
            if not isinstance(items_schema, dict):
                return []
            undocumented = []
            for item in value[:5]:
                if isinstance(item, (dict, list)):
                    undocumented.extend(
                        self._diff_value_against_schema(item, items_schema, spec_data, prefix, seen, depth + 1)
                    )
            return undocumented

        if isinstance(value, dict):
            add_props = schema.get("additionalProperties")
            if add_props is True or isinstance(add_props, dict):
                return []
            props = schema.get("properties")
            if not isinstance(props, dict) or not props:
                return []

            undocumented = []
            for key, sub_val in value.items():
                field_path = f"{prefix}.{key}" if prefix else str(key)
                if key not in props:
                    undocumented.append(field_path)
                elif isinstance(sub_val, (dict, list)) and isinstance(props.get(key), dict):
                    undocumented.extend(
                        self._diff_value_against_schema(sub_val, props[key], spec_data, field_path, seen, depth + 1)
                    )
            return undocumented

        return []

    @staticmethod
    def is_sensitive_field_name(field_path):
        leaf = field_path.rsplit(".", 1)[-1].lower()
        return any(kw in leaf for kw in SENSITIVE_FIELD_KEYWORDS)

    def build_unauthenticated_headers(self, extra_headers=None):
        return build_cross_origin_safe_headers(self.session, extra_headers)
