# autoswagger2/utils/config.py
# Contains all global constants and configurations.

__version__ = "2.0.3"

# --- IMPROVEMENT: Expanded discovery paths based on Nuclei templates ---
SWAGGER_UI_PATHS = sorted({
    "/", "/apidocs/", "/swagger/ui/index", "/swagger/index.html", "/swagger-ui.html",
    "/swagger-ui/index.html", "/swagger/swagger-ui.html", "/api/swagger-ui.html",
    "/api_docs", "/api/index.html", "/api/doc", "/api/docs/", "/api/swagger/index.html",
    "/api/swagger/swagger-ui.html", "/api/swagger-ui/api-docs", "/api/api-docs",
    "/api/apidocs", "/api/swagger", "/api/swagger/static/index.html",
    "/api/swagger-resources", "/api/swagger-resources/restservices/v2/api-docs",
    "/api/__swagger__/", "/api/_swagger_/", "/docu", "/docs", "/swagger", "/api-doc",
    "/doc/", "/webjars/swagger-ui/index.html", "/3.0.0/swagger-ui.html",
    "/MobiControl/api/docs/index/index.html", "/Swagger", "/Swagger/", "/Swagger/index.html",
    "/V2/api-docs/ui", "/admin/swagger-ui/index.html", "/api-doc/", "/api-docs/",
    "/api-docs/ui/", "/api-docs/v1/index.html", "/api-documentation/index.html",
    "/api/", "/api/api-docs", "/api/api-docs/index.html", "/api/api/",
    "/api/apidocs", "/api/config", "/api/doc", "/api/doc/", "/api/spec/", "/spec/",
    "/swagger-ui/swagger-ui.js", "/swagger/swagger-ui.js", "/swagger-ui.js",
    "/swagger/ui/swagger-ui.js", "/api/docs/index.html", "/api/help/swagger-console.html",
    "/api/swagger/ui/index", "/__swagger__/", "/_swagger_/",
    "/swagger-resources/configuration/security", "/swagger-resources/configuration/ui",
    "/swagger-ui/", "/swagger-ui/vendor", "/swagger/", "/swagger/api-docs/",
    "/swagger/dist/index.html", "/swagger/document", "/swagger/static/index.html",
    "/swaggerui/", "/swaggerui/index.html", "/v1/api-docs/", "/v1/api-docs/index.html",
    "/v1/swagger-ui.html", "/v3/api-docs/ui", "/webapi/index.html",
    "/webapi/swagger/index.html", "/webjars/springfox-swagger-ui/3.0.0/swagger-ui.html",
    "/webjars/swagger-ui/2.2.5/index.html",
    # UI Paths for OpenAPI 3.1
    "/v3.1/api-docs/ui", "/v3.1/swagger-ui.html",
    "/api/v3.1/swagger-ui.html", "/openapi3.1/swagger-ui.html",
    "/api/openapi3.1/swagger-ui.html", "/docs/openapi3.1/ui",
})

DIRECT_SPEC_PATHS = sorted({
    "/swagger.json", "/swagger.yaml", "/swagger.yml", "/api/swagger.json",
    "/api/swagger.yaml", "/api/swagger.yml", "/v1/swagger.json",
    "/v1/swagger.yaml", "/v1/swagger.yml", "/openapi.json",
    "/openapi.yaml", "/openapi.yml", "/api/openapi.json",
    "/api/openapi.yaml", "/api/openapi.yml", "/docs/swagger.json",
    "/docs/swagger.yaml", "/docs/openapi.json", "/docs/openapi.yaml",
    "/api-docs/swagger.json", "/api-docs/swagger.yaml",
    "/swagger/v1/swagger.json", "/swagger/v1/swagger.yaml",
    "/rest/swagger.json", "/rest/swagger.yaml", "/rest-api/swagger.json",
    "/swagger/v1/docs.json", "/api/swagger/docs.json",
    "/swagger/docs/v1.json", "/swagger/swagger.json", "/swagger/swagger.yaml",
    "/api-doc.json", "/api/spec/swagger.json", "/api/spec/swagger.yaml",
    "/api/v1/swagger-ui/swagger.json", "/api/v1/swagger-ui/swagger.yaml",
    "/api/swagger_doc.json", "/v2/swagger.json", "/v2/swagger.yaml",
    "/v3/swagger.json", "/v3/swagger.yaml", "/openapi2.json",
    "/openapi2.yaml", "/openapi2.yml", "/api/v3/openapi.json",
    "/api/v3/openapi.yaml", "/api/v3/openapi.yml", "/spec/swagger.json",
    "/spec/swagger.yaml", "/spec/openapi.json", "/spec/openapi.yaml",
    "/api-docs/swagger-ui.json", "/api-docs/swagger-ui.yaml",
    "/api-docs/openapi.json", "/api-docs/openapi.yaml",
    "/swagger-ui.json", "/swagger-ui.yaml",
    "/v2/api-docs", "/v3/api-docs",

    "/v3.1/api-docs", "/v3.1/openapi.json", "/v3.1/openapi.yaml", "/v3.1/openapi.yml",
    "/api/v3.1/openapi.json", "/api/v3.1/openapi.yaml", "/api/v3.1/openapi.yml",
    "/openapi3.1.json", "/openapi3.1.yaml", "/openapi3.1.yml",
    "/api/openapi3.1.json", "/api/openapi3.1.yaml", "/api/openapi3.1.yml",
    "/docs/openapi3.1.json", "/docs/openapi3.1.yaml",
    "/spec/openapi3.1.json", "/spec/openapi3.1.yaml",
    "/specs/openapi.json", "/specs/openapi.yaml",
    "/api-specs/openapi.json", "/api-specs/openapi.yaml",

    # swagger-ui-init.js paths (Express swagger-ui-express, etc.)
    "/swagger-ui-init.js", "/swagger-ui/swagger-ui-init.js", "/swagger/swagger-ui-init.js",
    "/api/swagger-ui-init.js", "/api/docs/swagger-ui-init.js", "/api/v1/docs/swagger-ui-init.js",
    "/docs/swagger-ui-init.js", "/v1/docs/swagger-ui-init.js",
})

# --- IMPROVEMENT: More creative and comprehensive test values ---
# Expanded with a wider range of payloads for injection, traversal, and edge cases.
TEST_VALUES = {
    "integer": [1, 0, -1, 100, 999999, 2147483647],
    "string": [
        # --- Common & Default ---
        "test", "admin", "1", "", "*",
        # --- Injection Payloads (SQL, NoSQL, Command, SSTI) ---
        "' OR 1=1--", "'; exec sp_xp_cmdshell 'whoami'--",
        "||'admin'--",
        "||(SELECT 'admin')",
        "1; SELECT pg_sleep(10)--",
        "{\"username\":{\"$ne\": \"\"}, \"password\":{\"$ne\": \"\"}}",
        "; ls -la", "| whoami", "`id`",
        "{{7*7}}", "${7*7}}", "<%= 7*7 %>",
        # --- Traversal & File Inclusion ---
        "../../../../etc/passwd", "../../../../../windows/system32/drivers/etc/hosts",
        "file:///etc/passwd", "php://filter/convert.base64-encode/resource=index.php",
        # --- XSS Payloads ---
        "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        # --- Edge Cases & Fuzzing ---
        "null", "true", "false", "undefined",
        "test@example.com", "550e8400-e29b-41d4-a716-446655440000", # Email & UUID
        "A" * 1024, # Long string
        "你好", # Unicode
        "%00", "%0a", "%0d", # Control characters
        "'" , "\"", "<", ">", "&", # Special characters
    ],
    "boolean": [True, False],
    "number": [1.0, 0.0, -1.5, 999.99, 1.7976931348623157e+308],
    "base64": [
        # --- Common & Default ---
        "MQ==", # 1
        "YWRtaW4=", # admin
        # --- Auth-related Payloads ---
        "YWRtaW46YWRtaW4=", # admin:admin
        "dGVzdDE6MTIzNDU2", # test1:123456
        # --- Common Formats & Files ---
        "eyJ1c2VyIjogImFkbWluIiwgImlkIjogMTIzfQ==", # {"user": "admin", "id": 123}
        "L2V0Yy9wYXNzd2Q=", # /etc/passwd
        "UEsDBAoAAAAA", # PK.. zip file header
    ],
    "default": ["1", "test", True, "550e8400-e29b-41d4-a716-446655440000", "*"]
}

BOPLA_SENSITIVE_KEYS = {
    "isAdmin": [True, 1, "true"],
    "admin": [True, 1, "true"],
    "role": ["admin", "administrator"],
    "permission": ["all", "*", "true", 1],
    "is_admin": [True, 1, "true"],
    "isadmin": [True, 1, "true"],
    "user_role": ["admin", "administrator"],
    "account_type": ["premium", "admin"],
    "credits": [999999],
    "balance": [999999]
}

PAGINATION_KEYWORDS = ['limit', 'size', 'page', 'offset', 'max', 'count']
