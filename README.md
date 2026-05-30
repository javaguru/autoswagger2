# [AutoSwagger2](https://github.com/javaguru/autoswagger2) by **[Franck Andriano.](http://jservlet.com)**

[![Tests](https://github.com/javaguru/autoswagger2/actions/workflows/tests.yml/badge.svg)](https://github.com/javaguru/autoswagger2/actions/workflows/tests.yml)

<a href="http://jservlet.com">
  <img width="200" height="300" alt="output" src="https://github.com/javaguru/autoswagger2/blob/master/image/output2.png" />
</a>
<br>  
<br>  

This tool is a significantly enhanced version of the original **[Autoswagger](https://www.intruder.io/research/broken-authorization-apis-autoswagger)**, created by Cale Anderson at [Intruder](https://intruder.io/).

## Overview

AutoSwagger2 is a command-line utility designed to automate the security assessment of OpenAPI/Swagger-based APIs. The tool automates the process of discovering API specifications, enumerating defined endpoints, and systematically testing them for vulnerabilities such as Personally Identifiable Information (PII) exposure, credential leakage, Broken Object Level Authorization (BOLA), and Broken Function Level Authorization (BFLA).

The utility leverages the **Presidio** library for advanced PII recognition and a comprehensive set of **TruffleHog-inspired regular expressions** for the detection of sensitive keys and tokens.

## Legal Disclaimer

### Authorized and Ethical Use

The use of AutoSwagger2 is strictly reserved for authorized penetration testing, security audits, or academic research. Executing this tool against targets without prior and explicit authorization from the system owner is illegal and constitutes a violation of cybercrime laws.

### Limitation of Liability

The author of this software disclaims all liability for any use made of it. In no event shall the author be held liable for any direct or indirect damages, data loss, service interruptions, or legal proceedings resulting from the use, misuse, or inability to use this tool.

### User Responsibility

It is the end user's responsibility to ensure that their activities comply with applicable local, national, and international legislation. The user assumes full responsibility for the consequences related to the requests sent by the tool, particularly regarding the load on target servers or the exposure of sensitive data.

### Software Nature

This software is provided "as is," without warranty of any kind, express or implied. The user acknowledges using this tool at their own risk.

## Key Features

* **Advanced Specification Discovery:** Employs a multi-phase discovery process that includes direct parsing, intelligent analysis of Swagger UI pages, and context-aware path bruteforcing, ensuring compatibility with modern frameworks such as Spring Boot. **New:** An intelligent caching system prevents duplicate requests during complex discovery phases.

* **Extensive OpenAPI Support:** Precise version detection (e.g., 3.0.4, 3.1) and native support for testing OpenAPI 3.1 Webhooks (safely skipping unresolved runtime expressions).

* **Comprehensive Security Testing:**

    * **PII & Secret Detection:** Scans API responses for a wide range of secrets (e.g., API keys, JWTs) and Personally Identifiable Information types. **New:** Advanced detection patterns for JWTs (with automatic signature masking to prevent credential leakage in reports), Asymmetric Keys (RSA, ed25519), and Generic API Keys. Also implements **Sensitive Parameter Detection** to identify credentials, keys, financial data, or PII exposed in query/path parameters (CWE-598).

    * **Authorization & Resource Testing:** Automates tests for access control and denial of service issues:
        * **BOLA (Broken Object Level Authorization):** Checks if users can access resources belonging to others.
        * **BFLA (Broken Function Level Authorization):** Checks if users can access administrative or privileged functions.
        * **BOPLA (Broken Object Property Level Authorization):** Checks if users can modify sensitive object properties (e.g., changing their role to "admin").
        * **URC (Unrestricted Resource Consumption):** Checks if pagination or count parameters fail to validate boundaries, leading to potential Denial of Service (DoS) vectors.

    * **Dynamic Payload Generation:** Utilizes a comprehensive set of test vectors to probe for common vulnerability classes, including SQL Injection, NoSQL Injection, Cross-Site Scripting (XSS), and Command Injection.

    * **Debug Information Analysis:** Identifies server misconfigurations by detecting stack traces, verbose error messages, and exposed environment variables.

* **Support for Authenticated Scanning:** Facilitates testing of endpoints with or without authentication. Credentials can be supplied via generic custom headers or through user-friendly flags designed for common token-based authentication schemes.

* **Structured Reporting:** Presents findings in either a formatted, human-readable table or a structured JSON format suitable for automated processing. **New:** Intelligent filtering by risk allows you to filter the output by severity (`-severity critical|high|medium|low`).

* **Robust and Configurable Operation:** The tool is multi-threaded for performance, supports rate limiting to prevent service disruption, and implements **automatic retries with exponential backoff** to handle connection errors and timeouts against unstable APIs.

## Installation & Usage

1. **Clone the repository:**

   ```bash
   git clone https://github.com/javaguru/autoswagger2.git
   cd autoswagger2
   ```

2. **Install dependencies** (Python 3.12+ is recommended):

   ```bash
   # Utilization of a virtual environment is considered best practice.
   python -m venv venv
   source venv/bin/activate
   
   pip install -r requirements.txt
   ```

3. **Execute the tool:**

   ```bash
   # Display the   help message for a full list of options.
   python -m autoswagger2 -h
   
   # Execute a standard scan against a target URL.
   python -m autoswagger2 https://api.example.com
   ```

## Options

```
usage: autoswagger2 [-h] [-V] [-v] [-rate RATE] [--openapi-version OPENAPI_VERSION] [-risk] [-all] [-b] [--test-bfla] [--test-bopla] [--test-urc] [-H ] [--api-key ] [--api-key-src ] [--key-header ] [--key-prefix ]
                    [--bola] [--bola-id "param=id"] [-product] [-stats] [-json] [-csv] [-sarif] [-html] [--out FILE] [-severity {critical,high,medium,low}]
                    [urls ...]

AutoSwagger2: Detect unauthenticated access control issues via Swagger2/OpenAPI documentation.

positional arguments:
  urls                  Base URL(s) or spec URL(s) of the target API(s)

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -v, --verbose         Enable verbose output
  -rate RATE            Set the limit of requests per second (default: 30). Use 0 to disable rate limiting.
  --openapi-version     Force OpenAPI version detection (e.g. 2.0, 3.0.1, 3.0.4, 3.1). If not specified, auto-detect.

Scan Behavior:
  -risk                 Include non-GET requests in testing
  -all                  Include all HTTP status codes in the results, excluding 401 and 403
  -b, --brute           Enable exhaustive testing of parameter values.
  --test-bfla           Test for Broken Function Level Authorization (BFLA). Requires an auth header.
  --test-bopla          Test for Broken Object Property Level Authorization (BOPLA).
  --test-urc            Test for Unrestricted Resource Consumption (DoS).

Authentication:
  -H, --header          Add a custom Key:Value header to all requests (e.g., "Authorization: Bearer ...")
  --api-key             API key/token for authentication.
  --api-key-src         File containing the API key/token (useful for long tokens).
  --key-header          Header name for the API key/token (default: Authorization).
  --key-prefix          Prefix for the API key/token value (default: "Bearer "). Use "" for no prefix.
  --user-agent UA       Specify a custom User-Agent header for all requests.

BOLA Testing:
  --bola                Enable BOLA testing mode.
  --bola-id "param=id"  Parameter name and your ID for BOLA baseline (e.g., "userId=123").

Output:
  -product              Output all endpoints in JSON, flagging those that contain PII or have large responses.
  -stats                Display scan statistics. Included in JSON if -product or -json is used.
  -json                 Output results in JSON format in default mode.
  -csv                  Output results in CSV format.
  -sarif                Output results in SARIF format.
  -html                 Output results in HTML format.
  --out FILE            Save output to file (used with -csv, -sarif, -html).
  -severity             Filter results by minimum severity level (critical, high, medium, low).
```

## Discovery Phases

`AutoSwagger2` employs a sophisticated multi-phase process to locate the OpenAPI specification, commencing with direct methods and subsequently reverting to broader discovery techniques.

### Phase 1: Direct URL Analysis

The initial phase involves a direct analysis of the user-provided URL:

1. **Direct Spec File:** The tool first determines if the URL directly references a specification file (i.e., ending in `.json`, `.yaml`, or `.yml`). If so, it proceeds with immediate parsing.

2. **Swagger UI Page:** If the URL does not point to a spec file, it is assessed as a potential Swagger UI HTML page. If confirmed, the page's content and linked JavaScript resources (e.g., `swagger-initializer.js`) are parsed to extract the definitive specification URL. This process accommodates modern configurations, including `configUrl` objects and dynamic URL variables.

### Phase 2: Context-Aware Discovery

Should Phase 1 fail to yield a specification, the tool presumes the provided URL constitutes an application base path and initiates a targeted search from that location.

1. **Known UI Paths:** A comprehensive list of common Swagger UI paths (e.g., `/swagger-ui.html`, `/api/docs`) is tested relative to the provided URL.

2. **Direct Spec Paths:** Subsequently, a list of common direct specification file paths (e.g., `/v2/api-docs`, `/openapi.json`) is tested, also relative to the provided URL.

### Phase 3: Root Fallback Discovery

If the context-aware search is unsuccessful and the initial URL was not the server root, a final fallback procedure is executed:

1. **Root Search:** The entirety of the "Context-Aware Discovery" process is repeated, commencing from the server's root (`/`). This step is crucial for identifying specifications in applications not deployed at the domain's root.

The discovery process concludes upon the successful parsing of a valid OpenAPI specification.

## Endpoint Testing

Upon successful parsing of a specification, the utility initiates a systematic testing protocol for each defined endpoint.

1. **Endpoint Collection**
   Every path and method defined under the `paths` object in the specification is extracted for testing.

2. **HTTP Method Selection**

    * By default, only `GET` requests are dispatched to ensure a safe, read-only scan.

    * The `-risk` flag enables testing of `POST`, `PUT`, `PATCH`, and `DELETE` methods, which are capable of modifying application state.

3. **Authentication**

    * **Unauthenticated (Default):** Requests are sent without authentication credentials to identify publicly exposed endpoints.

    * **Authenticated (Optional):** Authentication credentials may be provided via command-line arguments. These credentials will be included in all subsequent requests to assess endpoints protected by authentication.

        * `-H` / `--header`: For any generic header (e.g., `Authorization: Bearer <token>`). This option may be specified multiple times.

        * `--api-key`: A user-friendly shortcut for common token-based authentication schemes.

        * `--user-agent`: Specific shortcut to set a custom User-Agent string.

4. **Parameter & Body Generation**

    * **Path & Query Parameters:** URL path and query string parameters are populated using a comprehensive list of test values.

    * **Request Bodies:** For methods such as `POST` and `PUT`, valid request bodies are automatically constructed based on the API's schema, utilizing security-focused payloads from the `TEST_VALUES` dictionary.

    * **Brute-Force Mode (`-b`):** When enabled, this option significantly increases testing depth by attempting numerous values and types for each parameter.

5. **Rate Limiting & Concurrency**

    * Tests are executed concurrently using multiple threads to optimize performance.

    * The `-rate` option controls the maximum number of requests per second to prevent service degradation on the target API.

6. **Response Analysis**

    * Each response is analyzed based on its status code, content length, and content type.

    * Text-based responses undergo scanning for PII, secrets (utilizing TruffleHog patterns), and common debug messages to identify potential information leaks.

## BOLA Testing

`AutoSwagger2` can automate the detection of Broken Object Level Authorization (BOLA) vulnerabilities. This test checks if an authenticated user can access resources belonging to other users by manipulating object IDs in the URL.

### How it Works

1.  **Activation:** The test is enabled by using the `--bola` flag in conjunction with an authentication header (`-H`) and the user's own object ID (`--bola-id`).
2.  **Target Identification:** The tool automatically identifies all endpoints in the specification that use the specified object ID as a path parameter (e.g., `/api/users/{userId}/profile`).
3.  **Baseline Request:** It sends a request with the user's own ID to establish a "normal" successful response (baseline).
4.  **Attack Phase:** It then generates "neighbor" IDs (e.g., if the user's ID is 123, it will test 122 and 124) and sends requests for these resources using the original user's session.
5.  **Verification:** A BOLA vulnerability is flagged if a request for a neighbor's resource returns a successful status code (200 OK) and a response body of a similar size to the baseline.

### Example Usage

```bash
python -m autoswagger2 https://api.example.com \
  -H "Authorization: Bearer <your_auth_token>" \
  --bola \
  --bola-id "userId=123"
```

The results are displayed in a separate table at the end of the scan.

## BFLA Testing

`AutoSwagger2` can test for Broken Function Level Authorization (BFLA) by attempting to access administrative endpoints with a non-administrative user's session.

### How it Works

1.  **Activation:** The test is enabled by using the `--test-bfla` flag in conjunction with an authentication header (`-H`) from a regular user.
2.  **Target Identification:** The tool searches for endpoints with paths containing administrative keywords (e.g., `admin`, `management`, `internal`).
3.  **Attack Phase:** It sends requests to these potentially privileged endpoints using the provided non-admin session.
4.  **Verification:** A BFLA vulnerability is flagged if a request to an administrative endpoint returns a successful status code (2xx), indicating that the user was able to access a function they should not have been authorized for.

### Example Usage

```bash
python -m autoswagger2 https://api.example.com \
  -H "Authorization: Bearer <your_NON_ADMIN_token>" \
  --test-bfla
```

## BOPLA Testing

`AutoSwagger2` can test for Broken Object Property Level Authorization (BOPLA) by injecting sensitive properties into the request bodies of `POST`, `PUT`, and `PATCH` requests.

### How it Works

1.  **Activation:** The test is enabled by using the `--test-bopla` flag.
2.  **Target Identification:** The tool identifies all `POST`, `PUT`, and `PATCH` endpoints that accept a JSON request body.
3.  **Payload Generation:** For each target, it constructs a valid baseline request body based on the API specification.
4.  **Attack Phase:** It then systematically injects sensitive key-value pairs (e.g., `"isAdmin": true`, `"role": "admin"`) into the baseline body and sends the modified request.
5.  **Verification:** A BOPLA vulnerability is flagged if the server accepts the request with the injected property and returns a successful status code (2xx).

### Example Usage

```bash
python -m autoswagger2 https://api.example.com --test-bopla
```

## URC Testing

`AutoSwagger2` can test for Unrestricted Resource Consumption (URC / API Rate Limiting and DoS vulnerabilities) by injecting extreme values into pagination and size parameters.

### How it Works

1.  **Activation:** The test is enabled by using the `--test-urc` flag.
2.  **Target Identification:** The tool automatically identifies all `GET` endpoints in the specification that accept query parameters commonly associated with pagination or count (e.g., `limit`, `size`, `page`, `offset`, `max`, `count`).
3.  **Attack Phase:** It dispatches requests with an extreme value (e.g., `999999`) to these parameters.
4.  **Verification:** A URC vulnerability is flagged if the request triggers a severe response delay (exceeding 5 seconds), a server timeout, or returns a response size larger than 500 KB, indicating a failure to enforce pagination boundaries on the server side.

### Example Usage

```bash
python -m autoswagger2 https://api.example.com --test-urc
```

## 🛠️ Complete use case

### Standard Scan + Stats

```bash
python -m autoswagger2 https://api.example.com -v -stats
```

### High Severity Scan + SARIF for CI/CD

```bash
python -m autoswagger2 https://api.example.com \
-severity critical \
-sarif --out sarif-report.sarif
```

### Full Scan + All Tests + CSV

```bash
python -m autoswagger2 https://api.example.com \
-risk \
--test-bola --test-bfla --test-bopla --test-urc \
-csv --out full-report.csv
```

### Custom User-Agent + Proxy + OpenAPI 3.1

```bash
python -m autoswagger2 https://api.example.com \
--user-agent "Mozilla/5.0 (X11; Linux x86_64)" \
--openapi-version 3.1 \
-html --out report.html
```

### JSON Filter High Only

```bash
python -m autoswagger2 https://api.example.com \
-severity high \
-json | jq '.results[] | select(.pii_detected==true)'
```

## Response Analysis & Data Leakage Detection

`AutoSwagger2` extends beyond simple accessibility checks by performing a multi-layered analysis on the content of every successful response to identify potential data leaks.

### 1. High-Confidence Findings (PII & Secrets)

The script actively searches for high-confidence indicators of sensitive data exposure:

* **Personally Identifiable Information (PII):** Using the `presidio-analyzer` library, it performs context-aware scanning to pinpoint common PII such as:

    * Personal Identifiers: Names, Dates of Birth

    * Contact Information: Email Addresses, Phone Numbers, Physical Addresses

    * Financial Data: Credit Card Numbers, IBANs

    * National IDs: French INSEE Numbers, US Social Security Numbers

    * Other Identifiers: Passport Numbers, IP/MAC Addresses, License Plates (FR/US)

* **Secrets and Credentials:** It uses a comprehensive list of `TruffleHog`-inspired regular expressions to detect a wide range of secrets, including:

    * API Keys for various services (AWS, Google Cloud, Stripe, etc.)

    * JSON Web Tokens (JWT)

    * Private keys and credentials

Any finding in this category is considered a high-priority issue and is flagged under the **PII/Secret** column in the results table.

### 2. Low-Confidence Indicators (Debug Info & Data Exposure)

The script also looks for red flags that might not be secrets themselves but often indicate a misconfiguration or a potential information leak:

* **Debug Information:** It searches for common debug keywords (`ERROR`, `stacktrace`), environment variable names (`AWS_`, `env.`), and database error messages. These findings are flagged under the **Debug Info** column.

* **Large Responses:** As a heuristic, the script flags responses that are unusually large (e.g., containing over 100 JSON objects or exceeding 100k bytes). This can often indicate an endpoint that is leaking excessive data, such as returning the entire user database instead of a single record. These are marked as "interesting" in the JSON output.

## Output

**AutoSwagger2** offers two main output formats: a human-readable table (default) and a machine-readable JSON format for integration with other tools.

### Default Table View

By default, results are displayed in a formatted table in your terminal. This view is designed for quick manual analysis and highlights key information:

* **PII/Secret:** A clear "Yes/No" indicator, highlighted in red if potential secrets or PII are found.

* **Debug Info:** A separate "Yes/No" indicator for lower-priority findings like stack traces or error messages.

* **Body:** When using the `-risk` flag, this column shows the request body that was sent to the server.

### Multiple Output Formats

For automation and integration, you can use one of the several output options:

* **`-json`:** Outputs a detailed JSON array containing the "best" result for every tested endpoint. This is useful for custom scripting or manual review of all findings.

* **`-product`:** Produces a filtered JSON output containing **only** the endpoints that are considered "interesting" (i.e., those with PII/Secrets, debug info, or unusually large responses). This mode is ideal for feeding results into other security tools or for CI/CD pipelines where you only want to be alerted to potential issues.

* **`-csv`:** Exports the results as a standard Comma Separated Values file, making it easy to open in Excel or other spreadsheet tools.

* **`-sarif`:** Exports the results in the Static Analysis Results Interchange Format (SARIF). This format is natively supported by GitHub Security Alerts, VS Code, and other modern CI/CD tools.

* **`-html`:** Generates an interactive and visually appealing HTML report that can be opened in any web browser.

* **`--out <FILE>`:** Specifies the output file name for the `-csv`, `-sarif`, and `-html` formats. If omitted, a default name (e.g., `autoswagger_report.csv`) will be used.

### Statistics

* **`-stats`:** This flag can be combined with any other output option. It will add a "Scan Statistics" block at the end of the output, providing a summary of the scan (hosts tested, requests sent, etc.).

## Interpretation of Scan Results

The analysis of the data generated by `AutoSwagger2` necessitates a structured and methodical approach. Although the tool is designed for the rapid identification of potential security vulnerabilities, it is imperative that all findings undergo a process of manual verification. The following guide provides a framework for the prioritization and interpretation of the scan's output.

### Prioritization of Findings

The resultant data is presented in a manner intended to facilitate the immediate identification of critical issues. A hierarchical approach to the triage of these results is recommended.

#### Category 1: High-Confidence Indicators of Sensitive Data Exposure

**Primary attention should be directed toward any entry for which the `PII/Secret` column indicates an affirmative result.**

Such findings are to be considered of the highest criticality. An affirmative result signifies that the script has detected data that corresponds with a high degree of certainty to a known pattern for a secret credential (e.g., an API key, a JSON Web Token) or Personally Identifiable Information (PII).

* **Recommended Action:** These endpoints warrant immediate investigation. It is advised to utilize a tool such as `curl` or an API testing suite to replicate the request. A thorough examination of the complete server response is required to confirm the precise nature and context of the exposed data.

#### Category 2: Medium-Confidence Indicators of Misconfiguration

**Subsequent analysis should focus on entries where the `Debug Info` column is marked affirmative, or on endpoints associated with an unusually high `Content Length`.**

* **Debug Information:** The presence of application stack traces, verbose error messages, or environment variable names is indicative of a server-side misconfiguration. While not constituting a direct leakage of credentials, such information provides a significant tactical advantage to a potential adversary for the formulation of more sophisticated attacks.

* **Large Responses:** An endpoint that returns a response of considerable size (e.g., in excess of 100 kilobytes) may be indicative of an excessive data exposure vulnerability. This condition could suggest, for instance, the return of an entire database table where only a single record was anticipated.

* **Recommended Action:** A manual review of these endpoints is necessary to ascertain the context of the information leak. It must be determined whether the response constitutes a generic error or reveals sensitive internal architectural details.

#### Category 3: Analysis of Publicly Accessible Endpoints

**A final review should encompass all other endpoints that returned a `200 OK` status code.**

The primary function of `AutoSwagger2` is the identification of endpoints accessible without authentication. The public availability of an endpoint may be contrary to intended security policy, even in the absence of a direct PII or secret leak.

* **Recommended Action:** For each such endpoint, an evaluation must be made as to whether public access is appropriate. An endpoint such as `/api/v1/users` that enumerates all system users represents a significant vulnerability, irrespective of whether passwords are also exposed.

### Manual Verification Protocol

It is a mandatory step to independently confirm all automated findings. The output table provides the exact `Method` and `URL` required to replicate the request.

**Example of Replication using `curl`:**

Should the tool report a potential issue with the `POST /v1/user/get` endpoint, replication can be readily achieved. If an authentication header was utilized during the initial scan, it must be included in any subsequent manual verification attempts.

```bash
# Example of a simple GET request
curl -X GET "https://api.example.com/v1/user/get"

# Example of a POST request with a request body and an authentication header
curl -X POST "https://api.example.com/v1/admin/action" \
-H "Authorization: Bearer <TOKEN_VALUE>" \
-H "Content-Type: application/json" \
-d '{"action": "create"}'
```

For more complex analysis and manipulation of requests, the use of specialized tools such as **Burp Suite** or **Postman** is recommended.

## Statistical Aggregation and Reporting

The `-stats` flag enables the aggregation and presentation of key scan metrics, providing a quantitative summary of the tool's execution and findings.

### Metrics Collected

When enabled, the following statistics are compiled:

* **Host Analysis:** The number of unique hosts provided, the number of active hosts that responded, the number of hosts for which a valid OpenAPI specification was successfully parsed, and the percentage of active hosts that yielded one or more valid endpoint responses.

* **Findings Summary:** The total number of hosts returning at least one endpoint with high-confidence PII or secret findings.

* **Request Metrics:** The total number of HTTP requests dispatched during the scan and the calculated average requests per second (RPS).

### Output Format

The presentation of these statistics is contingent upon the selected output mode:

* **Default Mode:** In the default operational mode, statistics are rendered in a formatted table at the conclusion of the scan.

* **JSON Mode:** When JSON output is selected via the `-json` or `-product` flags, these metrics are serialized and included as a `stats` object within the final JSON output.

## License

This project is an Open Source Software released under the [BSD 3-Clause License](https://github.com/javaguru/autoswagger2/blob/master/LICENSE).

## Authors - Acknowledgments

AutoSwagger2 [**Franck ANDRIANO.**](http://jservlet.com) - AutoSwagger was primarily maintained by [**Intruder**](https://intruder.io/) and primarily developed by Cale Anderson
