# AutoSwagger2 by Franck Andriano

<a href="http://jservlet.com">
  <img width="966" alt="output" src="https://github.com/javaguru/autoswagger2/blob/master/image/output.png" />
</a>
<br>  
<br>  

This tool represents a significant enhancement of the original **Autoswagger**, which was developed by Cale Anderson at [Intruder](https://intruder.io/).

## Overview

AutoSwagger2 is a command-line utility designed to automate the security assessment of OpenAPI/Swagger-based APIs. The tool automates the process of discovering API specifications, enumerating defined endpoints, and systematically testing them for vulnerabilities such as Personally Identifiable Information (PII) exposure, credential leakage, and broken access control.

The utility leverages the **Presidio** library for advanced PII recognition and a comprehensive set of **TruffleHog-inspired regular expressions** for the detection of sensitive keys and tokens.

## Key Features

* **Advanced Specification Discovery:** Employs a multi-phase discovery process that includes direct parsing, intelligent analysis of Swagger UI pages, and context-aware path bruteforcing, ensuring compatibility with modern frameworks such as Spring Boot.

* **Comprehensive Security Testing:**
    * **PII & Secret Detection:** Scans API responses for a wide range of secrets (e.g., API keys, JWTs) and Personally Identifiable Information (e.g., names, email addresses).
    * **Dynamic Payload Generation:** Utilizes a comprehensive set of test vectors to probe for common vulnerability classes, including SQL Injection, NoSQL Injection, Cross-Site Scripting (XSS), and Command Injection.
    * **Debug Information Analysis:** Identifies server misconfigurations by detecting stack traces, verbose error messages, and exposed environment variables.

* **Support for Authenticated Scanning:** Facilitates testing of endpoints with or without authentication. Credentials can be supplied via generic custom headers or through user-friendly flags designed for common token-based authentication schemes.

* **Structured Reporting:** Presents findings in either a formatted, human-readable table or a structured JSON format suitable for automated processing. The output clearly differentiates between high-priority secret disclosures and lower-priority debug information.

* **Robust and Configurable Operation:** The tool is multi-threaded for performance, supports rate limiting to prevent service disruption, and provides a suite of command-line arguments to customize scan behavior and output.

---

## Installation & Usage

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/javaguru/autoswagger2.git](https://github.com/javaguru/autoswagger2.git)
    cd autoswagger2
    ```

2.  **Install dependencies** (Python 3.12+ is recommended):
    ```bash
    # Utilization of a virtual environment is considered best practice.
    python -m venv venv
    source venv/bin/activate
    
    pip install -r requirements.txt
    ```

3.  **Execute the tool:**
    ```bash
    # Display the help message for a full list of options.
    python autoswagger2.py -h
    
    # Execute a standard scan against a target URL.
    python autoswagger2.py [https://api.example.com](https://api.example.com)
    ```

---

## Options

```
usage: autoswagger2.py [-h] [-V] [-v] [-rate RATE] [-risk] [-all] [-b] [-H] [--api-key] [--api-key-src] [--key-header] [--key-prefix] [-product] [-stats] [-json] [urls ...]

AutoSwagger2: Detect unauthenticated access control issues via Swagger2/OpenAPI documentation.

positional arguments:
  urls                  Base URL(s) or spec URL(s) of the target API(s)

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -v, --verbose         Enable verbose output
  -rate RATE            Set the rate limit in requests per second (default: 30). Use 0 to disable rate limiting.

Scan Behavior:
  -risk                 Include non-GET requests in testing
  -all                  Include all HTTP status codes in the results, excluding 401 and 403
  -b, --brute           Enable exhaustive testing of parameter values.

Authentication:
  -H, --header          Add a custom header to all requests (e.g., "X-Custom-Header: 123")
  --api-key             API key/token for authentication.
  --api-key-src         File containing the API key/token (useful for long tokens).
  --key-header          Header name for the API key/token (default: Authorization).
  --key-prefix          Prefix for the API key/token value (default: "Bearer "). Use "" for no prefix.

Output:
  -product              Output all endpoints in JSON, flagging those that contain PII or have large responses.
  -stats                Display scan statistics. Included in JSON if -product or -json is used.
  -json                 Output results in JSON format in default mode.

Example usage:
  python autoswagger2.py [https://api.example.com](https://api.example.com) -v

```

---
## Discovery Phases

`AutoSwagger2` employs a sophisticated multi-phase process to locate the OpenAPI specification, commencing with direct methods and subsequently reverting to broader discovery techniques.

### Phase 1: Direct URL Analysis

The initial phase involves a direct analysis of the user-provided URL:

1.  **Direct Spec File:** The tool first determines if the URL directly references a specification file (i.e., ending in `.json`, `.yaml`, or `.yml`). If so, it proceeds with immediate parsing.
2.  **Swagger UI Page:** If the URL does not point to a spec file, it is assessed as a potential Swagger UI HTML page. If confirmed, the page's content and linked JavaScript resources (e.g., `swagger-initializer.js`) are parsed to extract the definitive specification URL. This process accommodates modern configurations, including `configUrl` objects and dynamic URL variables.

---
### Phase 2: Context-Aware Discovery

Should Phase 1 fail to yield a specification, the tool presumes the provided URL constitutes an application base path and initiates a targeted search from that location.

1.  **Known UI Paths:** A comprehensive list of common Swagger UI paths (e.g., `/swagger-ui.html`, `/api/docs`) is tested relative to the provided URL.
2.  **Direct Spec Paths:** Subsequently, a list of common direct specification file paths (e.g., `/v2/api-docs`, `/openapi.json`) is tested, also relative to the provided URL.

---
### Phase 3: Root Fallback Discovery

If the context-aware search is unsuccessful and the initial URL was not the server root, a final fallback procedure is executed:

1.  **Root Search:** The entirety of the "Context-Aware Discovery" process is repeated, commencing from the server's root (`/`). This step is crucial for identifying specifications in applications not deployed at the domain's root.

The discovery process concludes upon the successful parsing of a valid OpenAPI specification.

---

## Endpoint Testing

Upon successful parsing of a specification, the utility initiates a systematic testing protocol for each defined endpoint.

1.  **Endpoint Collection**
    Every path and method defined under the `paths` object in the specification is extracted for testing.

2.  **HTTP Method Selection**
    - By default, only `GET` requests are dispatched to ensure a safe, read-only scan.
    - The `-risk` flag enables testing of `POST`, `PUT`, `PATCH`, and `DELETE` methods, which are capable of modifying application state.

3.  **Authentication**
    - **Unauthenticated (Default):** Requests are sent without authentication credentials to identify publicly exposed endpoints.
    - **Authenticated (Optional):** Authentication credentials may be provided via command-line arguments. These credentials will be included in all subsequent requests to assess endpoints protected by authentication.
        - `-H` / `--header`: For any generic header (e.g., `Authorization: Bearer <token>`). This option may be specified multiple times.
        - `--api-key`: A user-friendly shortcut for common token-based authentication schemes.

4.  **Parameter & Body Generation**
    - **Path & Query Parameters:** URL path and query string parameters are populated using a comprehensive list of test values.
    - **Request Bodies:** For methods such as `POST` and `PUT`, valid request bodies are automatically constructed based on the API's schema, utilizing security-focused payloads from the `TEST_VALUES` dictionary.
    - **Brute-Force Mode (`-b`):** When enabled, this option significantly increases testing depth by attempting numerous values and types for each parameter.

5.  **Rate Limiting & Concurrency**
    - Tests are executed concurrently using multiple threads to optimize performance.
    - The `-rate` option controls the maximum number of requests per second to prevent service degradation on the target API.

6.  **Response Analysis**
    - Each response is analyzed based on its status code, content length, and content type.
    - Text-based responses undergo scanning for PII, secrets (utilizing TruffleHog patterns), and common debug messages to identify potential information leaks.

---


## Response Analysis & Data Leakage Detection

`AutoSwagger2` extends beyond simple accessibility checks by performing a multi-layered analysis on the content of every successful response to identify potential data leaks.

### 1. High-Confidence Findings (PII & Secrets)

The script actively searches for high-confidence indicators of sensitive data exposure:

* **Personally Identifiable Information (PII):** Using the `presidio-analyzer` library, it performs context-aware scanning to pinpoint common PII such as:
    * Names
    * Email addresses
    * Phone numbers
    * Physical addresses

* **Secrets and Credentials:** It uses a comprehensive list of `TruffleHog`-inspired regular expressions to detect a wide range of secrets, including:
    * API Keys for various services (AWS, Google Cloud, Stripe, etc.)
    * JSON Web Tokens (JWT)
    * Private keys and credentials

Any finding in this category is considered a high-priority issue and is flagged under the **PII/Secret** column in the results table.

---
### 2. Low-Confidence Indicators (Debug Info & Data Exposure)

The script also looks for red flags that might not be secrets themselves but often indicate a misconfiguration or a potential information leak:

* **Debug Information:** It searches for common debug keywords (`ERROR`, `stacktrace`), environment variable names (`AWS_`, `env.`), and database error messages. These findings are flagged under the **Debug Info** column.

* **Large Responses:** As a heuristic, the script flags responses that are unusually large (e.g., containing over 100 JSON objects or exceeding 100k bytes). This can often indicate an endpoint that is leaking excessive data, such as returning the entire user database instead of a single record. These are marked as "interesting" in the JSON output.

---


## Output

**AutoSwagger2** offers two main output formats: a human-readable table (default) and a machine-readable JSON format for integration with other tools.

### Default Table View

By default, results are displayed in a formatted table in your terminal. This view is designed for quick manual analysis and highlights key information:

* **PII/Secret:** A clear "Yes/No" indicator, highlighted in red if potential secrets or PII are found.
* **Debug Info:** A separate "Yes/No" indicator for lower-priority findings like stack traces or error messages.
* **Body:** When using the `-risk` flag, this column shows the request body that was sent to the server.

### JSON Output

For automation and integration, you can use one of the JSON output options:

* **`-json`:** Outputs a detailed JSON array containing the "best" result for every tested endpoint. This is useful for custom scripting or manual review of all findings.
* **`-product`:** Produces a filtered JSON output containing **only** the endpoints that are considered "interesting" (i.e., those with PII/Secrets, debug info, or unusually large responses). This mode is ideal for feeding results into other security tools or for CI/CD pipelines where you only want to be alerted to potential issues.

### Statistics

* **`-stats`:** This flag can be combined with any other output option. It will add a "Scan Statistics" block at the end of the output, providing a summary of the scan (hosts tested, requests sent, etc.).

---


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

Should the tool report a potential issue with the `POST /v2/pet` endpoint, replication can be readily achieved. If an authentication header was utilized during the initial scan, it must be included in any subsequent manual verification attempts.

```
# Example of a simple GET request
curl -X GET "[https://petstore.swagger.io/v2/user/logout](https://petstore.swagger.io/v2/user/logout)"

# Example of a POST request with a request body and an authentication header
curl -X POST "[https://api.example.com/v1/admin/action](https://api.example.com/v1/admin/action)" \
-H "Authorization: Bearer <TOKEN_VALUE>" \
-H "Content-Type: application/json" \
-d '{"action": "create"}'
```

For more complex analysis and manipulation of requests, the use of specialized tools such as **Burp Suite** or **Postman** is recommended.


---



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

---

## License

This project is an Open Source Software released under the [BSD 3-Clause License](https://github.com/javaguru/autoswagger2/blob/master/LICENSE).

---

## Acknowledgments

AutoSwagger2 **[Franck ANDRIANO.](http://jservlet.com)** (AutoSwagger was primarily maintained by **[Intruder](https://intruder.io/)** and primarily developed by Cale Anderson)
