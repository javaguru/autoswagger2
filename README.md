# [AutoSwagger2](https://github.com/javaguru/autoswagger) by **[Franck Andriano.](http://jservlet.com)**
<a href="http://jservlet.com">
  <img width="966" alt="output" src="https://github.com/javaguru/autoswagger/blob/master/image/output.png" />
</a>
<br>  
<br>  

Original creation by [Intruder](https://intruder.io/) 
**[Autoswagger](https://www.intruder.io/research/broken-authorization-apis-autoswagger)**

This script has been significantly enhanced from the original version.
Key improvements are detailed below:

1. Advanced Spec Discovery Engine:
    - Context-Aware Searching: The discovery logic now prioritizes searching within the user-provided URL path
      (e.g., /app-context/) before falling back to the server root, making it effective for non-root applications.
    - Intelligent URL Handling: It correctly distinguishes between direct spec URLs, Swagger UI pages, and base URLs,
      and follows the appropriate discovery path for each.
    - Spring Boot / springdoc-openapi Compatibility: The parser now correctly handles multi-step discovery,
      including the `configUrl` property and API group lists, to find the true spec URL.
    - Default Configuration Filtering: Actively ignores the default "petstore.swagger.io" example URL to prevent false positives.

 2. Enhanced Security Analysis Capabilities:
    - Expanded discovery paths based on Nuclei templates.
    - Secret Detection (TruffleHog Patterns): The list of regex patterns has been significantly expanded to detect
      modern secrets, including JSON Web Tokens (JWT), Azure and Google Cloud credentials, and Ethereum private keys.
    - PII (Personally Identifiable Information) Detection: Integrated the 'presidio-analyzer' library to scan
      API responses for sensitive personal data like names, emails, phone numbers, and addresses.
    - Creative Test Payloads: The `TEST_VALUES` dictionary has been completely revamped with a wide range of payloads
      for SQLi, NoSQLi, Command Injection, SSTI, XSS, Path Traversal, and various fuzzing/edge cases.
    - Refined Debug Info Detection: The pattern for detecting debug information is now more comprehensive,
      catching common stack traces and database error messages while being classified separately from secrets.

 3. General & Quality-of-Life Improvements:
    - Custom User-Agent: All outgoing HTTP requests now use a 'AutoSwagger2' User-Agent for better identification in server logs.
    - Robustness & Bug Fixes:
        - Correctly generates JSON object request bodies when expected by the API, resolving backend errors.
        - Prevents false positives by skipping secret detection on binary content (e.g., images, octet-streams).
        - Fixed serialization errors for table and JSON output when handling binary or complex request bodies.
    - Expanded Path Lists: Added more common paths to `SWAGGER_UI_PATHS` and `DIRECT_SPEC_PATHS` to increase the success rate of discovery.
    - Modernized Output: The output now clearly distinguishes between high-confidence "PII/Secret" findings and lower-confidence "Debug Info" indicators.

## Table of Contents
1. [Introduction](#introduction)
2. [Key Features](#key-features)
3. [Installation & Usage](#installation--usage)
4. [Discovery Phases](#discovery-phases)
5. [Endpoint Testing](#endpoint-testing)
6. [PII Detection](#pii-detection)
7. [Output Examples](#output)
8. [Stats & Reporting](#stats--reporting)
9. [Acknowledgments](#acknowledgments)

---

## Introduction

AutoSwagger2 automates the process of finding **OpenAPI/Swagger** specifications, extracting API endpoints, and systematically testing them for **PII** exposure, **secrets**, and large or interesting responses. It leverages **Presidio** for PII recognition and **regex** for sensitive key/token detection.

---

## Key Features

- **Multiple Discovery Phases**  
  Discovers OpenAPI specs in three ways:
  1. **Direct Spec**: If a full URL with a path ending in `.json`, `.yaml`, or `.yml` is provided, parse that file directly.  
  2. **Swagger UI**: Parse known paths of Swagger UI (e.g. `/swagger-ui.html`), and extract spec from HTML or JavaScript.  
  3. **Direct Spec by Bruteforce**: Attempt discovery using common OpenAPI schema locations (`/swagger.json`, `/openapi.json`, etc.). Only attempt this if 1. and 2. did not yield a result.

- **Parallel Endpoint Testing**  
  Multi-threaded concurrent testing of many endpoints, respecting a configurable rate limit (`-rate`).

- **Brute-Force of Parameter Values**  
  If `-b` or `--brute` is used, try using various data types with a few example values in an attempt to bypass parameter-specific validations.

- **Presidio PII Detection**  
  Check output for phone numbers, emails, addresses, and names (with context validation to reduce false positives). Also parse CSV rows and naive “key: value” lines.

- **Secrets Detection**  
  Leverages a set of regex patterns to detect tokens, keys, and debugging artifacts (like environment variables).

- **Command Line or JSON Output**  
  In default mode, displays results in a table. With `-json`, output a JSON structure. `-product` mode filters output to only show those that contain PII, secrets, or large responses.


---

## Installation & Usage

1. **Clone** or **download** the repository containing AutoSwagger2.
   ```bash
   git clone git@github.com:javaguru/autoswagger.git
   ```


2. **Install dependencies** (e.g., using Python 3.7+):
   ```bash
   pip install -r requirements.txt
   ```

   (It's recommended to use a virtual environment for this: `python3 -m venv venv;source venv/bin/activate`)

3. **Check installation, show help:**
  ```bash
  python3 autoswagger2.py -h
  ```



## Flags 

| Flag                 | Description                                                                                                 |
|----------------------|-------------------------------------------------------------------------------------------------------------|
| `urls`               | List of base URLs or direct spec URLs.                                                                       |
| `-v, --verbose`      | Enables verbose logging. Creates a log file under `~/.autoswagger/logs`.                                     |
| `-risk`              | Includes non-GET methods (POST, PUT, PATCH, DELETE) in testing.                                              |
| `-all`               | Includes 200 and 404 endpoints in output (excludes 401/403).                                                 |
| `-product`           | Outputs only endpoints with PII or large responses, in JSON format.                                          |
| `-stats`             | Displays scan statistics (e.g. requests, RPS, hosts with PII).                                               |
| `-rate <N>`          | Throttles requests to N requests per second. Default is 30. Use 0 to disable rate limiting.                  |
| `-b, --brute`        | Enables brute-forcing of parameter values (multiple test combos).                                            |
| `-json`              | Outputs results in JSON format instead of a Rich table in default mode.                                      |


## Help

```
    ___         __       _____                                    ___
   /   | __  __/ /_____ / ___/      ______ _____ _____ ____  ____|__ \
  / /| |/ / / / __/ __ \\__ \ | /| / / __ `/ __ `/ __ `/ _ \/ ___/_/ /
 / ___ / /_/ / /_/ /_/ /__/ / |/ |/ / /_/ / /_/ / /_/ /  __/ /  / __/
/_/  |_\__,_/\__/\____/____/|__/|__/\__,_/\__, /\__, /\___/_/  /____/
                                         /____//____/
                              https://jservlet.com
                          Find unauthenticated endpoints

usage: autoswagger2.py [-h] [-v] [-risk] [-all] [-product] [-stats] [-rate RATE] [-b] [-json] [urls ...]

Autoswagger2: Detect unauthenticated access control issues via Swagger2/OpenAPI documentation.

positional arguments:
  urls           Base URL(s) or spec URL(s) of the target API(s)

options:
  -h, --help     show this help message and exit
  -v, --verbose  Enable verbose output
  -risk          Include non-GET requests in testing
  -all           Include all HTTP status codes in the results, excluding 401 and 403
  -product       Output all endpoints in JSON, flagging those that contain PII or have large responses.
  -stats         Display scan statistics. Included in JSON if -product or -json is used.
  -rate RATE     Set the rate limit in requests per second (default: 30). Use 0 to disable rate limiting.
  -b, --brute    Enable exhaustive testing of parameter values.
  -json          Output results in JSON format in default mode.

Example usage:
  python autoswagger2.py https://api.example.com -v

```
## Discovery Phases

1. **Direct Spec**  
   If a provided URL ends with `.json/.yaml/.yml`, Autoswagger **directly** attempts to parse the OpenAPI schema.

2. **Swagger-UI Detection**  
   - Tries known UI paths (e.g., `/swagger-ui.html`).
   - If found, parses the HTML or local JavaScript files for a `swagger.json` or `openapi.json`.
   - Can detect embedded configs like `window.swashbuckleConfig`.

3. **Direct Spec by Bruteforce**  
   - If no spec is found so far, Autoswagger attempts a list of default endpoints like `/swagger.json`, `/openapi.json`, etc.
   - Stops when a valid spec is discovered or none are found.

---

## Endpoint Testing

1. **Collect Endpoints**  
   After loading a spec, Autoswagger extracts each path and method under the `paths` key.

2. **HTTP Methods**  
   - By default, tests `GET` only.  
   - Use `-risk` to include other methods (`POST`, `PUT`, `PATCH`, `DELETE`).

3. **Parameter Values**  
   - Fill path/query parameters with defaults or values to enumerate.  
   - Optionally builds request bodies from the spec’s `requestBody` (OpenAPI 3) or body parameters (Swagger 2).

4. **Rate Limiting & Concurrency**  
   - Supports threading with a cap on requests per second (`-rate`).  
   - Each endpoint is tested in a dedicated job.

5. **Response Analysis**  
   - Decodes responses, checks for PII, secrets, and large content.  
   - Logs relevant findings.

---

## PII Detection

1. **Presidio-Based Analysis**  
   - Searches for phone numbers, emails, addresses, names.  
   - Context-based scanning (e.g., CSV headers, key-value lines).

2. **Secrets & Debug Info**  
   - TruffleHog-like regex checks for API keys, tokens, environment variables.  
   - Merges any matches into the PII data structure for final reporting.

3. **Large Response Check**  
   - Flags responses with 100+ JSON elements or large XML structures as “interesting.”  
   - Also checks raw size threshold (e.g., >100k bytes).

---

## Output

By default, output is shown in a table.

- `-json` produces JSON objects, grouping results by endpoint.
- `-product` filters down to only “interesting” endpoints (PII, large responses and responses with secrets).

---

## Interpreting Results

For most use cases, interpreting results involves looking at the output (endpoints resulting in Status Code 200s), and paying particular attention to endpoints which are marked as 'PII or Secret Detected'. These endpoints are the ones that contain impactful exposures, but they should be manually checked to confirm. You may also wish to look at other 200s that do not contain PII, and determine whether it's intended for these endpoints to be public or not.

Simple GET endpoints can be triaged using command line tools like curl, but we would recommend using your usual API testing suite (tools such as Postman or Burp Suite) to replay requests and read responses to confirm whether an exposure is present.

---

## Stats & Reporting

- `-stats` appends or prints overall statistics, such as:
  - Hosts with valid specs
  - Hosts with PII
  - Total requests sent, average RPS
  - Percentage of endpoints responding with 2xx or 4xx
  - Shown in either a Rich table in default mode or embedded in JSON if `-json` or `-product` is used.

---

## License

This project is an Open Source Software released under the [BSD 3-Clause License](https://github.com/javaguru/autoswagger/blob/master/LICENSE).

---

## Acknowledgments

AutoSwagger2 **[Franck ANDRIANO.](http://jservlet.com)** (AutoSwagger was primarily maintained by **[Intruder](https://intruder.io/)** and primarily developed by Cale Anderson)

