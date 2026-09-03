import argparse
import json
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests


DEFAULT_TIMEOUT = 10

SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "mysqli",
    "postgresql",
    "pg_query",
    "pg_exec",
    "sqlite error",
    "sqlite3",
    "ora-00933",
    "ora-01756",
    "sql server",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "unclosed quotation mark",
    "syntax error",
]


def build_test_url(url, parameter, payload):
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)

    updated_query = []

    for key, value in query:
        if key == parameter:
            updated_query.append((key, payload))
        else:
            updated_query.append((key, value))

    new_query = urlencode(updated_query)

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )


def find_parameters(url):
    parsed = urlparse(url)

    return [
        key
        for key, _ in parse_qsl(
            parsed.query,
            keep_blank_values=True
        )
    ]


def detect_sql_error(response_text):
    body = response_text.lower()

    for pattern in SQL_ERROR_PATTERNS:
        if pattern in body:
            return pattern

    return None


def test_parameter(url, parameter, timeout=DEFAULT_TIMEOUT):
    payloads = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
    ]

    findings = []

    try:
        baseline = requests.get(
            url,
            timeout=timeout,
            verify=False
        )

        baseline_length = len(baseline.content)

        for payload in payloads:
            test_url = build_test_url(
                url,
                parameter,
                payload
            )

            response = requests.get(
                test_url,
                timeout=timeout,
                verify=False
            )

            error_pattern = detect_sql_error(
                response.text
            )

            if error_pattern:
                findings.append(
                    {
                        "parameter": parameter,
                        "payload": payload,
                        "url": test_url,
                        "status": response.status_code,
                        "evidence": error_pattern,
                        "baseline_length": baseline_length,
                        "response_length": len(
                            response.content
                        ),
                    }
                )

    except requests.RequestException as error:
        print(
            f"[!] Request failed for "
            f"{parameter}: {error}"
        )

    return findings


def scan_url(url):
    parameters = find_parameters(url)

    if not parameters:
        print("[!] No URL parameters found.")
        return []

    print(
        f"[+] Found {len(parameters)} "
        f"parameter(s): {', '.join(parameters)}"
    )

    findings = []

    for parameter in parameters:
        print(
            f"[+] Testing parameter: {parameter}"
        )

        results = test_parameter(
            url,
            parameter
        )

        findings.extend(results)

    return findings


def save_results(findings):
    Path("results").mkdir(exist_ok=True)

    output_file = Path(
        "results/sql_injection_results.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            findings,
            file,
            indent=4
        )

    print(
        f"[+] Results saved to {output_file}"
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Basic SQL injection error-based "
            "scanner"
        )
    )

    parser.add_argument(
        "url",
        help="Authorized URL containing query parameters"
    )

    args = parser.parse_args()

    print(
        "========== SQL INJECTION SCANNER ==========\n"
    )

    findings = scan_url(args.url)

    print(
        "\n========== RESULTS ==========\n"
    )

    if findings:
        for finding in findings:
            print(
                f"[!] Possible SQL injection indicator: "
                f"{finding['parameter']}"
            )
            print(
                f"    Evidence: "
                f"{finding['evidence']}"
            )
            print(
                f"    Payload: "
                f"{finding['payload']}"
            )
    else:
        print(
            "[+] No SQL error indicators detected."
        )

    save_results(findings)


if __name__ == "__main__":
    main()
