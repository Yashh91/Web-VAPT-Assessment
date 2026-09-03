import argparse
import json
from pathlib import Path

import requests
import urllib3


urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


DEFAULT_TIMEOUT = 10

SENSITIVE_PATHS = [
    "/.git/",
    "/.env",
    "/config",
    "/config.php",
    "/backup/",
    "/backups/",
    "/debug",
    "/server-status",
    "/phpinfo.php",
    "/test/",
    "/testing/",
]


def check_sensitive_paths(url):
    findings = []

    base_url = url.rstrip("/")

    for path in SENSITIVE_PATHS:
        target = f"{base_url}{path}"

        try:
            response = requests.get(
                target,
                timeout=DEFAULT_TIMEOUT,
                verify=False,
                allow_redirects=False
            )

            if response.status_code in [
                200,
                206,
                401,
                403
            ]:
                findings.append(
                    {
                        "path": path,
                        "url": target,
                        "status": response.status_code,
                        "content_length": len(
                            response.content
                        ),
                    }
                )

        except requests.RequestException:
            continue

    return findings


def check_http_methods(url):
    findings = []

    try:
        response = requests.options(
            url,
            timeout=DEFAULT_TIMEOUT,
            verify=False,
            allow_redirects=False
        )

        allow_header = response.headers.get(
            "Allow",
            ""
        )

        if allow_header:
            methods = [
                method.strip().upper()
                for method in allow_header.split(",")
            ]

            risky_methods = [
                method
                for method in methods
                if method in [
                    "PUT",
                    "DELETE",
                    "TRACE"
                ]
            ]

            if risky_methods:
                findings.append(
                    {
                        "type": "http_methods",
                        "methods": risky_methods,
                        "allow_header": allow_header,
                    }
                )

    except requests.RequestException:
        pass

    return findings


def check_server_information(response):
    findings = []

    server = response.headers.get(
        "Server"
    )

    powered_by = response.headers.get(
        "X-Powered-By"
    )

    if server:
        findings.append(
            {
                "type": "server_information",
                "header": "Server",
                "value": server,
            }
        )

    if powered_by:
        findings.append(
            {
                "type": "technology_disclosure",
                "header": "X-Powered-By",
                "value": powered_by,
            }
        )

    return findings


def check_directory_listing(response):
    body = response.text.lower()

    indicators = [
        "<title>directory listing for",
        "directory listing",
        "parent directory",
        "index of /",
    ]

    for indicator in indicators:
        if indicator in body:
            return {
                "type": "directory_listing",
                "indicator": indicator,
            }

    return None


def analyze_target(url):
    results = {
        "target": url,
        "findings": [],
    }

    try:
        response = requests.get(
            url,
            timeout=DEFAULT_TIMEOUT,
            verify=False,
            allow_redirects=False
        )

    except requests.RequestException as error:
        results["error"] = str(error)
        return results

    results["status_code"] = (
        response.status_code
    )

    results["server_information"] = (
        check_server_information(response)
    )

    directory_listing = (
        check_directory_listing(response)
    )

    if directory_listing:
        results["findings"].append(
            {
                "severity": "Medium",
                **directory_listing,
            }
        )

    for item in results[
        "server_information"
    ]:
        results["findings"].append(
            {
                "severity": "Low",
                **item,
            }
        )

    method_findings = check_http_methods(
        url
    )

    for item in method_findings:
        results["findings"].append(
            {
                "severity": "Medium",
                **item,
            }
        )

    sensitive_paths = check_sensitive_paths(
        url
    )

    for item in sensitive_paths:
        results["findings"].append(
            {
                "severity": "Review",
                "type": "sensitive_path",
                **item,
            }
        )

    return results


def save_results(results):
    Path("results").mkdir(
        exist_ok=True
    )

    output_file = Path(
        "results/misconfiguration_results.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            results,
            file,
            indent=4
        )

    print(
        f"\n[+] Results saved to "
        f"{output_file}"
    )


def print_results(results):
    print(
        "\n========== RESULTS ==========\n"
    )

    if results.get("error"):
        print(
            f"[!] Error: {results['error']}"
        )
        return

    findings = results.get(
        "findings",
        []
    )

    if not findings:
        print(
            "[+] No obvious "
            "misconfigurations detected."
        )
        return

    for finding in findings:
        severity = finding.get(
            "severity",
            "Info"
        )

        finding_type = finding.get(
            "type",
            "unknown"
        )

        print(
            f"[!] {severity}: "
            f"{finding_type}"
        )

        if "path" in finding:
            print(
                f"    Path: "
                f"{finding['path']}"
            )

        if "status" in finding:
            print(
                f"    Status: "
                f"{finding['status']}"
            )

        if "value" in finding:
            print(
                f"    Value: "
                f"{finding['value']}"
            )

        if "methods" in finding:
            print(
                f"    Methods: "
                f"{', '.join(finding['methods'])}"
            )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Basic web security "
            "misconfiguration scanner"
        )
    )

    parser.add_argument(
        "url",
        help="Authorized target URL"
    )

    args = parser.parse_args()

    print(
        "========== "
        "MISCONFIGURATION SCANNER "
        "==========\n"
    )

    print(
        f"[+] Target: {args.url}"
    )

    results = analyze_target(
        args.url
    )

    print_results(
        results
    )

    save_results(
        results
    )


if __name__ == "__main__":
    main()
