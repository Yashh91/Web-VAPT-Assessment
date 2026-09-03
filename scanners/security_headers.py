import argparse
import json
from pathlib import Path

import requests
import urllib3


urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


DEFAULT_TIMEOUT = 10

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "Medium",
        "description": (
            "Helps control which resources can be "
            "loaded by the browser and reduces "
            "certain client-side attack risks."
        ),
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "description": (
            "Instructs browsers to use HTTPS for "
            "future connections."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": (
            "Helps prevent MIME-type sniffing."
        ),
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": (
            "Helps protect against clickjacking."
        ),
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": (
            "Controls how much referrer information "
            "is sent with requests."
        ),
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": (
            "Controls access to selected browser "
            "features."
        ),
    },
}


def check_security_headers(url):
    print(f"[+] Target: {url}\n")

    try:
        response = requests.get(
            url,
            timeout=DEFAULT_TIMEOUT,
            verify=False,
            allow_redirects=True
        )

    except requests.RequestException as error:
        print(
            f"[!] Request failed: {error}"
        )
        return None

    findings = []

    for header, details in SECURITY_HEADERS.items():
        value = response.headers.get(header)

        if value:
            status = "Present"

            print(
                f"[+] {header}: {value}"
            )

        else:
            status = "Missing"

            print(
                f"[-] {header}: Missing"
            )

            findings.append(
                {
                    "header": header,
                    "severity": details["severity"],
                    "status": "Missing",
                    "description": details[
                        "description"
                    ],
                }
            )

    return {
        "target": url,
        "status_code": response.status_code,
        "final_url": response.url,
        "headers": {
            header: response.headers.get(header)
            for header in SECURITY_HEADERS
        },
        "findings": findings,
    }


def save_results(results):
    Path("results").mkdir(
        exist_ok=True
    )

    output_file = Path(
        "results/security_headers_results.json"
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


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Security HTTP headers "
            "assessment scanner"
        )
    )

    parser.add_argument(
        "url",
        help="Authorized target URL"
    )

    args = parser.parse_args()

    print(
        "========== SECURITY HEADERS SCANNER ==========\n"
    )

    results = check_security_headers(
        args.url
    )

    if results is None:
        return

    print(
        "\n========== SUMMARY ==========\n"
    )

    present = sum(
        1
        for value in results["headers"].values()
        if value
    )

    missing = len(
        results["headers"]
    ) - present

    print(
        f"[+] Present headers: {present}"
    )

    print(
        f"[-] Missing headers: {missing}"
    )

    print(
        "\n========== FINDINGS ==========\n"
    )

    if results["findings"]:
        for finding in results["findings"]:
            print(
                f"[!] {finding['severity']}: "
                f"{finding['header']}"
            )
    else:
        print(
            "[+] All checked security headers "
            "are present."
        )

    save_results(results)


if __name__ == "__main__":
    main()
