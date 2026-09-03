import argparse
import json
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3


urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


DEFAULT_TIMEOUT = 10

DANGEROUS_EXTENSIONS = {
    ".php",
    ".php5",
    ".phtml",
    ".jsp",
    ".jspx",
    ".asp",
    ".aspx",
    ".cgi",
    ".pl",
}


def analyze_upload_endpoint(url):
    parsed = urlparse(url)

    findings = []

    if parsed.scheme not in ["http", "https"]:
        findings.append(
            {
                "type": "invalid_scheme",
                "severity": "Informational",
                "message": (
                    "Target URL should use HTTP or HTTPS."
                ),
            }
        )

        return findings

    try:
        response = requests.options(
            url,
            timeout=DEFAULT_TIMEOUT,
            verify=False,
            allow_redirects=False
        )

        allowed_methods = response.headers.get(
            "Allow",
            ""
        )

        if allowed_methods:
            methods = [
                method.strip().upper()
                for method in allowed_methods.split(",")
            ]

            if "POST" in methods:
                findings.append(
                    {
                        "type": "upload_candidate",
                        "severity": "Review",
                        "message": (
                            "POST is allowed by the "
                            "endpoint. Manual verification "
                            "is required to determine whether "
                            "file uploads are supported."
                        ),
                    }
                )

            if "PUT" in methods:
                findings.append(
                    {
                        "type": "upload_candidate",
                        "severity": "Review",
                        "message": (
                            "PUT is allowed by the "
                            "endpoint. Manual verification "
                            "is required to determine whether "
                            "file uploads are supported."
                        ),
                    }
                )

        else:
            findings.append(
                {
                    "type": "method_discovery",
                    "severity": "Informational",
                    "message": (
                        "The server did not expose an "
                        "Allow header. File upload support "
                        "requires manual verification."
                    ),
                }
            )

    except requests.RequestException as error:
        findings.append(
            {
                "type": "request_error",
                "severity": "Error",
                "message": str(error),
            }
        )

    return findings


def check_upload_configuration():
    checks = []

    for extension in sorted(
        DANGEROUS_EXTENSIONS
    ):
        checks.append(
            {
                "extension": extension,
                "risk": (
                    "Server-side executable extension "
                    "requires strict validation and "
                    "should normally be blocked for "
                    "ordinary file uploads."
                ),
            }
        )

    return checks


def save_results(url, findings, extension_checks):
    Path("results").mkdir(
        exist_ok=True
    )

    results = {
        "target": url,
        "findings": findings,
        "dangerous_extensions": extension_checks,
        "note": (
            "This scanner performs non-destructive "
            "configuration analysis. Actual file "
            "upload validation requires manual testing "
            "with an authorized target."
        ),
    }

    output_file = Path(
        "results/file_upload_results.json"
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
        f"[+] Results saved to {output_file}"
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Basic file upload security "
            "assessment checker"
        )
    )

    parser.add_argument(
        "url",
        help="Authorized upload endpoint URL"
    )

    args = parser.parse_args()

    print(
        "========== FILE UPLOAD CHECKER ==========\n"
    )

    print(
        f"[+] Target: {args.url}"
    )

    findings = analyze_upload_endpoint(
        args.url
    )

    extension_checks = (
        check_upload_configuration()
    )

    print(
        "\n========== ANALYSIS ==========\n"
    )

    if findings:
        for finding in findings:
            print(
                f"[!] {finding['severity']}: "
                f"{finding['message']}"
            )
    else:
        print(
            "[+] No upload-related indicators detected."
        )

    print(
        "\n========== EXTENSION POLICY ==========\n"
    )

    for item in extension_checks:
        print(
            f"[+] Review blocked extension: "
            f"{item['extension']}"
        )

    save_results(
        args.url,
        findings,
        extension_checks
    )


if __name__ == "__main__":
    main()
