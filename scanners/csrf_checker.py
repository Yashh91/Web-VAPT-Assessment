import argparse
import json
from pathlib import Path
from urllib.parse import urlparse

import requests


DEFAULT_TIMEOUT = 10

CSRF_TOKEN_NAMES = [
    "csrf",
    "csrf_token",
    "csrftoken",
    "_csrf",
    "_csrf_token",
    "xsrf",
    "xsrf_token",
    "x-csrf-token",
]


def get_page(url, timeout=DEFAULT_TIMEOUT):
    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=False
        )

        return response

    except requests.RequestException as error:
        print(f"[!] Request failed: {error}")
        return None


def find_csrf_indicators(response):
    indicators = []

    cookies = response.cookies

    for cookie in cookies:
        cookie_name = cookie.name.lower()

        if any(
            token in cookie_name
            for token in CSRF_TOKEN_NAMES
        ):
            indicators.append(
                f"CSRF-related cookie: {cookie.name}"
            )

    html = response.text.lower()

    for token_name in CSRF_TOKEN_NAMES:
        if token_name in html:
            indicators.append(
                f"Possible CSRF token reference: "
                f"{token_name}"
            )

    return indicators


def check_same_site_cookies(response):
    results = []

    for cookie in response.cookies:
        rest = getattr(cookie, "_rest", {})

        same_site = None

        for key, value in rest.items():
            if key.lower() == "samesite":
                same_site = value

        if same_site:
            results.append(
                {
                    "cookie": cookie.name,
                    "samesite": same_site,
                    "status": "present",
                }
            )
        else:
            results.append(
                {
                    "cookie": cookie.name,
                    "samesite": None,
                    "status": "not specified",
                }
            )

    return results


def analyze_response(response):
    findings = []

    indicators = find_csrf_indicators(
        response
    )

    cookie_analysis = check_same_site_cookies(
        response
    )

    if not indicators:
        findings.append(
            {
                "type": "csrf_protection",
                "severity": "review",
                "message": (
                    "No obvious CSRF token indicators "
                    "were detected. Manual verification "
                    "is required for state-changing "
                    "requests."
                ),
            }
        )

    for cookie in cookie_analysis:
        if cookie["status"] == "not specified":
            findings.append(
                {
                    "type": "cookie_samesite",
                    "severity": "review",
                    "cookie": cookie["cookie"],
                    "message": (
                        "SameSite attribute was not "
                        "explicitly detected."
                    ),
                }
            )

    return {
        "csrf_indicators": indicators,
        "cookie_analysis": cookie_analysis,
        "findings": findings,
    }


def save_results(url, analysis):
    Path("results").mkdir(
        exist_ok=True
    )

    output = {
        "target": url,
        "analysis": analysis,
    }

    output_file = Path(
        "results/csrf_results.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            output,
            file,
            indent=4
        )

    print(
        f"[+] Results saved to {output_file}"
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Basic CSRF protection "
            "assessment checker"
        )
    )

    parser.add_argument(
        "url",
        help="Authorized target URL"
    )

    args = parser.parse_args()

    print(
        "========== CSRF CHECKER ==========\n"
    )

    response = get_page(args.url)

    if response is None:
        return

    print(
        f"[+] Target: {args.url}"
    )

    print(
        f"[+] HTTP Status: "
        f"{response.status_code}"
    )

    analysis = analyze_response(
        response
    )

    print(
        "\n========== CSRF INDICATORS ==========\n"
    )

    if analysis["csrf_indicators"]:
        for indicator in analysis[
            "csrf_indicators"
        ]:
            print(f"[+] {indicator}")
    else:
        print(
            "[-] No obvious CSRF indicators detected."
        )

    print(
        "\n========== COOKIE ANALYSIS ==========\n"
    )

    if analysis["cookie_analysis"]:
        for cookie in analysis[
            "cookie_analysis"
        ]:
            print(
                f"[+] {cookie['cookie']}: "
                f"SameSite="
                f"{cookie['samesite'] or 'Not specified'}"
            )
    else:
        print(
            "[+] No cookies detected."
        )

    print(
        "\n========== FINDINGS ==========\n"
    )

    if analysis["findings"]:
        for finding in analysis["findings"]:
            print(
                f"[!] {finding['severity'].upper()}: "
                f"{finding['message']}"
            )
    else:
        print(
            "[+] No obvious CSRF issues detected."
        )

    save_results(
        args.url,
        analysis
    )


if __name__ == "__main__":
    main()
