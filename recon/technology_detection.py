import argparse
import requests
from bs4 import BeautifulSoup


def detect_technologies(url):
    print(f"[+] Target: {url}\n")

    try:
        response = requests.get(
            url,
            timeout=10,
            verify=False
        )
    except requests.RequestException as error:
        print(f"[!] Request failed: {error}")
        return

    technologies = set()

    headers = response.headers

    server = headers.get("Server")
    powered_by = headers.get("X-Powered-By")

    if server:
        technologies.add(f"Server: {server}")

    if powered_by:
        technologies.add(f"X-Powered-By: {powered_by}")

    html = response.text.lower()

    indicators = {
        "WordPress": ["wp-content", "wp-includes"],
        "React": ["react", "__react"],
        "Vue.js": ["vue.js", "vue@"],
        "Angular": ["ng-version", "angular"],
        "Next.js": ["_next/static", "__next"],
        "Django": ["csrfmiddlewaretoken"],
        "Laravel": ["laravel_session"],
        "ASP.NET": ["asp.net", "__viewstate"],
    }

    for technology, patterns in indicators.items():
        for pattern in patterns:
            if pattern.lower() in html:
                technologies.add(technology)
                break

    cookies = response.cookies

    for cookie in cookies:
        name = cookie.name.lower()

        if "phpsessid" in name:
            technologies.add("PHP")

        if "laravel_session" in name:
            technologies.add("Laravel")

        if "connect.sid" in name:
            technologies.add("Node.js / Express")

    soup = BeautifulSoup(response.text, "html.parser")

    generator = soup.find("meta", attrs={"name": "generator"})

    if generator:
        content = generator.get("content")

        if content:
            technologies.add(
                f"Generator: {content}"
            )

    print("========== TECHNOLOGIES ==========\n")

    if technologies:
        for technology in sorted(technologies):
            print(f"[+] {technology}")
    else:
        print("[!] No obvious technology indicators detected.")

    print("\n========== SECURITY HEADERS ==========\n")

    security_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    for header in security_headers:
        value = headers.get(header)

        if value:
            print(f"[+] {header}: {value}")
        else:
            print(f"[-] {header}: Not present")


def main():
    parser = argparse.ArgumentParser(
        description="Basic web technology detection"
    )

    parser.add_argument(
        "url",
        help="Authorized target URL"
    )

    args = parser.parse_args()

    detect_technologies(args.url)


if __name__ == "__main__":
    main()
