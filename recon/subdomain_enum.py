import argparse
import socket
from pathlib import Path


def resolve_subdomain(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)

        return {
            "subdomain": subdomain,
            "ip": ip
        }

    except socket.gaierror:
        return None


def enumerate_subdomains(domain, wordlist):
    wordlist_path = Path(wordlist)

    if not wordlist_path.exists():
        print(f"[!] Wordlist not found: {wordlist}")
        return

    with open(wordlist_path, "r", encoding="utf-8") as file:
        prefixes = [
            line.strip()
            for line in file
            if line.strip() and not line.startswith("#")
        ]

    results = []

    print(f"[+] Enumerating subdomains for: {domain}\n")

    for prefix in prefixes:
        subdomain = f"{prefix}.{domain}"

        result = resolve_subdomain(subdomain)

        if result:
            results.append(result)

            print(
                f"[+] {result['subdomain']} "
                f"-> {result['ip']}"
            )

    Path("results").mkdir(exist_ok=True)

    with open(
        "results/subdomains.txt",
        "w",
        encoding="utf-8"
    ) as file:

        for result in results:
            file.write(
                f"{result['subdomain']} -> {result['ip']}\n"
            )

    print(
        f"\n[+] Found {len(results)} subdomains"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Basic subdomain enumeration"
    )

    parser.add_argument(
        "domain",
        help="Authorized domain"
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        default="wordlists/subdomains.txt",
        help="Subdomain wordlist"
    )

    args = parser.parse_args()

    enumerate_subdomains(
        args.domain,
        args.wordlist
    )


if __name__ == "__main__":
    main()
