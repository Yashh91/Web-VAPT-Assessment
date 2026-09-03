import argparse
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


DEFAULT_WORDLIST = "wordlists/common.txt"


def check_endpoint(base_url, path, timeout=5):
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False
        )

        if response.status_code in [200, 201, 204, 301, 302, 307, 308, 401, 403]:
            return {
                "url": url,
                "status": response.status_code,
                "length": len(response.content)
            }

    except requests.RequestException:
        pass

    return None


def discover_endpoints(base_url, wordlist, threads=10):
    wordlist_path = Path(wordlist)

    if not wordlist_path.exists():
        print(f"[!] Wordlist not found: {wordlist}")
        return []

    with open(wordlist_path, "r", encoding="utf-8") as file:
        paths = [
            line.strip()
            for line in file
            if line.strip() and not line.startswith("#")
        ]

    results = []

    print(f"[+] Target: {base_url}")
    print(f"[+] Loaded {len(paths)} paths")
    print(f"[+] Threads: {threads}\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(check_endpoint, base_url, path)
            for path in paths
        ]

        for future in as_completed(futures):
            result = future.result()

            if result:
                results.append(result)

                print(
                    f"[+] {result['status']} "
                    f"{result['url']} "
                    f"({result['length']} bytes)"
                )

    results.sort(key=lambda item: item["url"])

    Path("results").mkdir(exist_ok=True)

    with open(
        "results/discovered_endpoints.txt",
        "w",
        encoding="utf-8"
    ) as file:

        for result in results:
            file.write(
                f"{result['status']} "
                f"{result['url']} "
                f"{result['length']} bytes\n"
            )

    print(
        f"\n[+] Discovered {len(results)} accessible endpoints"
    )

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Web endpoint discovery tool"
    )

    parser.add_argument(
        "url",
        help="Authorized target URL"
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        default=DEFAULT_WORDLIST,
        help="Path to endpoint wordlist"
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent requests"
    )

    args = parser.parse_args()

    discover_endpoints(
        args.url,
        args.wordlist,
        args.threads
    )


if __name__ == "__main__":
    main()
