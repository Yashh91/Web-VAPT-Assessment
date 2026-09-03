import argparse
import json
import subprocess
import shutil
from pathlib import Path


def run_nmap(target, ports="1-1000"):
    if not shutil.which("nmap"):
        raise RuntimeError("Nmap is not installed or not available in PATH.")

    command = [
        "nmap",
        "-sV",
        "-Pn",
        "-p",
        ports,
        target
    ]

    print(f"[+] Running Nmap against: {target}")
    print(f"[+] Ports: {ports}")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    output = result.stdout

    if result.returncode != 0:
        print("[!] Nmap error:")
        print(result.stderr)
        return

    print("\n========== NMAP RESULTS ==========\n")
    print(output)

    Path("results").mkdir(exist_ok=True)

    with open("results/nmap_scan.txt", "w", encoding="utf-8") as file:
        file.write(output)

    print("\n[+] Results saved to results/nmap_scan.txt")


def main():
    parser = argparse.ArgumentParser(
        description="Nmap-based network reconnaissance"
    )

    parser.add_argument(
        "target",
        help="Authorized target hostname or IP address"
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="1-1000",
        help="Port range, e.g. 1-1000 or 80,443"
    )

    args = parser.parse_args()

    try:
        run_nmap(args.target, args.ports)
    except Exception as error:
        print(f"[!] Error: {error}")


if __name__ == "__main__":
    main()
