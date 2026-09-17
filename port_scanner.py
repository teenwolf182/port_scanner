import socket
import csv
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


def scan_port(target, port, timeout):
    """
    Scan a single TCP port.
    """

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((target, port))

            if result == 0:

                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"

                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": service
                }

    except socket.timeout:
        pass

    except socket.error:
        pass

    return None


def parse_ports(port_argument):
    """
    Convert port input into a list.

    Examples:
        80
        80,443,8080
        1-1024
        22,80,443,8000-8010
    """

    ports = set()

    for item in port_argument.split(","):

        item = item.strip()

        if "-" in item:

            start, end = item.split("-", 1)

            start = int(start)
            end = int(end)

            if start < 1 or end > 65535 or start > end:
                raise ValueError("Invalid port range")

            ports.update(range(start, end + 1))

        else:

            port = int(item)

            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {port}")

            ports.add(port)

    return sorted(ports)


def scan_target(target, ports, timeout, workers):
    """
    Scan multiple ports concurrently.
    """

    results = []

    print("\n" + "=" * 60)
    print("TCP PORT SCANNER")
    print("=" * 60)

    print(f"Target : {target}")
    print(f"Ports  : {len(ports)}")
    print(f"Threads: {workers}")
    print("=" * 60)

    with ThreadPoolExecutor(max_workers=workers) as executor:

        futures = {
            executor.submit(
                scan_port,
                target,
                port,
                timeout
            ): port

            for port in ports
        }

        for future in as_completed(futures):

            result = future.result()

            if result:

                results.append(result)

                print(
                    f"[OPEN] "
                    f"{result['port']:5}/"
                    f"{result['protocol']:3} "
                    f"{result['service']}"
                )

    return sorted(results, key=lambda x: x["port"])


def save_csv(results, filename):
    """
    Save scan results to CSV.
    """

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "port",
                "protocol",
                "state",
                "service"
            ]
        )

        writer.writeheader()
        writer.writerows(results)


def main():

    parser = argparse.ArgumentParser(
        description="Lightweight TCP Port Scanner"
    )

    parser.add_argument(
        "target",
        help="IP address or hostname"
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="Port(s), e.g. 80, 22,80,443 or 1-1024"
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds"
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=50,
        help="Number of concurrent workers"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Save results to CSV"
    )

    args = parser.parse_args()

    try:

        target_ip = socket.gethostbyname(args.target)

        ports = parse_ports(args.ports)

        start_time = datetime.now()

        results = scan_target(
            target_ip,
            ports,
            args.timeout,
            args.workers
        )

        elapsed = (
            datetime.now() - start_time
        ).total_seconds()

        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)

        print(f"Target      : {args.target}")
        print(f"IP Address  : {target_ip}")
        print(f"Open ports  : {len(results)}")
        print(f"Scan time   : {elapsed:.2f} seconds")

        if results:

            print("\nOpen ports:")

            for result in results:

                print(
                    f"{result['port']:5}/"
                    f"{result['protocol']:3} "
                    f"{result['service']}"
                )

        else:
            print("\nNo open TCP ports detected.")

        if args.output:

            save_csv(
                results,
                args.output
            )

            print(
                f"\nResults saved to: "
                f"{args.output}"
            )

    except socket.gaierror:

        print(
            f"Error: Unable to resolve "
            f"target '{args.target}'"
        )

    except ValueError as error:

        print(f"Error: {error}")

    except KeyboardInterrupt:

        print("\nScan interrupted by user.")


if __name__ == "__main__":
    main()
