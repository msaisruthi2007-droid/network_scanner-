import socket
import requests  # Kept because it is imported in the original tutorial.
import nmap
from datetime import datetime


def network_scan(target, start_port, end_port):
    print(f"\nStarting network scan for {target}")
    start_time = datetime.now()

    # 1. Port scanning
    open_ports = port_scan(target, start_port, end_port)

    if open_ports:
        print(f"\nOpen ports found: {open_ports}")
    else:
        print("\nNo open ports found.")

    # 2. Banner grabbing
    for port in open_ports:
        banner = banner_grab(target, port)

        if banner:
            print(f"\nBanner for {target} on port {port}: {banner}")
        else:
            print(f"\nNo banner found for {target} on port {port}.")

    # 3. Vulnerability and operating-system discovery
    nmap_result = vulnerability_scan(target)

    if nmap_result and target in nmap_result.all_hosts():
        # python-nmap returns a PortScanner object; access host data by key.
        host_info = nmap_result[target]

        if host_info.get("hostnames"):
            print("\nHost names:")
            print(host_info.get("hostnames"))

        if host_info.get("osmatch"):
            print("\nOperating system:")
            for os_match in host_info.get("osmatch", []):
                print(
                    f"{os_match.get('name', 'Unknown')} "
                    f"(accuracy: {os_match.get('accuracy', 'Unknown')}%)"
                )

        # Nmap vulnerability-script results are stored under scanned ports.
        vulnerabilities_found = []
        for protocol in host_info.all_protocols():
            for port_data in host_info[protocol].values():
                for script_name, script_output in port_data.get("script", {}).items():
                    vulnerabilities_found.append(
                        f"{script_name}: {script_output}"
                    )

        if vulnerabilities_found:
            print("\nVulnerability/script results:")
            for result in vulnerabilities_found:
                print(f"- {result}")
        else:
            print("\nNo vulnerabilities detected or no vulnerability-script results returned.")
    elif nmap_result:
        print(f"\nNmap did not return host information for {target}.")
    else:
        print("\nNo vulnerability information detected or unable to detect.")

    end_time = datetime.now()
    print(f"\nScan completed in {(end_time - start_time).total_seconds():.2f} seconds.")


def port_scan(target, start_port, end_port):
    print(
        f"\nScanning target {target} for open ports "
        f"from {start_port} to {end_port}"
    )

    open_ports = []

    # Include the ending port in the range.
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
        except OSError:
            pass
        finally:
            sock.close()

    return open_ports


def banner_grab(target, port):
    print(f"\nGrabbing banner for {target}:{port}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))

        banner = sock.recv(4024).decode("utf-8", errors="ignore")
        sock.close()

        return banner.strip() or None

    except (OSError, socket.timeout):
        return None


def vulnerability_scan(target):
    print(f"\nScanning target {target} for vulnerabilities.")

    try:
        nm = nmap.PortScanner()
        nm.scan(
            hosts=target,
            arguments="-O -sV --script=vuln"
        )
        return nm

    except Exception as error:
        print(f"Error during vulnerability scan: {error}")
        return None


if __name__ == "__main__":
    target_ip = input("Enter target IP address or hostname: ").strip()

    try:
        start_port = int(input("Enter the starting port for scanning: "))
        end_port = int(input("Enter the ending port for scanning: "))

        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            raise ValueError("Ports must be between 1 and 65535.")
        if start_port > end_port:
            raise ValueError("Starting port must not be greater than ending port.")

        network_scan(target_ip, start_port, end_port)

    except ValueError as error:
        print(f"Invalid input: {error}")
