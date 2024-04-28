import sys
import socket
import subprocess
import argparse
import logging
import requests
import nmap

# Constants
DEFAULT_PACKETS = 5
DEFAULT_TIMEOUT = 10
DEFAULT_LOG_FILE = "network_scanner.log"

# Configure the logger
logging.basicConfig(filename=DEFAULT_LOG_FILE, level=logging.INFO,
                    format="%(asctime)s [%(levelname)s]: %(message)s")

def get_target_ip(site):
    try:
        target_ip = socket.gethostbyname(site)
        return target_ip
    except socket.gaierror as e:
        raise ValueError(f"Hostname Could Not Be Resolved: {e}")

def ping_host(target, packets=DEFAULT_PACKETS, timeout=DEFAULT_TIMEOUT):
    try:
        result = subprocess.run(["ping", "-c", str(packets), "-W", str(timeout), target],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Ping timed out. The host may not be responding."
    except subprocess.CalledProcessError as e:
        return f"An error occurred: {e}"

def scan_with_nmap(target, timeout=DEFAULT_TIMEOUT):
    try:
        result = subprocess.run(["nmap", target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Nmap scan timed out."
    except subprocess.CalledProcessError as e:
        return f"An error occurred while scanning with nmap: {e}"

def check_vulnerabilities(target_ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(target_ip, arguments='-T4 -F')
        vulnerabilities = nm[target_ip]['tcp']
        return vulnerabilities
    except nmap.nmap.PortScannerError as e:
        return f"An error occurred while checking vulnerabilities: {e}"

def get_ip_location(target_ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{target_ip}")
        response.raise_for_status()
        data = response.json()
        return f"Location: {data['city']}, {data['regionName']}, {data['country']}"
    except requests.exceptions.HTTPError as e:
        return f"HTTP Error: {e}"
    except requests.exceptions.RequestException as e:
        return f"Request Exception: {e}"
    except Exception as e:
        return f"An error occurred while getting IP location: {e}"

def get_os_info(target_ip):
    # This function is under development
    return []

def analyze_http_methods(target):
    def send_get_request(target):
        try:
            response = requests.get(target)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"HTTP GET Request Error: {e}")
            return None

    def send_post_request(target):
        try:
            post_data = input("Enter the data to send (e.g., key=value): ").strip()
            post_data = dict(item.split("=") for item in post_data.split("&"))
            response = requests.post(target, data=post_data)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"HTTP POST Request Error: {e}")
            return None

    try:
        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        response_get = send_get_request(target)
        if response_get:
            print("HTTP GET Response:")
            print(f"Status Code: {response_get.status_code}")
            print(f"Response Headers: {response_get.headers}")

            print("-" * 50)

            send_post_request_option = input("Do you want to send a POST request? (Y/n): ").strip().lower()
            if send_post_request_option == "y":
                response_post = send_post_request(target)
                if response_post:
                    print("HTTP POST Response:")
                    print(f"Status Code: {response_post.status_code}")
                    print(f"Response Headers: {response_post.headers}")
                else:
                    print("HTTP POST request failed.")
            else:
                print("No POST request sent.")
        else:
            print("HTTP GET request failed.")
    except Exception as e:
        logging.error(f"An error occurred while analyzing HTTP methods: {e}")

def print_separator():
    print('-' * 50)

def main():
    parser = argparse.ArgumentParser(description="Network Scanner", add_help=False)
    parser.add_argument("target", help="Target host or IP address")
    args = parser.parse_args()

    target_ip = get_target_ip(args.target)
    
    advanced_info_request = input(f"Request advanced information about {target_ip}? (Y/n): ")
    if advanced_info_request.lower() == "y":
        ping_result = ping_host(args.target)
        print_separator()
        print(ping_result)

        nmap_result = scan_with_nmap(args.target)
        print_separator()
        print(nmap_result)

        vulnerabilities = check_vulnerabilities(target_ip)
        if isinstance(vulnerabilities, dict):
            print_separator()
            print("Vulnerabilities found:")
            for protocol, ports in vulnerabilities.items():
                print(f"{protocol} Ports:")
                for port, info in ports.items():
                    print(f"Port {port}: {info}")
        else:
            print_separator()
            print("No vulnerabilities found or an error occurred.")

        location_result = get_ip_location(target_ip)
        print_separator()
        print(location_result)

        os_info = get_os_info(target_ip)
        if os_info:
            print_separator()
            print("Operating System Information:")
            for info in os_info:
                print(info)

        print_separator()
        analyze_http_methods(args.target)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
