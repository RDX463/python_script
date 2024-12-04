import re
import csv
from collections import defaultdict

def analyze_log_file(file_path):

    analysis = {
        "requests_per_ip": defaultdict(int),
        "endpoint_hits": defaultdict(int),
        "fail_logs": defaultdict(int),
    }

    patterns = {
        "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "endpoint": r'"GET (\S+)',
        "failed_login": r"Failed login from (\b(?:\d{1,3}\.){3}\d{1,3}\b)"
    }

    try:
        with open(file_path, "r") as log_file:
            for entry in log_file:
                ip_match = re.search(patterns["ip"], entry)# Counting requests per IP
                if ip_match:
                    ip_address = ip_match.group()
                    analysis["requests_per_ip"][ip_address] += 1

                endpoint_match = re.search(patterns["endpoint"], entry)# Counting endpoint accesses
                if endpoint_match:
                    endpoint = endpoint_match.group(1)
                    analysis["endpoint_hits"][endpoint] += 1

                failed_login_match = re.search(patterns["failed_login"], entry)# checking failed login attempts
                if failed_login_match:
                    failed_ip = failed_login_match.group(1)
                    analysis["fail_logs"][failed_ip] += 1

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"Unexpected error occurred: {e}")

    return analysis


def save_results_to_csv(analysis_data):
    output_file = "log_analysis_results.csv"

    try:
        with open(output_file, "w", newline="") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Requests per IP"])# Saving requests per IP
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in analysis_data["requests_per_ip"].items():
                writer.writerow([ip, count])
            writer.writerow([])

            writer.writerow(["Most Accessed Endpoints"])  # Saving most accessed endpoints
            writer.writerow(["Endpoint", "Access Count"])
            for endpoint, count in analysis_data["endpoint_hits"].items():
                writer.writerow([endpoint, count])
            writer.writerow([])

            writer.writerow(["Suspicious Activity"]) # Saving suspicious activity
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in analysis_data["fail_logs"].items():
                writer.writerow([ip, count])

        print(f"Results successfully saved to '{output_file}'")

    except Exception as e:
        print(f"Error saving results to CSV: {e}")


def display_summary(analysis_data):
    print("\n--- Log Analysis Summary ---\n")
    print("Requests Per IP:")
    for ip, count in analysis_data["requests_per_ip"].items():
        print(f"  {ip}: {count} requests")

    print("\nMost Accessed Endpoints:")
    for endpoint, count in sorted(analysis_data["endpoint_hits"].items(), key=lambda x: x[1], reverse=True):
        print(f"  {endpoint}: {count} hits")

    print("\nFailed Login Attempts:")
    for ip, count in analysis_data["fail_logs"].items():
        print(f"  {ip}: {count} failed attempts")


if __name__ == "__main__":
    log_file_path = "sample.txt"  #file Path

    print(f"Analyzing log file: {log_file_path}")
    log_analysis = analyze_log_file(log_file_path)

    display_summary(log_analysis)
    save_results_to_csv(log_analysis)
