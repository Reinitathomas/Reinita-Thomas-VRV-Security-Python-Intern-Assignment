"""
Log Analysis Script
Language Used: Python

Author: REINITA THOMAS
"""
import re
import csv
from collections import defaultdict

# Constants
LOG_FILE = 'sample.log'
OUTPUT_CSV = 'log_analysis_results.csv'
FAILED_LOGIN_THRESHOLD = 10  # Default threshold for failed login attempts

def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def count_requests_per_ip(logs):
    ip_count = defaultdict(int)
    endpoint_count = defaultdict(int)
    failed_logins = defaultdict(int)

    # Regular expressions for parsing
    ip_pattern = r'^([\d\.]+)'  # Matches the IP address
    endpoint_pattern = r'\"[A-Z]+\s+([^ ]+)'  # Matches the endpoint
    failed_login_pattern = r'401'  # HTTP status code for failed login

    for log in logs:
        # Extract IP address
        ip_match = re.match(ip_pattern, log)
        if ip_match:
            ip = ip_match.group(1)
            ip_count[ip] += 1

            # Extract endpoint
            endpoint_match = re.search(endpoint_pattern, log)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_count[endpoint] += 1

            # Check for failed login attempts
            if re.search(failed_login_pattern, log):
                failed_logins[ip] += 1

    return ip_count, endpoint_count, failed_logins

# Function to find the most accessed endpoint
def find_most_accessed_endpoint(endpoint_count):
    if not endpoint_count:
        return None, 0
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1])
    return most_accessed

# Function to detect suspicious activity
def detect_suspicious_activity(failed_logins):
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_ips

# to fetch the output and generate the csv file
def output_results(ip_count, most_accessed_endpoint, suspicious_activity):
    # Print to terminal
    print("IP Address           Request Count")
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed_endpoint:
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    else:
        print("No endpoints accessed.")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    if suspicious_activity:
        for ip, count in sorted(suspicious_activity.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip:<20} {count}")
    else:
        print(f"{'-':<20} {'-'}")  # Print dashes if no suspicious activity

    # Save to CSV
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        if most_accessed_endpoint:
            writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        if suspicious_activity:
            for ip, count in sorted(suspicious_activity.items(), key=lambda x: x[1], reverse=True):
                writer.writerow([ip, count])
        else:
            writer.writerow(['-', '-'])  # Write dashes in CSV if no suspicious activity

def main():
    logs = parse_log_file(LOG_FILE)
    ip_count, endpoint_count, failed_logins = count_requests_per_ip(logs)
    most_accessed_endpoint = find_most_accessed_endpoint(endpoint_count)
    suspicious_activity = detect_suspicious_activity(failed_logins)
    output_results(ip_count, most_accessed_endpoint, suspicious_activity)

if __name__ == "__main__":
    main()
