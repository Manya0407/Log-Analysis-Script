import re
import csv
from collections import Counter, defaultdict

""" Giving a default value of 4 , can be changed according to dataset"""
FAILED_LOGIN_THRESHOLD = 4
LOG_FILE = "sample.log"
CSV_OUTPUT_FILE = "log_analysis_results.csv"

def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def count_requests_per_ip(logs):
    ip_pattern = r'^\d+\.\d+\.\d+\.\d+'
    ip_counter = Counter(re.match(ip_pattern, log).group() for log in logs if re.match(ip_pattern, log))
    return ip_counter.most_common()

def identify_most_frequent_endpoint(logs):
    endpoint_pattern = r'\"(?:GET|POST|PUT|DELETE) (/\S*)'
    endpoint_counter = Counter(re.search(endpoint_pattern, log).group(1) for log in logs if re.search(endpoint_pattern, log))
    most_frequent = endpoint_counter.most_common(1)
    return most_frequent[0] if most_frequent else ("None", 0)

def detect_suspicious_activity(logs, threshold=FAILED_LOGIN_THRESHOLD):
    failed_login_pattern = r'^\d+\.\d+\.\d+\.\d+.*"(POST \S+ HTTP/1.1)".*401.*Invalid credentials'
    failed_logins = defaultdict(int)
    for log in logs:
        match = re.match(failed_login_pattern, log)
        if match:
            ip = log.split()[0]
            failed_logins[ip] += 1
    return [(ip, count) for ip, count in failed_logins.items() if count > threshold]

def display_suspicious_activity(suspicious_activity):
    print("Suspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts'}")
    for ip, count in suspicious_activity:
        print(f"{ip:<20} {count}")
    print()

def save_results_to_csv(requests_per_ip, most_accessed_endpoint, suspicious_activity):
    with open(CSV_OUTPUT_FILE, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(requests_per_ip)
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activity)

def main():
    logs = parse_log_file(LOG_FILE)
    requests_per_ip = count_requests_per_ip(logs)
    print("Requests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count'}")
    for ip, count in requests_per_ip:
        print(f"{ip:<20} {count}")
    print()
    most_accessed_endpoint = identify_most_frequent_endpoint(logs)
    print(f"Most Frequently Accessed Endpoint: {most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)\n")
    suspicious_activity = detect_suspicious_activity(logs)
    display_suspicious_activity(suspicious_activity)
    save_results_to_csv(requests_per_ip, most_accessed_endpoint, suspicious_activity)
    print(f"Results saved to {CSV_OUTPUT_FILE}")

if __name__ == "__main__":
    main()
