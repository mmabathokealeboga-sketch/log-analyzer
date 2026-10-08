import re
import argparse
import sys
from datetime import datetime,timedelta

def read_log_file(path):
    with open(path) as file:
        return file.readlines()


def extract_ip(line):
    match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    if match:
        return match.group(1)
    return None


def extract_login_details(line):
    match = re.search(r"(Failed|Accepted) password for (\S+)", line)
    if match:
        return match.group(1), match.group(2)
    return None, None


def extract_time(line):
    match = re.search(r"^(\w+ +\d+ \d+:\d+:\d+)", line)
    if match:
        return datetime.strptime(f"2026 {match.group(1)}", "%Y %b %d %H:%M:%S")
    return None


def parse_line(line):
    time = extract_time(line)
    ip = extract_ip(line)
    status, username = extract_login_details(line)

    if time is None or ip is None or status is None:
        return None

    return {
        "time": time,
        "status": status,
        "username": username,
        "ip": ip,
    }


def is_brute_force(times, threshold=5, window_seconds=60):
    window = timedelta(seconds=window_seconds)
    for start in times:
        count = 0
        for time in times:
            if start <= time <= start + window:
                count += 1
        if count >= threshold:
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description="Detect brute-force login attempts in server logs.")
    parser.add_argument("log_file", help="path to the log file to analyze")
    parser.add_argument("--threshold", type=int, default=5, help="failed attempts needed to trigger an alert (default: 5)")
    parser.add_argument("--window", type=int, default=60, help="time window in seconds (default: 60)")
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if args.window < 1:
        parser.error("--window must be at least 1")

    log_path = args.log_file

    try:
        lines = read_log_file(log_path)
    except FileNotFoundError:
        print(f"Error: file '{log_path}' not found.")
        sys.exit(1)

    failed_attempts = []

    for line in lines:
        event = parse_line(line)
        if event is None or event["status"] != "Failed":
            continue
        failed_attempts.append(event)

    failures_by_ip = {}

    for attempt in failed_attempts:
        ip = attempt["ip"]
        if ip not in failures_by_ip:
            failures_by_ip[ip] = []
        failures_by_ip[ip].append(attempt["time"])

    attacks_found = False

    for ip, times in failures_by_ip.items():
        if is_brute_force(times, args.threshold, args.window):
            attacks_found = True
            seconds = int((times[-1] - times[0]).total_seconds())
            print(f"ALERT: Brute-force detected from {ip} ({len(times)} attempts in {seconds} seconds)")

    if not attacks_found:
        print("No attacks detected.")


if __name__ == "__main__":
    main()