import re
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
    if len(sys.argv) != 2:
        print("Usage: python src/analyzer.py <log_file>")
        sys.exit(1)

    log_path = sys.argv[1]

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

    for ip, times in failures_by_ip.items():
        attack = is_brute_force(times)
        print(f"{ip}: {len(times)} failed attempts, brute-force: {attack}")


if __name__ == "__main__":
    main()