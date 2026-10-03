import re
import sys


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

    for line in lines:
        ip = extract_ip(line)
        status, username = extract_login_details(line)
        print(status, username, ip)


if __name__ == "__main__":
    main()