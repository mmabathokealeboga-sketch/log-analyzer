import sys


def read_log_file(path):
    with open(path) as file:
        return file.readlines()


def main():
    if len(sys.argv) != 2:
        print("Usage: python src/analyzer.py <log_file>")
        sys.exit(1)

    log_path = sys.argv[1]
    lines = read_log_file(log_path)

    for line in lines:
        print(line.strip())


if __name__ == "__main__":
    main()