# Log Analyzer

A Python command-line tool that reads server login logs and detects suspicious activity, such as brute-force password attacks.

## What it does

- Reads a log file line by line
- Finds failed login attempts and the IP addresses they came from
- Flags IPs with too many failed attempts in a short time
- Prints a report of suspicious activity

## Usage

```
python3 src/analyzer.py logs/sample.log
```

## Status

🚧 In progress: built as part of my Cyber Security elective.