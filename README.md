# Log Analyzer

A Python command-line tool that reads server login logs and detects suspicious activity, like a small intrusion detection system (IDS).

## What it detects

| Rule | What it means | Why it's suspicious |
|---|---|---|
| **Brute-force** | One IP fails to log in 5+ times within 60 seconds | Too fast for a human, so it's likely a program guessing passwords |
| **Username guessing** | One IP fails with 3+ different usernames | A real person only tries their own username |
| **Odd-hour login** | A successful login between 00:00 and 05:00 | Could be someone using a stolen password while no one is watching |

## How it works

1. Reads the log file line by line
2. Uses regex to pull out the time, result (Failed/Accepted), username and IP from each line
3. Skips any line that isn't a login attempt
4. Groups failed attempts by IP
5. Checks each IP against the detection rules
6. Prints an alert for anything suspicious, followed by a summary

## Project structure

```
log-analyzer/
├── logs/            sample log files used for testing
├── src/
│   └── analyzer.py  the analyzer
├── tests/
│   └── test_analyzer.py
├── pytest.ini
└── README.md
```

## Requirements

- Python 3.10 or newer
- pytest (only needed to run the tests)

No other libraries are needed. Everything else uses Python's standard library.

## Usage

```
python src/analyzer.py <log_file> [--threshold N] [--window SECONDS]
```

| Option | What it does | Default |
|---|---|---|
| `--threshold` | Failed attempts needed to trigger a brute-force alert | 5 |
| `--window` | Time window in seconds for the brute-force rule | 60 |

Use `python3` on Linux/Mac, or `py` on Windows if `python` doesn't work.

### Examples

```
python src/analyzer.py logs/sample.log
python src/analyzer.py logs/sample.log --threshold 3 --window 30
python src/analyzer.py --help
```

## Example output

```
ALERT: Brute-force detected from 203.0.113.45 (8 attempts in 21 seconds)
ALERT: 203.0.113.45 tried 4 different usernames: admin, root, test, user

--- Summary ---
Lines read:      15
Login events:    15
Failed attempts: 10
Alerts raised:   2
```

## Running the tests

```
pip install pytest
python -m pytest
```

There are 28 tests covering every function, including edge cases such as a login at exactly 05:00 and a failed attempt exactly 60 vs 61 seconds after the first.

## Sample log files

| File | What it contains |
|---|---|
| `logs/sample.log` | Normal logins plus a simulated brute-force attack |
| `logs/messy.log` | Logins mixed with unrelated and broken lines |
| `logs/night.log` | Logins around midnight to 5am, including edge cases |

All IP addresses in the sample logs are from reserved documentation ranges, not real systems.

## Limitations

- The log format doesn't include a year, so the analyzer assumes 2026
- Only supports SSH-style login lines (`Failed password` / `Accepted password`)
- Reads a saved log file rather than monitoring logs live

## What I learned

- Reading and parsing text files with regular expressions
- Working with dates and time windows using `datetime` and `timedelta`
- Building a command-line tool with `argparse`
- Writing tests with pytest, including edge cases
- Refactoring code into small, testable functions
- Using Git and GitHub with daily commits across two computers
- How analysts spot brute-force attacks and other suspicious logins in server logs

## Status

✅ Complete: built as part of my Cyber Security elective.

## License

MIT

WTC-P69C7TNF