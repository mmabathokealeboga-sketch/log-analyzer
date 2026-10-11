# Log Analyzer

A Python command-line tool that reads server login logs and detects suspicious activity.

## What it detects

| Rule | What it means | Why it's suspicious |
|---|---|---|
| **Brute-force** | One IP fails to log in 5+ times within 60 seconds | Too fast for a human, so it's likely a program guessing passwords |
| **Username guessing** | One IP fails with 3+ different usernames | A real person only tries their own username |
| **Odd-hour login** | A successful login between 00:00 and 05:00 | Could be someone using a stolen password while no one is watching |

## Usage

```
python src/analyzer.py <log_file> [--threshold N] [--window SECONDS]
```

| Option | What it does | Default |
|---|---|---|
| `--threshold` | Failed attempts needed to trigger a brute-force alert | 5 |
| `--window` | Time window in seconds for the brute-force rule | 60 |

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

## Sample log files

| File | What it contains |
|---|---|
| `logs/sample.log` | Normal logins plus a simulated brute-force attack |
| `logs/messy.log` | Logins mixed with unrelated and broken lines |
| `logs/night.log` | Logins around midnight to 5am, including edge cases |

All IP addresses in the sample logs are from reserved documentation ranges, not real systems.

## Status

🚧 In progress: built as part of my Cyber Security elective.