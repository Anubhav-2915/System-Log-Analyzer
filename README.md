# Security-Log-analyzer

A Python/pandas tool that parses syslog files to detect potential brute-force 
login attempts by analyzing repeated authentication failures across users and 
source IPs/hosts.

## What it does

- Parses raw syslog text into a structured pandas DataFrame
- Extracts key fields using regex: timestamp, host, process, PID, and message
- Filters for authentication failure events (PAM auth failures, failed 
  password attempts, etc.)
- Extracts the targeted username and source IP/host from each failure
- Aggregates failed attempts by (source, user) pair to surface repeated or 
  suspicious login attempts
- Flags sources with unusually high attempt counts as potential brute-force 
  activity

## Why

Manually scanning syslog files for suspicious login activity doesn't scale. 
This tool automates the process of turning unstructured log text into 
something queryable — so you can quickly answer questions like "which IP 
tried the most usernames?" or "was any account targeted repeatedly?"

## How it works

1. **Read & clean** — loads the raw syslog file line by line into a DataFrame
2. **Filter** — keeps only lines containing failure-related keywords
3. **Parse** — regex extracts structured fields (timestamp, host, process, 
   user, source) from each matching line
4. **Aggregate** — groups by source and user to count repeated attempts
5. **Flag** — surfaces the highest-count (source, user) pairs as likely 
   brute-force candidates

## Usage

```python
from logcheck import logcheck

result = logcheck('syslog.log')
print(result)
```

Example output:

| source        | user    | attempt_count |
|---------------|---------|----------------|
| 10.145.12.55  | esopr   | 25             |
| 10.145.15.65  | pay     | 19             |
| 10.145.8.81   | esopr   | 28             |

## Requirements
pandas

Install with:
```bash
pip install pandas
```
