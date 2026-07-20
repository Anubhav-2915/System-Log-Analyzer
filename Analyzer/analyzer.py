import pandas as pd
import re

LOG_LINE_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+?)(\[(?P<pid>\d+)\])?:\s+(?P<message>.*)'
)

AUTH_FAIL_PATTERN = re.compile(
    r'error:\s+PAM:\s+Authentication failed for\s+(?P<user>\S+)\s+from\s+(?P<source>\S+)'
)

DEFAULT_MIN_ATTEMPTS = 10

def parse_lines(lines : list[str]) -> pd.DataFrame:
    records = []
    for raw_line in lines:
        match = LOG_LINE_PATTERN.search(raw_line)
        if match:
            records.append(match.groupdict())
    return pd.DataFrame(records)

def find_brute_attempts(df : pd.DataFrame, min_attempts : int = DEFAULT_MIN_ATTEMPTS) -> pd.DataFrame:
    if df.empty or "message" not in df.columns:
        return pd.DataFrame(columns=["source", "user", "attempt_count"])

    auth_records = []
    for msg in df['message']:
        match = AUTH_FAIL_PATTERN.search(msg)
        if match:
            auth_records.append(match.groupdict())

    auth_df = pd.DataFrame(auth_records)
    if auth_df.empty:
        return pd.DataFrame(columns=["source", "user", "attempt_count"])

    summary = auth_df.groupby(['source', 'user']).size().reset_index(name='attempt_count')
    summary = summary[summary['attempt_count'] > 10]
    summary = summary.sort_values('attempt_count', ascending=False).reset_index()
    return summary



def log_check(filepath : str,min_attempts : int = DEFAULT_MIN_ATTEMPTS) -> pd.DataFrame:
    with open(filepath, 'r') as f:
        lines = f.readlines()
    parsed = parse_lines(lines)
    return find_brute_attempts(parsed, min_attempts)


