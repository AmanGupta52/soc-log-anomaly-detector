import re
import pandas as pd

log_file = "access.log"
output_csv = "access_log.csv"

pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)'
)

rows = []

with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        match = pattern.search(line)
        if match:
            rows.append(match.groupdict())

df = pd.DataFrame(rows)

df["status"] = df["status"].astype(int)
df["bytes"] = df["bytes"].replace("-", "0").astype(int)

df["timestamp"] = pd.to_datetime(
    df["time"], format="%d/%b/%Y:%H:%M:%S %z", errors="coerce"
)

df.drop(columns=["time"], inplace=True)

df.to_csv(output_csv, index=False)

print("CSV created:", output_csv)
print(df.head())
print("Total rows:", len(df))
