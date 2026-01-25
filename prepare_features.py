import pandas as pd
from urllib.parse import urlparse

df = pd.read_csv("access_log.csv")
df["timestamp"] = pd.to_datetime(df["timestamp"])

# Time features
df["hour"] = df["timestamp"].dt.hour
df["day"] = df["timestamp"].dt.dayofweek

# Status features
df["is_error"] = (df["status"] >= 400).astype(int)
df["is_server_error"] = (df["status"] >= 500).astype(int)

# Traffic features
df["large_transfer"] = (df["bytes"] > 10000).astype(int)
df["url_length"] = df["url"].apply(len)

# Request rate per IP (behavioral feature)
ip_counts = df.groupby("ip")["url"].transform("count")
df["requests_per_ip"] = ip_counts

# Method encoding
df["is_post"] = (df["method"] == "POST").astype(int)
df["is_get"] = (df["method"] == "GET").astype(int)

# File type feature
df["is_exe"] = df["url"].str.contains(".exe", case=False, na=False).astype(int)
df["is_admin"] = df["url"].str.contains("admin", case=False, na=False).astype(int)

features = df[
    [
        "hour", "day", "bytes",
        "is_error", "is_server_error",
        "large_transfer", "url_length",
        "requests_per_ip",
        "is_post", "is_get",
        "is_exe", "is_admin"
    ]
]

features.to_csv("features.csv", index=False)

print("Features saved to features.csv")
print(features.head())
