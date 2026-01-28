import pandas as pd
import numpy as np

# ============================
# Load real Apache log dataset
# ============================

file_path = "data/access_log.csv"

df = pd.read_csv(file_path)

print("Raw data sample:")
print(df.head())
print("\nColumns:", df.columns.tolist())

# ============================
# Basic Cleaning
# ============================
# Fill missing values
df.fillna(0, inplace=True)

# Convert timestamp
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

# Drop rows with invalid timestamps
df.dropna(subset=['timestamp'], inplace=True)

# ============================
# Feature Engineering (SOC style)
# ============================

df['hour'] = df['timestamp'].dt.hour
df['day_of_week'] = df['timestamp'].dt.dayofweek

# Convert bytes to numeric
df['bytes'] = pd.to_numeric(df['bytes'], errors='coerce').fillna(0)

# Create suspicious indicators
df['is_failed'] = df['status'].apply(lambda x: 1 if int(x) >= 400 else 0)
df['is_large_transfer'] = df['bytes'].apply(lambda x: 1 if x > 500000 else 0)

# ============================
# Select ML features
# ============================

features = df[['hour', 'day_of_week', 'bytes', 'is_failed', 'is_large_transfer']]

print("\nML Feature Sample:")
print(features.head())

# Save prepared dataset
features.to_csv("data/prepared_logs.csv", index=False)

print("\nPrepared dataset saved as data/prepared_logs.csv")
print("Total log entries:", len(features))
