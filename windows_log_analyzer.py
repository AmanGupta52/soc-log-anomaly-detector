# windows_log_analyzer.py
import wmi
import pandas as pd
from datetime import datetime
import joblib

# ============================
# Load existing model & scaler
# ============================
scaler = joblib.load("scaler.pkl")
model = joblib.load("anomaly_model.pkl")

# ============================
# WMI connection
# ============================
c = wmi.WMI()

# ============================
# Query Windows Security log
# ============================
query = "Select TimeGenerated, EventCode, InsertionStrings from Win32_NTLogEvent where Logfile='Security'"
events = []

for e in c.query(query):
    if e.EventCode in [4624, 4625]:  # Login success/failure
        # Parse timestamp
        try:
            ts = datetime.strptime(e.TimeGenerated.split('.')[0], "%Y%m%d%H%M%S")
        except:
            ts = pd.NaT

        # Auto-detect username
        user = "Unknown"
        ip = "Local"

        if e.InsertionStrings:
            # Try to find a string that looks like a username (contains \ or @)
            for s in e.InsertionStrings:
                if isinstance(s, str) and ("\\" in s or "@" in s):
                    user = s
                    break

            # Try to find a string that looks like an IP
            for s in e.InsertionStrings:
                if isinstance(s, str):
                    parts = s.split(".")
                    if len(parts) == 4 and all(p.isdigit() for p in parts):
                        ip = s
                        break

        # Login success or failure
        success = 1 if e.EventCode == 4624 else 0

        # Append event
        events.append({
            "timestamp": ts,
            "user": user,
            "src_ip": ip,
            "login_success": success
        })

# ============================
# Create DataFrame
# ============================
if len(events) == 0:
    print("⚠️ No Windows Security events found! Creating empty DataFrame.")
    df = pd.DataFrame(columns=["timestamp", "user", "src_ip", "login_success"])
else:
    df = pd.DataFrame(events)

# Ensure required columns exist
for col in ["timestamp", "user", "src_ip", "login_success"]:
    if col not in df.columns:
        df[col] = None

# ============================
# Convert timestamp to datetime safely
# ============================
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

# ============================
# Feature Engineering
# ============================
df["login_attempts"] = df.groupby("src_ip")["src_ip"].transform("count") if "src_ip" in df.columns else 0
df["hour"] = df["timestamp"].dt.hour if "timestamp" in df.columns else 0
df["day"] = df["timestamp"].dt.dayofweek if "timestamp" in df.columns else 0
df["failed_login"] = (df["login_success"] == 0).astype(int) if "login_success" in df.columns else 0
df["high_attempts"] = (df["login_attempts"] > 5).astype(int)

MODEL_FEATURES = ["hour", "day", "failed_login", "high_attempts"]

# ============================
# Predict anomalies
# ============================
if len(df) > 0:
    X_scaled = scaler.transform(df[MODEL_FEATURES])
    preds = model.predict(X_scaled)
    df["anomaly"] = (preds == -1).astype(int)
else:
    df["anomaly"] = []

# ============================
# Save outputs
# ============================
df.to_csv("windows_auth_log.csv", index=False)
df[df.get("anomaly", 0) == 1].to_csv("windows_anomalies.csv", index=False)

print("✅ Windows Security logs parsed and anomalies detected!")
print(f"Total logs: {len(df)}, Anomalies: {df['anomaly'].sum() if 'anomaly' in df.columns else 0}")
