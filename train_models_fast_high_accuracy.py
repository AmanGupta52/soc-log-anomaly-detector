import time
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
start = time.time()

print("[+] Loading dataset...")
X = pd.read_csv("features.csv")

total_samples = len(X)
print(f"[+] Loaded {total_samples} rows")

# -----------------------
# Improved heuristic labels
# -----------------------
print("[+] Creating improved heuristic labels...")

y_true = (
    (X["is_server_error"] == 1) |
    ((X["large_transfer"] == 1) & (X["requests_per_ip"] > 1000)) |
    (X["is_admin"] == 1) |
    (X["is_exe"] == 1)
).astype(int)

normal_count = (y_true == 0).sum()
anomaly_count = (y_true == 1).sum()

# -----------------------
# Sampling
# -----------------------
print("[+] Sampling 100000 rows for training...")
train_sample = X.sample(n=100000, random_state=42)

# -----------------------
# Scaling
# -----------------------
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(train_sample)
X_full_scaled = scaler.transform(X)

# -----------------------
# Train Isolation Forest
# -----------------------
print("[+] Training Isolation Forest...")

model = IsolationForest(
    n_estimators=150,
    contamination=0.02,
    max_samples=100000,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train_scaled)

# -----------------------
# Predict full dataset
# -----------------------
print("[+] Predicting anomalies on full dataset...")

pred = model.predict(X_full_scaled)
pred = (pred == -1).astype(int)

# -----------------------
# Evaluation
# -----------------------
print("[+] Evaluating model...")

acc = accuracy_score(y_true, pred)
report = classification_report(y_true, pred)

# -----------------------
# Save anomalies
# -----------------------
X["anomaly"] = pred
anomalies = X[X["anomaly"] == 1]
anomalies.to_csv("detected_anomalies.csv", index=False)

# -----------------------
# Save report
# -----------------------
with open("evaluation_report.txt", "w") as f:
    f.write("SOC Log Anomaly Detection Evaluation Report\n")
    f.write("=" * 55 + "\n\n")
    f.write(f"Total samples: {total_samples}\n")
    f.write(f"Normal: {normal_count}\n")
    f.write(f"Suspicious (heuristic): {anomaly_count}\n\n")
    f.write(f"Isolation Forest Accuracy: {acc:.4f}\n\n")
    f.write(report)

end = time.time()

print("\n===== Results =====")
print(f"Accuracy: {acc:.4f}")
print(f"Anomalies detected: {pred.sum()} ({(pred.sum()/total_samples)*100:.2f}%)")
print(f"Runtime: {end-start:.2f} seconds")

print("\nFiles generated:")
print("- detected_anomalies.csv")
print("- evaluation_report.txt")
joblib.dump(model, "anomaly_model.pkl")
joblib.dump(scaler, "scaler.pkl")
