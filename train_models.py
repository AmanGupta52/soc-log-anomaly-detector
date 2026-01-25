import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, accuracy_score
import time

start_time = time.time()

# ========================
# Load data (optimized)
# ========================
print("[+] Loading dataset...")

X = pd.read_csv("features.csv").astype("float32")

total_samples = len(X)
print(f"[+] Loaded {total_samples} rows")

# ========================
# Create heuristic labels
# ========================
print("[+] Creating heuristic labels...")

y_true = (
    (X["is_server_error"] == 1) |
    (X["large_transfer"] == 1) |
    (X["requests_per_ip"] > 500)
).astype(int)

normal_count = (y_true == 0).sum()
anomaly_count = (y_true == 1).sum()

normal_pct = (normal_count / total_samples) * 100
anomaly_pct = (anomaly_count / total_samples) * 100

# ========================
# Sample for training
# ========================
TRAIN_SIZE = min(100_000, total_samples)

print(f"[+] Sampling {TRAIN_SIZE} rows for training...")

X_train = X.sample(TRAIN_SIZE, random_state=42)

# ========================
# Isolation Forest (FAST CONFIG)
# ========================
print("[+] Training Isolation Forest...")

iso_model = IsolationForest(
    n_estimators=100,        # reduced trees
    contamination=0.03,
    max_samples=TRAIN_SIZE,
    n_jobs=-1,              # use all CPU cores
    random_state=42
)

iso_model.fit(X_train)

print("[+] Predicting anomalies on full dataset...")

iso_pred = iso_model.predict(X)
iso_pred = (iso_pred == -1).astype(int)

iso_anomaly_count = iso_pred.sum()
iso_anomaly_pct = (iso_anomaly_count / total_samples) * 100

# ========================
# Evaluation
# ========================
print("[+] Evaluating model...")

iso_acc = accuracy_score(y_true, iso_pred)
report_iso = classification_report(y_true, iso_pred)

# ========================
# Save anomalies
# ========================
print("[+] Saving detected anomalies...")

X["anomaly"] = iso_pred
anomalies = X[X["anomaly"] == 1]
anomalies.to_csv("detected_anomalies.csv", index=False)

# ========================
# Save evaluation report
# ========================
print("[+] Writing evaluation report...")

with open("evaluation_report.txt", "w") as f:
    f.write("SOC Log Anomaly Detection Evaluation Report\n")
    f.write("=" * 55 + "\n\n")

    f.write("Dataset Statistics:\n")
    f.write(f"Total samples: {total_samples}\n")
    f.write(f"Normal samples: {normal_count} ({normal_pct:.2f}%)\n")
    f.write(f"Suspicious samples (heuristic): {anomaly_count} ({anomaly_pct:.2f}%)\n\n")

    f.write("Isolation Forest Results:\n")
    f.write(f"Detected anomalies: {iso_anomaly_count} ({iso_anomaly_pct:.2f}%)\n")
    f.write(f"Accuracy: {iso_acc:.4f}\n")
    f.write(report_iso + "\n")

end_time = time.time()
elapsed = end_time - start_time

# ========================
# Console Output
# ========================
print("\n===== Dataset Distribution =====")
print(f"Total samples: {total_samples}")
print(f"Normal: {normal_count} ({normal_pct:.2f}%)")
print(f"Suspicious (heuristic): {anomaly_count} ({anomaly_pct:.2f}%)")

print("\n===== Model Detection =====")
print(f"Isolation Forest anomalies: {iso_anomaly_count} ({iso_anomaly_pct:.2f}%)")

print("\n===== Accuracy =====")
print("Isolation Forest Accuracy:", iso_acc)

print("\n===== Runtime =====")
print(f"Total time: {elapsed:.2f} seconds")

print("\nFiles generated:")
print("- detected_anomalies.csv")
print("- evaluation_report.txt")
joblib.dump(model, "anomaly_model2.pkl")
joblib.dump(scaler, "scaler2.pkl")
