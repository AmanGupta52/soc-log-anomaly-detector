import pandas as pd
import numpy as np

print("[+] Loading feature dataset...")

X = pd.read_csv("features.csv")

print("[+] Total original rows:", len(X))

# ============================
# Create synthetic attacks
# ============================

ATTACK_SAMPLES = 5000   # You can increase/decrease

attack = X.sample(ATTACK_SAMPLES, random_state=42).copy()

# Brute-force pattern
attack["requests_per_ip"] = np.random.randint(3000, 8000, size=ATTACK_SAMPLES)

# Admin endpoint access
attack["is_admin"] = 1

# Executable access
attack["is_exe"] = 1

# POST requests (optional realism)
attack["is_post"] = 1
attack["is_get"] = 0

# Large transfer simulation
attack["bytes"] = np.random.randint(20000, 90000, size=ATTACK_SAMPLES)
attack["large_transfer"] = 1

# URL length increase (payloads)
attack["url_length"] = np.random.randint(80, 200, size=ATTACK_SAMPLES)

# Server errors occasionally
attack["is_server_error"] = np.random.choice([0, 1], size=ATTACK_SAMPLES, p=[0.7, 0.3])
attack["is_error"] = attack["is_server_error"]

# ============================
# Merge datasets
# ============================

test_data = pd.concat([X, attack], ignore_index=True)

# Add ground truth column (for testing only)
test_data["ground_truth"] = 0
test_data.loc[len(X):, "ground_truth"] = 1

test_data.to_csv("attack_test.csv", index=False)

print("[+] Synthetic attacks added:", ATTACK_SAMPLES)
print("[+] Total test rows:", len(test_data))
print("[+] Saved as attack_test.csv")

print("\nExpected behavior:")
print("- High requests_per_ip")
print("- is_admin = 1")
print("- is_exe = 1")
print("- large_transfer = 1")
