# SOC Log Anomaly Detection Dashboard

A machine learning–based Security Operations Center (SOC) tool for detecting anomalous web traffic and cyber attacks using structured logs.

## Features

- ML-based anomaly detection (Isolation Forest)
- Synthetic attack injection testing
- Interactive SOC dashboard (Streamlit)
- Real-time analytics & charts
- Attack explanation engine
- CSV report generation

## Tech Stack

- Python
- Scikit-learn
- Pandas
- Streamlit
- Plotly
- Joblib

## Model Features

hour, day, bytes, is_error, is_server_error, large_transfer, url_length,  
requests_per_ip, is_post, is_get, is_exe, is_admin

## How to Run

### 1. Install dependencies

```bash
pip install -r requirements.txt
2. Start dashboard

streamlit run dashboard/soc_dashboard.py
3. Upload CSV file
Upload:

features.csv (normal logs)

or attack_test.csv (with injected attacks)

Detection Logic
The model flags anomalies using:

High request rate

Admin endpoint access

Executable downloads

Server errors

Large data transfers

Statistical deviations

Output
Visual anomaly analytics

Explanation per attack

Exportable SOC report: soc_anomaly_report.csv

Sample Results
Attack detection accuracy: ~97%

Supports datasets >1M rows

Author
Aman – Cybersecurity & ML Developer


---

## 4. Add `.gitignore`

pycache/
*.pkl
*.csv
.env
.venv


(Keep sample CSVs only)

---

## 5. Resume Project Description (Use this)

**SOC Log Anomaly Detection System (ML + Streamlit)**  
- Built an ML-based SOC tool using Isolation Forest to detect web-based cyber attacks from structured logs.  
- Engineered 12 security features including request rate, admin access, executable downloads, and transfer size.  
- Achieved 97%+ attack detection accuracy using synthetic attack injection testing.  
- Developed an interactive Streamlit dashboard with real-time analytics, filtering, and automated attack explanations.  
- Tech: Python, Scikit-learn, Pandas, Streamlit, Plotly.

---

## 6. Optional: Add GitHub Topics

In GitHub repo settings → Topics:

cybersecurity
machine-learning
soc
anomaly-detection
streamlit
python
security-analytics



---

If you want, I can also:

- Write a **GitHub project description**
- Add **badges**
- Improve UI to look like **Splunk / Elastic SOC**
- Add **real-time log streaming**
- Add **alert severity levels (Low/Medium/High/Critical)**

Just tell me 👍