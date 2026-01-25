import streamlit as st
import pandas as pd
import joblib
import plotly.express as px

# ============================
# Page config
# ============================
st.set_page_config(page_title="SOC Log Anomaly Detector", layout="wide")
st.title("SOC Log Anomaly Detection Dashboard")

# ============================
# Load model & scaler
# ============================
model = joblib.load("anomaly_model.pkl")
scaler = joblib.load("scaler.pkl")

# Features used for model
MODEL_FEATURES = [
    "hour", "day", "bytes", "is_error", "is_server_error",
    "large_transfer", "url_length", "requests_per_ip",
    "is_post", "is_get", "is_exe", "is_admin"
]

# ============================
# File upload
# ============================
uploaded_file = st.file_uploader("Upload structured log CSV (features.csv or attack_test.csv)", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.subheader("Log Preview")
    st.dataframe(df.head())

    # ============================
    # Prepare model input safely
    # ============================
    missing_cols = [c for c in MODEL_FEATURES if c not in df.columns]
    if missing_cols:
        st.error(f"Missing required features: {missing_cols}")
        st.stop()

    X_model = df[MODEL_FEATURES]
    X_scaled = scaler.transform(X_model)

    # ============================
    # Predict anomalies
    # ============================
    preds = model.predict(X_scaled)
    df["anomaly"] = (preds == -1).astype(int)
    anomalies = df[df["anomaly"] == 1].copy()

    # ============================
    # Explain anomalies
    # ============================
    def explain(row):
        reasons = []
        if row["requests_per_ip"] > 1000:
            reasons.append("High request volume")
        if row["is_server_error"] == 1:
            reasons.append("Server error response")
        if row["large_transfer"] == 1:
            reasons.append("Large data transfer")
        if row["is_admin"] == 1:
            reasons.append("Admin endpoint access")
        if row["is_exe"] == 1:
            reasons.append("Executable file access")
        return ", ".join(reasons) if reasons else "Statistical anomaly"

    if len(anomalies) > 0:
        anomalies["reason"] = anomalies.apply(explain, axis=1)

    # ============================
    # Metrics
    # ============================
    st.subheader("Detection Summary")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Logs", len(df))
    col2.metric("Anomalies Detected", len(anomalies))
    col3.metric("Anomaly Rate", f"{(len(anomalies)/len(df))*100:.2f}%")

    if "ground_truth" in df.columns:
        accuracy = (df["ground_truth"] == df["anomaly"]).mean()
        st.metric("Attack Detection Accuracy", f"{accuracy*100:.2f}%")

    # ============================
    # Filters
    # ============================
    st.subheader("Filter Anomalies")
    reason_filter = st.multiselect(
        "Select anomaly reasons to view",
        options=anomalies["reason"].unique() if len(anomalies) > 0 else [],
        default=None
    )

    filtered_anomalies = anomalies.copy()
    if reason_filter:
        filtered_anomalies = anomalies[anomalies["reason"].isin(reason_filter)]

    # ============================
    # Charts
    # ============================
    st.subheader("Anomaly Analytics")

    if len(filtered_anomalies) > 0:
        # Anomalies per hour
        fig_hour = px.histogram(filtered_anomalies, x="hour", title="Anomalies per Hour")
        st.plotly_chart(fig_hour, use_container_width=True)

        # Anomalies per day
        fig_day = px.histogram(filtered_anomalies, x="day", title="Anomalies per Day of Week")
        st.plotly_chart(fig_day, use_container_width=True)

        # Top reasons
        reason_counts = filtered_anomalies["reason"].value_counts().reset_index()
        reason_counts.columns = ["reason", "count"]
        fig_reason = px.bar(reason_counts, x="reason", y="count", title="Top Anomaly Reasons")
        st.plotly_chart(fig_reason, use_container_width=True)

    # ============================
    # Show anomaly table
    # ============================
    st.subheader("Top Detected Anomalies")
    st.dataframe(filtered_anomalies.head(50))

    # ============================
    # Save report
    # ============================
    if len(filtered_anomalies) > 0:
        filtered_anomalies.to_csv("soc_anomaly_report.csv", index=False)
        st.success("Anomaly report saved: soc_anomaly_report.csv")
    else:
        st.info("No anomalies detected or matching the filter.")
