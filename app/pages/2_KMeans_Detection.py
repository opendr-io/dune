"""K-Means distance-to-centroid anomaly detection (from kmeans-mark-3)."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

import matplotlib.pyplot as plt
import seaborn as sns
import streamlit as st

from lib.data_io import encode_categoricals, scalar_columns
from lib.kmeans_utils import detect_anomalies, fit_kmeans, forecast_kmeans_runtime, pca_reduce, standardize

st.set_page_config(page_title="K-Means Detection", page_icon="🎯", layout="wide")
st.title("🎯 K-Means Detection")
st.caption("Cluster the data and flag rows far from their nearest centroid as anomalies.")

if "raw_df" not in st.session_state:
    st.warning("Load a dataset on the home page first.")
    st.stop()

df = st.session_state["raw_df"]
candidate_cols = scalar_columns(df)

columns = st.multiselect(
    "Columns to use for clustering",
    candidate_cols,
    default=[c for c in ["sourceIPAddress", "eventSource", "eventName", "userAgent"] if c in candidate_cols],
)

id_col = st.selectbox(
    "Row ID column (used to map anomalies back to full rows)",
    candidate_cols,
    index=candidate_cols.index("eventID") if "eventID" in candidate_cols else 0,
)

col1, col2, col3, col4 = st.columns(4)
k = col1.number_input("k (clusters)", min_value=2, max_value=200, value=st.session_state.get("suggested_k", 8))
percentile = col2.slider("Outlier percentile", min_value=90.0, max_value=99.9, value=99.0, step=0.1)
mode = col3.selectbox("KMeans mode", ["default", "safe", "minibatch"])
seed = col4.number_input("Random seed", min_value=0, value=42)

if st.button("Estimate runtime", disabled=not columns):
    with st.spinner("Timing small samples and extrapolating..."):
        encoded = encode_categoricals(df, columns)
        x = standardize(encoded, columns)
        x2, _ = pca_reduce(x, 2)
        forecasts = forecast_kmeans_runtime(x2, int(k), seed=int(seed))
    for name, (t_pred, samples) in forecasts.items():
        if t_pred is None:
            st.write(f"**{name}**: not enough data to forecast")
        else:
            st.write(f"**{name}**: predicted runtime ≈ {t_pred:.2f}s (samples: {samples})")

if st.button("Run K-Means detection", type="primary", disabled=not columns):
    with st.spinner("Encoding, scaling, clustering, and scoring..."):
        encoded = encode_categoricals(df, columns)
        x = standardize(encoded, columns)
        x2, _ = pca_reduce(x, 2)
        model = fit_kmeans(x2, int(k), mode=mode, seed=int(seed))
        clusters, anomaly_idx, threshold = detect_anomalies(x2, model, percentile=percentile)

        result = df.copy()
        result["cluster"] = clusters
        result["c1"] = x2[:, 0]
        result["c2"] = x2[:, 1]
        result["outlier_kmeans"] = 0
        result.iloc[anomaly_idx, result.columns.get_loc("outlier_kmeans")] = 1

        st.session_state["kmeans_output"] = result
        st.session_state["kmeans_x2"] = x2
        st.session_state["kmeans_model"] = model
        st.session_state["kmeans_anomaly_idx"] = anomaly_idx
        st.session_state["kmeans_threshold"] = threshold

if "kmeans_output" in st.session_state:
    result = st.session_state["kmeans_output"]
    anomaly_idx = st.session_state["kmeans_anomaly_idx"]
    x2 = st.session_state["kmeans_x2"]
    model = st.session_state["kmeans_model"]

    st.subheader("Results")
    st.metric("Anomalous rows", len(anomaly_idx))
    st.caption(f"Distance threshold at the {percentile:.1f}th percentile: {st.session_state['kmeans_threshold']:.4f}")

    fig, ax = plt.subplots(figsize=(11, 7))
    sns.scatterplot(x=result["c1"], y=result["c2"], hue=result["cluster"], palette="tab10", alpha=0.4, s=40, legend=False, ax=ax)
    sns.scatterplot(x=x2[anomaly_idx, 0], y=x2[anomaly_idx, 1], color="red", marker="X", s=60, edgecolor="black", ax=ax, label="anomaly")
    sns.scatterplot(x=model.cluster_centers_[:, 0], y=model.cluster_centers_[:, 1], color="blue", marker="X", s=200, ax=ax, label="centroid")
    ax.set_title("K-Means clusters, centroids in blue, outliers in red")
    ax.legend()
    st.pyplot(fig)

    anomalies = result[result["outlier_kmeans"] == 1]
    st.subheader(f"Flagged rows ({len(anomalies)})")
    st.dataframe(anomalies, width="stretch")
    st.download_button(
        "Download anomalies as CSV",
        anomalies.to_csv(index=False).encode("utf-8"),
        file_name="kmeans_anomalies.csv",
        mime="text/csv",
    )
