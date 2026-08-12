"""Ensemble anomaly detection across many PyOD models (from pyod-mark-3)."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import streamlit as st

from lib.data_io import encode_categoricals, scalar_columns
from lib.pyod_utils import ALL_MODEL_NAMES, CORE_MODEL_NAMES, build_classifiers, forecast_runtimes, run_ensemble

st.set_page_config(page_title="PyOD Ensemble", page_icon="🧪", layout="wide")
st.title("🧪 PyOD Ensemble")
st.caption("Run a panel of PyOD outlier detectors and rank rows by how many models flag them.")

if "raw_df" not in st.session_state:
    st.warning("Load a dataset on the home page first.")
    st.stop()

df = st.session_state["raw_df"]
candidate_cols = scalar_columns(df)

columns = st.multiselect(
    "Columns to use for outlier detection",
    candidate_cols,
    default=[c for c in ["sourceIPAddress", "eventSource", "eventName", "userAgent", "userIdentity.arn"] if c in candidate_cols],
)

id_col = st.selectbox(
    "Row ID column (used to map anomalies back to full rows)",
    candidate_cols,
    index=candidate_cols.index("eventID") if "eventID" in candidate_cols else 0,
)

col1, col2, col3 = st.columns(3)
contamination = col1.number_input("Contamination fraction", min_value=0.0001, max_value=0.5, value=0.001, step=0.0001, format="%.4f")
max_seconds = col2.number_input("Exclude models slower than (s)", min_value=5, max_value=600, value=60)
seed = col3.number_input("Random seed", min_value=0, value=42)

include_optional = st.checkbox(
    "Include optional/slower models (OCSVM, KDE, QMCD, DIF, LUNAR)",
    value=False,
    help="DIF and LUNAR require torch; they're skipped automatically if it isn't installed.",
)
selected_models = st.multiselect(
    "Models to run",
    ALL_MODEL_NAMES,
    default=CORE_MODEL_NAMES if not include_optional else ALL_MODEL_NAMES,
)

if st.button("Estimate runtimes", disabled=not (columns and selected_models)):
    with st.spinner("Building classifiers and timing samples..."):
        encoded = encode_categoricals(df, columns)
        x = encoded.loc[:, columns].values
        rs = np.random.RandomState(int(seed))
        clf, unavailable = build_classifiers(contamination, rs, selected_models)
        forecasts = forecast_runtimes(clf, x)
    if unavailable:
        st.info(f"Unavailable (missing dependency): {', '.join(unavailable)}")
    st.dataframe(forecasts, width="stretch")
    excluded = forecasts[forecasts["predicted_seconds"] > max_seconds]["model"].tolist()
    if excluded:
        st.warning(f"These would be excluded at the current time limit: {', '.join(excluded)}")

if st.button("Run ensemble", type="primary", disabled=not (columns and selected_models)):
    encoded = encode_categoricals(df, columns)
    rs = np.random.RandomState(int(seed))
    clf, unavailable = build_classifiers(contamination, rs, selected_models)
    if unavailable:
        st.info(f"Skipped (missing dependency): {', '.join(unavailable)}")

    with st.spinner("Estimating per-model runtime..."):
        x = encoded.loc[:, columns].values
        forecasts = forecast_runtimes(clf, x)
        predicted_times = dict(zip(forecasts["model"], forecasts["predicted_seconds"]))

    progress = st.progress(0.0, text="Starting...")

    def on_progress(i, total, name):
        progress.progress((i + 1) / total, text=f"Fitting {name} ({i + 1}/{total})")

    with st.spinner("Fitting models..."):
        result, failed, excluded = run_ensemble(
            encoded, columns, clf, max_seconds=max_seconds, predicted_times=predicted_times, progress_cb=on_progress
        )
    progress.empty()

    if excluded:
        st.warning(f"Excluded for exceeding the time limit: {', '.join(excluded)}")
    if failed:
        st.error(f"Failed to fit: {', '.join(failed)}")

    st.session_state["pyod_encoded"] = result
    out_cols = [c for c in result.columns if c.startswith("out_")]
    scored_ids = result.loc[result["rank"] > 0, id_col].unique()
    output = df[df[id_col].isin(scored_ids)].merge(result[[id_col, "rank"] + out_cols], on=id_col, how="left")
    st.session_state["pyod_output"] = output
    st.session_state["pyod_out_cols"] = out_cols

if "pyod_output" in st.session_state:
    output = st.session_state["pyod_output"]
    out_cols = st.session_state["pyod_out_cols"]
    encoded_result = st.session_state["pyod_encoded"]

    st.subheader("Results")
    st.metric("Flagged rows", len(output))

    st.markdown("**Rank distribution** (number of models that voted a row an outlier)")
    st.bar_chart(encoded_result["rank"].value_counts().sort_index())

    if len(out_cols) > 1:
        st.markdown("**Model agreement (Pearson correlation between vote columns)**")
        fig, ax = plt.subplots(figsize=(min(1.2 * len(out_cols), 14), min(1.0 * len(out_cols), 12)))
        sns.heatmap(encoded_result[out_cols].corr(), annot=True, fmt=".2f", cmap="viridis", ax=ax)
        st.pyplot(fig)

    st.subheader(f"Flagged rows ({len(output)})")
    st.dataframe(output.sort_values("rank", ascending=False), width="stretch")
    st.download_button(
        "Download anomalies as CSV",
        output.to_csv(index=False).encode("utf-8"),
        file_name="pyod_anomalies.csv",
        mime="text/csv",
    )
