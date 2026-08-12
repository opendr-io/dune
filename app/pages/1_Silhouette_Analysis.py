"""Find a good k before running K-Means Detection (from silhouettes-mark-3)."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

import streamlit as st

from lib.data_io import encode_categoricals, scalar_columns
from lib.kmeans_utils import silhouette_search, standardize

st.set_page_config(page_title="Silhouette Analysis", page_icon="📈", layout="wide")
st.title("📈 Silhouette Analysis")
st.caption("Compute silhouette scores across candidate cluster counts to pick a good k for K-Means Detection.")

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

col1, col2, col3 = st.columns(3)
k_min = col1.number_input("Min k", min_value=2, max_value=200, value=2)
k_max = col2.number_input("Max k", min_value=2, max_value=200, value=32)
sample_size = col3.number_input("Search sample size", min_value=200, max_value=50000, value=5000, step=500)

if k_min >= k_max:
    st.error("Min k must be less than max k.")
    st.stop()

if st.button("Run silhouette search", type="primary", disabled=not columns):
    with st.spinner("Encoding, scaling, and scoring candidate k values..."):
        encoded = encode_categoricals(df, columns)
        x = standardize(encoded, columns)
        scores = silhouette_search(x, list(range(int(k_min), int(k_max) + 1)), sample_size=int(sample_size))

    best = scores.loc[scores["silhouette_score"].idxmax()]
    st.session_state["silhouette_scores"] = scores
    st.session_state["suggested_k"] = int(best["k"])

if "silhouette_scores" in st.session_state:
    scores = st.session_state["silhouette_scores"]
    best_k = st.session_state["suggested_k"]

    st.subheader("Results")
    st.bar_chart(scores.set_index("k")["silhouette_score"])
    st.dataframe(scores, width="stretch")
    st.success(f"Best k = **{best_k}** (silhouette score {scores['silhouette_score'].max():.4f})")
    st.caption("This value is remembered and pre-filled on the K-Means Detection page.")
