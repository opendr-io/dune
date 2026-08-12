"""DUNE Threat Hunter - Databricks App entry point.

Loads a log dataframe (e.g. CloudTrail) once here, then Silhouette Analysis,
K-Means Detection, PyOD Ensemble and Explorer pages all operate on it via
st.session_state.
"""

import streamlit as st

from lib.data_io import cardinality_table, load_dataframe

st.set_page_config(page_title="DUNE Threat Hunter", page_icon="🛡️", layout="wide")

st.title("🛡️ DUNE Threat Hunter")
st.markdown(
    "Ensemble and cluster-based anomaly detection for security logs, adapted from the "
    "[DUNE project](https://github.com/opendr-io/dune) notebooks. Load a dataset below, "
    "then use the pages in the sidebar to find outliers and explore them."
)

st.subheader("1. Load data")

source = st.radio("Data source", ["Upload file", "Workspace / Volume path"], horizontal=True)

signature = None
load_requested = False
loader = None

if source == "Upload file":
    uploaded = st.file_uploader("CSV or Parquet file", type=["csv", "parquet"])
    if uploaded is not None:
        signature = ("upload", uploaded.name, uploaded.size)
        loader = lambda: load_dataframe(uploaded_file=uploaded)  # noqa: E731
        load_requested = st.button("Load dataset", type="primary")
else:
    path = st.text_input(
        "Path to a CSV or Parquet file",
        placeholder="/Volumes/catalog/schema/volume/cloudtrail.parquet",
        help="Any path readable by the app's compute, e.g. a Unity Catalog Volume.",
    )
    if path:
        signature = ("path", path)
        loader = lambda: load_dataframe(path=path)  # noqa: E731
        load_requested = st.button("Load dataset", type="primary")

# Only (re)load and clear downstream results when the user explicitly asks to,
# not on every rerun (e.g. navigating back to this page) - otherwise a still-set
# file_uploader value would silently wipe kmeans_output / pyod_output each visit.
if load_requested and loader is not None:
    with st.spinner("Loading file..."):
        df = loader()
    st.session_state["raw_df"] = df
    st.session_state["source_name"] = signature[1]
    for key in ("kmeans_output", "pyod_output", "suggested_k"):
        st.session_state.pop(key, None)

if "raw_df" in st.session_state:
    df = st.session_state["raw_df"]
    st.success(f"Loaded **{st.session_state.get('source_name', 'dataset')}** — {df.shape[0]:,} rows x {df.shape[1]} columns")

    st.subheader("2. Preview")
    st.dataframe(df.head(50), width="stretch")

    st.subheader("3. Column cardinality")
    st.caption("Distinct values per column - useful for choosing which fields to encode for modeling.")
    st.dataframe(cardinality_table(df).rename("distinct_values"), width="stretch")

    st.subheader("Next steps")
    st.markdown(
        "- **Silhouette Analysis** — find a good number of clusters (k) before running K-Means.\n"
        "- **K-Means Detection** — distance-to-centroid anomaly detection.\n"
        "- **PyOD Ensemble** — vote-based anomaly detection across many models.\n"
        "- **Explorer** — filter, aggregate, and graph any of the above results."
    )
else:
    st.info("Upload a file or provide a path to get started.")
