"""Filter, aggregate, and graph any loaded/scored dataframe (from viewer-mark-3)."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

import streamlit as st

from lib.data_io import scalar_columns
from lib.ip_enrich import enrich_ips
from lib.network_graph import build_ip_user_graph

st.set_page_config(page_title="Explorer", page_icon="🔎", layout="wide")
st.title("🔎 Explorer")
st.caption("Group, filter, and graph the raw dataset or a scored anomaly output.")

available = {}
if "raw_df" in st.session_state:
    available["Raw dataset"] = st.session_state["raw_df"]
if "kmeans_output" in st.session_state:
    available["K-Means output"] = st.session_state["kmeans_output"]
if "pyod_output" in st.session_state:
    available["PyOD output"] = st.session_state["pyod_output"]

if not available:
    st.warning("Load a dataset on the home page first.")
    st.stop()

choice = st.selectbox("Dataset to explore", list(available.keys()))
df = available[choice]
cols = scalar_columns(df)

st.divider()
st.subheader("Group & aggregate")

group_cols = st.multiselect("Group by", cols, key="group_cols")
gcol1, gcol2 = st.columns(2)
ascending = gcol2.radio("Sort", ["Descending", "Ascending"], horizontal=True) == "Ascending"
top_n = gcol1.number_input("Top N rows", min_value=1, value=50)

if st.button("Run aggregation", disabled=not group_cols):
    agg = df.groupby(group_cols).size().reset_index(name="count").sort_values("count", ascending=ascending)
    st.dataframe(agg.head(int(top_n)), width="stretch")
    st.caption(f"Showing {min(int(top_n), len(agg))} of {len(agg)} groups.")

st.divider()
st.subheader("Filter")

max_unique = st.slider("Max distinct values for a filterable column", min_value=5, max_value=200, value=50)
auto_cols = [c for c in cols if 1 < df[c].nunique(dropna=True) <= max_unique]
filter_cols = st.multiselect("Columns to filter on", cols, default=auto_cols[:6])

filters = {}
if filter_cols:
    fcols = st.columns(min(3, len(filter_cols)))
    for i, col in enumerate(filter_cols):
        options = ["(All)"] + sorted(df[col].dropna().astype(str).unique().tolist())
        selected = fcols[i % len(fcols)].selectbox(col, options, key=f"filter_{col}")
        if selected != "(All)":
            filters[col] = selected

filtered = df
for col, val in filters.items():
    filtered = filtered[filtered[col].astype(str) == val]

st.dataframe(filtered.head(200), width="stretch")
st.caption(f"Showing {min(len(filtered), 200)} of {len(filtered)} matching rows.")
st.download_button(
    "Download filtered rows as CSV",
    filtered.to_csv(index=False).encode("utf-8"),
    file_name="filtered_rows.csv",
    mime="text/csv",
)

st.divider()
st.subheader("IP <-> user graph")

ip_candidates = [c for c in cols if "ip" in c.lower()] or cols
user_candidates = [c for c in cols if "user" in c.lower()] or cols

gcol1, gcol2 = st.columns(2)
ip_col = gcol1.selectbox("IP column", ip_candidates, index=0)
user_col = gcol2.selectbox("User column", user_candidates, index=0)

enrich = st.checkbox("Enrich IPs with RDAP/whois (ASN + country, public IPs only, network calls)", value=False)
max_lookups = st.number_input("Max live RDAP lookups", min_value=1, max_value=200, value=10, disabled=not enrich)

col1, col2, col3, col4, col5, col6 = st.columns(6)
top_ips = col1.slider("Top IPs", 3, 200, 30)
min_count = col2.slider("Min event count", 1, 100, 1)
spring_length = col3.slider("Spacing", 80, 420, 170, step=10)
repulsion = col4.slider("Repulsion", 8000, 80000, 26000, step=2000)
font_size = col5.slider("Font size", 14, 40, 24, step=2)
node_margin = col6.slider("Node margin", 0, 30, 10, step=2)

if st.button("Render graph", type="primary"):
    agg = df.dropna(subset=[user_col]).groupby([ip_col, user_col]).size().reset_index(name="count")

    asn_col = country_col = None
    if enrich:
        with st.spinner("Looking up ASN/country for public IPs..."):
            ips = agg[ip_col].dropna().astype(str).unique().tolist()
            ip_info = enrich_ips(ips, max_lookups=int(max_lookups))
            agg = agg.merge(ip_info.rename(columns={"sourceIPAddress": ip_col}), on=ip_col, how="left")
            asn_col, country_col = "asn_name", "country"

    with st.spinner("Building graph..."):
        html = build_ip_user_graph(
            agg,
            ip_col=ip_col,
            user_col=user_col,
            count_col="count",
            asn_col=asn_col,
            country_col=country_col,
            top_ips=int(top_ips),
            min_count=int(min_count),
            spring_length=int(spring_length),
            repulsion=int(repulsion),
            font_size=int(font_size),
            node_margin=int(node_margin),
        )
    st.iframe(html, height=900)
