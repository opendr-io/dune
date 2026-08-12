"""IP <-> user relationship graph (from viewer-mark-3)."""

from __future__ import annotations

import pandas as pd
from pyvis.network import Network


def build_ip_user_graph(
    df: pd.DataFrame,
    ip_col: str,
    user_col: str,
    count_col: str,
    asn_col: str | None = None,
    country_col: str | None = None,
    top_ips: int = 30,
    min_count: int = 1,
    spring_length: int = 170,
    repulsion: int = 26000,
    font_size: int = 24,
    node_margin: int = 10,
) -> str:
    """Build a pyvis IP<->user bipartite graph and return standalone HTML."""
    d = df[df[count_col] >= min_count].copy()

    ip_fanout_all = d.groupby(ip_col)[user_col].nunique()
    keep_ips = set(ip_fanout_all.sort_values(ascending=False).head(top_ips).index)
    d = d[d[ip_col].isin(keep_ips)]

    if d.empty:
        return "<p>No rows match the current filters.</p>"

    ip_total = d.groupby(ip_col)[count_col].sum()
    ip_fanout = d.groupby(ip_col)[user_col].nunique()
    user_total = d.groupby(user_col)[count_col].sum()
    user_fanout = d.groupby(user_col)[ip_col].nunique()

    net = Network(height="860px", width="100%", notebook=False, directed=False, cdn_resources="in_line")
    net.barnes_hut()
    net.set_options(f"""
    {{
      "nodes": {{
        "font": {{ "size": {font_size} }},
        "borderWidth": 1,
        "margin": {node_margin},
        "color": {{
          "border": "#9e9e9e",
          "background": "#e0e0e0",
          "highlight": {{ "border": "#757575", "background": "#eeeeee" }},
          "hover": {{ "border": "#757575", "background": "#eeeeee" }}
        }}
      }},
      "edges": {{
        "smooth": false,
        "color": {{ "color": "#bdbdbd" }}
      }},
      "physics": {{
        "barnesHut": {{
          "gravitationalConstant": -{repulsion},
          "springLength": {spring_length},
          "springConstant": 0.04,
          "damping": 0.12
        }},
        "stabilization": {{ "iterations": 150 }}
      }}
    }}
    """)

    for ip in ip_total.index:
        total = int(ip_total[ip])
        fan = int(ip_fanout[ip])
        row0 = d.loc[d[ip_col] == ip].iloc[0]
        asn = (row0.get(asn_col, "") or "") if asn_col else ""
        cc = (row0.get(country_col, "") or "") if country_col else ""

        label = f"{ip}\n{asn}\n{cc}\n{total} events\n{fan} users"
        title = f"<b>IP</b>: {ip}<br><b>ASN</b>: {asn}<br><b>Country</b>: {cc}<br><b>Total events</b>: {total}<br><b>Distinct users</b>: {fan}"

        color = {
            "border": "#616161",
            "background": "#9e9e9e",
            "highlight": {"border": "#424242", "background": "#bdbdbd"},
            "hover": {"border": "#424242", "background": "#bdbdbd"},
        }
        if fan > 1:
            color = {
                "border": "#b71c1c",
                "background": "#e53935",
                "highlight": {"border": "#7f0000", "background": "#ef5350"},
                "hover": {"border": "#7f0000", "background": "#ef5350"},
            }

        net.add_node(f"ip:{ip}", label=label, title=title, shape="dot", size=18 + total**0.5, color=color)

    for u in user_total.index:
        total = int(user_total[u])
        fan = int(user_fanout[u])
        label = f"{u}\n{total} events\n{fan} IPs"
        title = f"<b>User</b>: {u}<br><b>Total events</b>: {total}<br><b>Distinct IPs</b>: {fan}"

        net.add_node(
            f"user:{u}",
            label=label,
            title=title,
            shape="box",
            size=18 + total**0.5,
            color={
                "border": "#9e9e9e",
                "background": "#e0e0e0",
                "highlight": {"border": "#757575", "background": "#eeeeee"},
                "hover": {"border": "#757575", "background": "#eeeeee"},
            },
        )

    for _, r in d.iterrows():
        net.add_edge(f"ip:{r[ip_col]}", f"user:{r[user_col]}", value=int(r[count_col]), title=f"<b>Events</b>: {int(r[count_col])}")

    return net.generate_html(notebook=False)
