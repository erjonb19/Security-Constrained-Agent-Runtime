"""
aiops_panel.py
==============
AIOps panel for the governed Medicare agent. Reads the runtime's audit logs and
surfaces the signals that prove production thinking: allow vs deny, what each
control blocked, latency, and the recent decision feed.

Run from the repo root with venv311 active:
    pip install streamlit pandas
    streamlit run aiops_panel.py
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from aiops_metrics import load_events, build_records, summarize

st.set_page_config(page_title="Medicare Agent — Governance & AIOps", layout="wide")
st.title("Medicare Agent — Governance & AIOps")
st.caption("Every agent action passes through policy, SQL guard, groundedness, and taint. "
           "This panel reads the runtime's audit log.")

LOG_DIR = "logs"

rows = build_records(load_events(LOG_DIR))
if not rows:
    st.warning("No audit events found in logs/. Generate some with:  python aiops_demo_run.py")
    st.stop()

df = pd.DataFrame(rows)
s = summarize(rows)

# ---- KPI row -------------------------------------------------------------
k = st.columns(6)
k[0].metric("Total calls", s["total_calls"])
k[1].metric("Allow rate", f"{s['allow_rate']*100:.0f}%")
k[2].metric("Denied", s["denied"])
k[3].metric("Guard blocks", s["guard_blocks"])
k[4].metric("Groundedness blocks", s["groundedness_blocks"])
k[5].metric("Taint blocks", s["taint_blocks"])

st.divider()

# ---- outcome breakdown + latency ----------------------------------------
left, right = st.columns(2)

with left:
    st.subheader("Outcomes by control")
    counts = df["category"].value_counts().rename_axis("category").reset_index(name="count")
    st.bar_chart(counts, x="category", y="count", height=300)

with right:
    st.subheader("Avg latency by capability (ms)")
    lat = (df.dropna(subset=["latency_ms"])
             .groupby("capability")["latency_ms"].mean()
             .reset_index())
    if len(lat):
        st.bar_chart(lat, x="capability", y="latency_ms", height=300)
    else:
        st.info("No latency recorded yet.")

st.divider()

# ---- decisions over time -------------------------------------------------
st.subheader("Decisions over time")
ts = df.dropna(subset=["timestamp"]).copy()
if len(ts):
    ts["second"] = ts["timestamp"].dt.floor("s")
    ts["outcome"] = ts["allowed"].map({True: "allowed", False: "denied"})
    pivot = (ts.groupby(["second", "outcome"]).size()
               .unstack(fill_value=0).reset_index().set_index("second"))
    st.line_chart(pivot, height=280)
else:
    st.info("No timestamps to plot.")

st.divider()

# ---- recent decision feed ------------------------------------------------
st.subheader("Recent decisions")
feed = df[["timestamp", "capability", "category", "reason"]].tail(25).iloc[::-1]
st.dataframe(feed, use_container_width=True, hide_index=True)
