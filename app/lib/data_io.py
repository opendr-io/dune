"""Loading and light introspection helpers for CloudTrail-style log dataframes."""

from __future__ import annotations

import numpy as np
import pandas as pd

UNHASHABLE_TYPES = (list, tuple, dict, np.ndarray)


def load_dataframe(uploaded_file=None, path: str | None = None) -> pd.DataFrame:
    """Load a dataframe from an uploaded file (Streamlit UploadedFile) or a
    filesystem/Volume path. Supports parquet and csv."""
    if uploaded_file is not None:
        name = uploaded_file.name.lower()
        if name.endswith(".parquet"):
            return pd.read_parquet(uploaded_file)
        if name.endswith(".csv"):
            return pd.read_csv(uploaded_file, low_memory=False)
        raise ValueError(f"Unsupported file type: {uploaded_file.name}")

    if path:
        lower = path.strip().lower()
        if lower.endswith(".parquet"):
            return pd.read_parquet(path)
        if lower.endswith(".csv"):
            return pd.read_csv(path, low_memory=False)
        raise ValueError(f"Unsupported file type: {path}")

    raise ValueError("Provide either an uploaded file or a path")


def scalar_columns(df: pd.DataFrame) -> list[str]:
    """Columns that hold hashable scalars (list/array/dict-valued columns,
    e.g. CloudTrail's `resources`, are dropped since they can't be encoded
    or grouped-by directly)."""
    cols = []
    for c in df.columns:
        if not df[c].map(lambda v: isinstance(v, UNHASHABLE_TYPES)).any():
            cols.append(c)
    return cols


def cardinality_table(df: pd.DataFrame) -> pd.Series:
    """Distinct-value counts per scalar column, descending."""
    cols = scalar_columns(df)
    return df[cols].nunique(dropna=True).sort_values(ascending=False)


def encode_categoricals(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """Integer-code the given columns (category codes), leaving the rest untouched."""
    encoded = df.copy()
    for col in columns:
        encoded[col] = encoded[col].astype("category")
        encoded[col] = encoded[col].cat.codes
    return encoded
