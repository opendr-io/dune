"""PyOD ensemble anomaly detection helpers (from pyod-mark-3)."""

from __future__ import annotations

import time

import numpy as np
import pandas as pd

# Models that ship without extra heavy dependencies (no torch needed).
CORE_MODEL_NAMES = [
    "CBLOF", "IForest", "KNN", "AvKNN", "LOF", "ROD", "CD",
    "COPOD", "ECOD", "GMM", "HBOS", "INNE", "LODA",
]

# Slower / heavier optional models. DIF and LUNAR require torch.
OPTIONAL_MODEL_NAMES = ["OCSVM", "KDE", "QMCD", "DIF", "LUNAR"]

ALL_MODEL_NAMES = CORE_MODEL_NAMES + OPTIONAL_MODEL_NAMES


def build_classifiers(
    contamination: float, random_state: np.random.RandomState, selected: list[str] | None = None
) -> tuple[dict, list[str]]:
    """Build the requested PyOD classifier instances. Returns (classifiers, unavailable)
    where `unavailable` lists any requested models that couldn't be imported
    (e.g. optional models when torch isn't installed)."""
    if selected is None:
        selected = CORE_MODEL_NAMES

    clf: dict = {}
    unavailable: list[str] = []

    def maybe(name: str, factory):
        if name not in selected:
            return
        try:
            clf[name] = factory()
        except Exception:
            unavailable.append(name)

    from pyod.models.cblof import CBLOF
    from pyod.models.cd import CD
    from pyod.models.copod import COPOD
    from pyod.models.ecod import ECOD
    from pyod.models.gmm import GMM
    from pyod.models.hbos import HBOS
    from pyod.models.iforest import IForest
    from pyod.models.inne import INNE
    from pyod.models.knn import KNN
    from pyod.models.loda import LODA
    from pyod.models.rod import ROD

    maybe("CBLOF", lambda: CBLOF(contamination=contamination, check_estimator=False, random_state=random_state))
    maybe("IForest", lambda: IForest(contamination=contamination, random_state=random_state))
    maybe("KNN", lambda: KNN(contamination=contamination))
    maybe("AvKNN", lambda: KNN(method="mean", contamination=contamination))
    maybe("LOF", lambda: __import__("pyod.models.lof", fromlist=["LOF"]).LOF(n_neighbors=35, contamination=contamination))
    maybe("ROD", lambda: ROD(contamination=contamination))
    maybe("CD", lambda: CD(contamination=contamination))
    maybe("COPOD", lambda: COPOD(contamination=contamination))
    maybe("ECOD", lambda: ECOD(contamination=contamination))
    maybe("GMM", lambda: GMM(contamination=contamination))
    maybe("HBOS", lambda: HBOS(contamination=contamination))
    maybe("INNE", lambda: INNE(contamination=contamination))
    maybe("LODA", lambda: LODA(contamination=contamination))

    # Optional / heavier models - imported lazily so a missing dependency
    # (e.g. torch for DIF/LUNAR) only disables that one model.
    maybe("OCSVM", lambda: __import__("pyod.models.ocsvm", fromlist=["OCSVM"]).OCSVM(contamination=contamination))
    maybe("KDE", lambda: __import__("pyod.models.kde", fromlist=["KDE"]).KDE(contamination=contamination))
    maybe("QMCD", lambda: __import__("pyod.models.qmcd", fromlist=["QMCD"]).QMCD(contamination=contamination))
    maybe("DIF", lambda: __import__("pyod.models.dif", fromlist=["DIF"]).DIF(contamination=contamination))
    maybe("LUNAR", lambda: __import__("pyod.models.lunar", fromlist=["LUNAR"]).LUNAR(contamination=contamination))

    return clf, unavailable


def _time_model(model, x: np.ndarray) -> float | None:
    """Time a single fit; returns None (rather than raising) if the model
    can't fit this particular sample, e.g. a clustering-based model failing
    on a too-small/degenerate sample during runtime estimation."""
    t0 = time.perf_counter()
    try:
        model.fit(x)
    except Exception:
        return None
    return time.perf_counter() - t0


def forecast_runtimes(
    clf: dict, x: np.ndarray, sizes: tuple[int, ...] = (1000, 3000, 7000), repeats: int = 3, seed: int = 42
) -> pd.DataFrame:
    """Power-law runtime extrapolation per classifier, as in pyod-mark-3's estimator cell."""
    rng = np.random.default_rng(seed)
    n_full = len(x)
    sample_n = min(max(1000, int(n_full * 0.10)), n_full)
    idx_sample = rng.choice(n_full, size=sample_n, replace=False)
    x_sample = x[idx_sample]

    rows = []
    for name, model in clf.items():
        results = []
        seen_sizes = set()
        for s in sizes:
            s = min(s, len(x_sample))
            if s < 10 or s in seen_sizes:
                continue
            seen_sizes.add(s)
            times = []
            for _ in range(repeats):
                idx = rng.choice(len(x_sample), size=s, replace=False)
                t = _time_model(model, x_sample[idx])
                if t is not None:
                    times.append(t)
            if times:
                results.append((s, float(np.median(times))))

        fixed, last_t = [], 0.0
        for s, t in sorted(results):
            t = max(t, last_t)
            fixed.append((s, t))
            last_t = t

        if len(fixed) < 2:
            # Not enough successful sample fits to extrapolate from (e.g. the
            # model failed on every attempt, or the dataset is too small for
            # multiple distinct sample sizes) - report unknown rather than 0s,
            # which would wrongly look "fast" and skip the exclusion check.
            rows.append({"model": name, "predicted_seconds": float("nan")})
            continue

        ns = np.array([p[0] for p in fixed], dtype=float)
        ts = np.array([p[1] for p in fixed], dtype=float)
        b, loga = np.polyfit(np.log(ns), np.log(ts + 1e-9), 1)
        b = max(b, 0.0)
        a = np.exp(loga)
        t_pred = a * (n_full**b)
        rows.append({"model": name, "predicted_seconds": t_pred})

    return pd.DataFrame(rows).sort_values("predicted_seconds", ascending=False).reset_index(drop=True)


def run_ensemble(
    df_encoded: pd.DataFrame,
    columns: list[str],
    clf: dict,
    max_seconds: float | None = None,
    predicted_times: dict[str, float] | None = None,
    progress_cb=None,
) -> tuple[pd.DataFrame, list[str], list[str]]:
    """Fit each classifier and add an `out_<model>` outlier-vote column plus a
    `rank` column (sum of votes). Returns (result_df, failed_models, excluded_models)."""
    x = df_encoded.loc[:, columns].values
    result = df_encoded.copy()

    excluded = []
    clf_to_run = dict(clf)
    if max_seconds is not None and predicted_times:
        for name in list(clf_to_run):
            if predicted_times.get(name, 0.0) > max_seconds:
                excluded.append(name)
                clf_to_run.pop(name, None)

    failed = []
    for name in clf_to_run:
        result[f"out_{name}"] = np.nan

    for i, (name, model) in enumerate(clf_to_run.items()):
        if progress_cb:
            progress_cb(i, len(clf_to_run), name)
        try:
            model.fit(x)
            result[f"out_{name}"] = model.predict(x)
        except Exception:
            failed.append(name)

    out_cols = [f"out_{n}" for n in clf_to_run if f"out_{n}" in result.columns]
    result["rank"] = result[out_cols].sum(axis=1)
    return result, failed, excluded
