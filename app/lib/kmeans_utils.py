"""K-means anomaly detection helpers (from kmeans-mark-3 / silhouettes-mark-3)."""

from __future__ import annotations

import time

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans, MiniBatchKMeans
from sklearn.decomposition import PCA
from sklearn.metrics import pairwise_distances_argmin_min, silhouette_score
from sklearn.preprocessing import StandardScaler


def standardize(df: pd.DataFrame, columns: list[str]) -> np.ndarray:
    return StandardScaler().fit_transform(df.loc[:, columns].values)


def pca_reduce(x: np.ndarray, n_components: int = 2) -> tuple[np.ndarray, PCA]:
    pca = PCA(n_components=n_components)
    return pca.fit_transform(x), pca


def silhouette_search(
    x_scaled: np.ndarray,
    k_values: list[int],
    sample_size: int = 5000,
    silhouette_sample: int = 2000,
    seed: int = 42,
) -> pd.DataFrame:
    """Fit KMeans for each candidate k on a sample and score with silhouette.
    Mirrors silhouettes-mark-3's grid search. Returns a k/score dataframe."""
    rng = np.random.default_rng(seed)
    n = len(x_scaled)
    n_sample = min(sample_size, n)
    idx = rng.choice(n, size=n_sample, replace=False)
    x_search = x_scaled[idx]

    rows = []
    for k in k_values:
        km = KMeans(n_clusters=k, n_init=3, max_iter=100, algorithm="elkan", random_state=seed)
        labels = km.fit_predict(x_search)
        score = silhouette_score(
            x_search, labels, sample_size=min(silhouette_sample, len(x_search)), random_state=seed
        )
        rows.append({"k": k, "silhouette_score": score})

    return pd.DataFrame(rows)


def _time_fit(model, x: np.ndarray) -> float:
    t0 = time.perf_counter()
    model.fit(x)
    return time.perf_counter() - t0


def forecast_kmeans_runtime(
    x: np.ndarray, k: int, sizes: tuple[int, ...] = (2000, 5000), seed: int = 42
) -> dict[str, tuple[float | None, list[tuple[int, float]]]]:
    """Extrapolate fit time for 'default', 'safe' and 'minibatch' KMeans modes
    by timing fits on small samples and fitting a power law, as in
    kmeans-mark-3's runtime estimator cell."""
    n_full = len(x)
    rng = np.random.default_rng(seed)

    candidates = {
        "default": lambda: KMeans(n_clusters=k, random_state=seed),
        "safe": lambda: KMeans(
            n_clusters=k, init="k-means++", n_init=3, max_iter=100, algorithm="elkan", random_state=seed
        ),
        "minibatch": lambda: MiniBatchKMeans(
            n_clusters=k, batch_size=2048, n_init=3, max_iter=100, random_state=seed
        ),
    }

    results = {}
    for name, make_model in candidates.items():
        samples = []
        seen_sizes = set()
        for s in sizes:
            s = min(s, n_full)
            if s < 50 or s in seen_sizes:
                continue
            seen_sizes.add(s)
            idx = rng.choice(n_full, size=s, replace=False)
            t = _time_fit(make_model(), x[idx])
            samples.append((s, t))

        if not samples:
            results[name] = (None, samples)
            continue

        if len(samples) < 2:
            # Only one distinct sample size was available (e.g. the dataset is
            # smaller than every requested size). If that size already covers
            # the whole dataset, the timed run *is* the answer - no need to
            # extrapolate (and extrapolating from a single point divides by
            # log(1) = 0).
            s, t = samples[0]
            results[name] = (t if s >= n_full else None, samples)
            continue

        (n1, t1), (n2, t2) = samples[0], samples[-1]
        b = np.log(max(t2, 1e-9) / max(t1, 1e-9)) / np.log(n2 / n1)
        a = t1 / (n1**b)
        t_pred = a * (n_full**b)
        results[name] = (t_pred, samples)

    return results


def fit_kmeans(x: np.ndarray, k: int, mode: str = "default", seed: int = 42):
    if mode == "safe":
        model = KMeans(n_clusters=k, init="k-means++", n_init=3, max_iter=100, algorithm="elkan", random_state=seed)
    elif mode == "minibatch":
        model = MiniBatchKMeans(n_clusters=k, batch_size=2048, n_init=3, max_iter=100, random_state=seed)
    else:
        model = KMeans(n_clusters=k, random_state=seed)
    model.fit(x)
    return model


def detect_anomalies(x: np.ndarray, model, percentile: float = 99.0) -> tuple[np.ndarray, np.ndarray, float]:
    """Distance-to-nearest-centroid outlier detection. Returns
    (cluster_labels, anomaly_indices, distance_threshold)."""
    clusters = model.predict(x)
    distances = pairwise_distances_argmin_min(x, model.cluster_centers_)[1]
    threshold = float(np.percentile(distances, percentile))
    anomaly_indices = np.where(distances > threshold)[0]
    return clusters, anomaly_indices, threshold
