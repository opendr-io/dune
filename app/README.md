# DUNE Threat Hunter (Databricks App)

A [Databricks App](https://docs.databricks.com/en/dev-tools/databricks-apps/index.html)
version of the four DUNE threat-hunting notebooks in the parent
[Databricks-Notebooks](..) folder. It's a multi-page Streamlit app: load a
CloudTrail-style (or any tabular log) dataset once on the home page, then use
the sidebar to run clustering/ensemble anomaly detection and explore results
interactively, instead of editing notebook cells by hand.

Part of the [DUNE project](https://github.com/opendr-io/dune).

## Pages

| Page | Notebook it replaces | What it does |
|---|---|---|
| `app.py` (Home) | — | Load a CSV/Parquet file (upload or a workspace/Volume path), preview it, and see column cardinality. |
| `1_Silhouette_Analysis.py` | `silhouettes-mark-3.ipynb` | Grid-search candidate cluster counts and plot silhouette scores to pick a good `k`. The chosen `k` is carried over to K-Means Detection. |
| `2_KMeans_Detection.py` | `kmeans-mark-3.ipynb` | Encode chosen columns, scale, PCA-reduce, fit K-Means, and flag rows far from their nearest centroid (by percentile of distance) as anomalies. Includes the notebook's runtime estimator for `default`/`safe`/`minibatch` KMeans modes. |
| `3_PyOD_Ensemble.py` | `pyod-mark-3.ipynb` | Fit a panel of [PyOD](https://github.com/yzhao062/pyod) outlier detectors (CBLOF, IForest, KNN, LOF, COPOD, ECOD, GMM, HBOS, INNE, LODA, ROD, CD, plus optional OCSVM/KDE/QMCD/DIF/LUNAR) and rank rows by how many models vote them an outlier. Includes the notebook's per-model runtime forecaster and a model-agreement heatmap. |
| `4_Explorer.py` | `viewer-mark-3.ipynb` | Group-by/aggregate, dropdown filtering, and an interactive IP↔user relationship graph (via `pyvis`) with optional RDAP/whois enrichment, over the raw data or any scored output. |

Shared logic lives in `lib/` (`data_io.py`, `kmeans_utils.py`, `pyod_utils.py`,
`ip_enrich.py`, `network_graph.py`) so the Streamlit pages stay thin.

## Data expectations

Any tabular dataset works, but the defaults (candidate columns, ID column
`eventID`) are tuned for AWS CloudTrail logs, matching the source notebooks.
List/array/dict-valued columns (e.g. CloudTrail's `resources`) are
automatically excluded from encoding, grouping, and filtering since they
aren't hashable.

## Deploying app to Databricks

```bash
databricks apps create dune-threat-hunter
databricks sync . /Workspace/Users/<you>/dune-threat-hunter/app --watch  # from the app/ folder
databricks apps deploy dune-threat-hunter --source-code-path /Workspace/Users/<you>/dune-threat-hunter/app
```

To read data straight from a Unity Catalog Volume instead of uploading a
file, grant the app's service principal read access to the Volume and enter
its path (e.g. `/Volumes/catalog/schema/volume/cloudtrail.parquet`) on the
home page.

### Using App From Databricks
After deploying, you can reach the app's UI two ways:

In the workspace UI:

Open your Databricks workspace in the browser.
In the left sidebar, go to Compute → Apps (in some workspace versions it's just Apps).
Click your app (dune-threat-hunter). Its detail page shows a URL/Open App button — click it to launch the Streamlit UI in a new tab.
Via CLI (to get the URL directly):

```bash
databricks apps get dune-threat-hunter
```

The response includes a url field (something like https://dune-threat-hunter-<workspace-id>.<region>.databricksapps.com) — open that directly.

Notes:

* The app only responds once its status is RUNNING (check via the same apps get call or the UI status badge) — it takes a minute or so to start after databricks apps deploy.
* Access is governed by workspace permissions: by default only you (the creator) can open it. To let others in, grant them Can Use on the app from its Permissions tab in the UI, or via databricks apps set-permissions.
* It runs inside an iframe/tab in the workspace or as a standalone browser tab depending on how you open it — either way it's the same Streamlit app you tested locally.

## Notes

- **Optional models**: `DIF` and `LUNAR` in the PyOD Ensemble page need
  `torch`. If it isn't installed, those two models are skipped automatically
  and reported as unavailable rather than crashing the run.
- **RDAP/whois enrichment** in the Explorer page makes live network lookups
  and is capped (default 10) to keep the app responsive; it's off by default.
- Large K-Means/PyOD runs can be slow on high-cardinality columns or big
  row counts — use the runtime estimator buttons on those pages before
  committing to a full run, same as the notebooks' "Estimator" cells.
