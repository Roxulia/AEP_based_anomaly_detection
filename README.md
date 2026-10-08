# Server Statistical Anomaly Detection

This project analyzes server request logs with a first-order Markov sequence model, entropy rate, AEP deviation, and KDE-based information-score density. The output describes activity that is statistically atypical under the fitted detector; it does not establish malicious intent and is not a generic machine-learning classifier.

## Dataset folders

The default locations are configurable in `config/default.yaml` and are placeholders until you add the datasets:

```text
Data/Train/       # fit transition probabilities, entropy rate, and KDE
Data/Validate/    # calibrate AEP and density thresholds
Data/Test/        # held-out evaluation only
```

The folders are used as provided. The folder workflow does not split them again. Raw route logs should use the supported `routes-*.log` format. The parser preserves malformed lines in its parsed CSV and reports parsing/preprocessing counts.

## Build and evaluate

From the repository root, activate the Python environment and run:

```powershell
python -m src.aep_anomaly build
python -m src.aep_anomaly evaluate
```

`build` fits the statistical detector using Train and calibrates thresholds from Validate. It saves `models/default/model.json` and `models/default/density.pkl`, plus prepared CSV files under `Data/processed/`. `evaluate` scores the separate Test folder in AEP-only, density-only, and hybrid modes and writes `reports/evaluation/evaluation.json` and one JSONL file per detector mode. If test windows do not contain usable ground-truth labels, the report marks classification metrics unavailable while still reporting scoreable/outlier window counts.

Override configured folders when needed:

```powershell
python -m src.aep_anomaly build --train-dir Data/Train --validate-dir Data/Validate
python -m src.aep_anomaly evaluate --test-dir Data/Test
```

Existing `parse`, CSV `train`, and `detect` CLI commands remain available for direct pipeline use. `train` retains its legacy chronological split behavior; use `build` for the separate-folder workflow above.

## Dashboard and experiments

Install API dependencies with `pip install -r requirements.txt`, then run the local API:

```powershell
python -m src.aep_anomaly serve
```

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal. The dashboard shows dataset readiness, detector composition, evaluation comparisons, and persisted alerts. The Experiments page accepts raw `.log` or `.txt` files in the supported request-log format and scores them with the saved detector. API paths can be configured with `AEP_CONFIG`, `AEP_MODEL_DIR`, `AEP_WATCH_DIR`, `AEP_ALERT_DB`, and frontend `VITE_API_URL`.

## Continuous monitoring

Place route log files named `routes-*.log` in the watched folder (default `Data/live`). Start the poller after building the detector:

```powershell
python -m src.aep_anomaly monitor --watch-dir Data/live --model-dir models/default --database Data/alerts.sqlite3
```

The monitor polls appended and rotated files, retains partial final lines until complete, builds fixed-count windows, preserves malformed lines in its SQLite skipped-line ledger, and stores anomalous or unscorable windows in SQLite. The API exposes alert listing and acknowledgement; the dashboard refreshes alert data every ten seconds and can request a one-time scan. Continuous monitoring currently uses fixed-count windows. Direct hosted-site ingestion and external notification services are future extensions.

## Statistical outputs

Per-window results include normalized self-information, entropy rate, AEP deviation and threshold, KDE information-score density and threshold, detector decision, source events, and least-probable transitions. Unknown states are reported as unscorable rather than mapped to existing states. Model and density artifacts should be loaded only from trusted sources because the KDE wrapper is stored using Python pickle.

Request states use `(HTTP method, URL group, status category)`. URL groups retain API namespace/resource families and common two-segment route families, while known credential, source-control, CMS, system-file, and path-traversal probes receive dedicated security groups. Status categories distinguish success, redirects, authentication failures, not-found responses, rate limits, other client errors, server errors, and unknown/informational outcomes. Prepared CSVs retain `normalized_uri` and `status_class` for inspection and add `url_group` and `status_category` for modeling. Rebuild the model after changing this state encoding; prior model bundles are rejected to prevent silently scoring with mismatched states.
