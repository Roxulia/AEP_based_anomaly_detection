# Server Statistical Anomaly Detection

This project analyzes server request logs with a first-order Markov sequence model, entropy rate, AEP deviation, and KDE-based information-score density. The output describes activity that is statistically atypical under the fitted detector; it does not establish malicious intent and is not a generic machine-learning classifier.

## Dataset folders

The default locations are configurable in `config/default.yaml` and are placeholders until you add the datasets:

```text
Data/Train/       # fit transition probabilities, entropy rate, and KDE
Data/Validate/    # calibrate AEP and density thresholds
Data/Test/        # held-out evaluation only
```

The folder workflow does not split the folders again. Raw route logs should use the supported `routes-*.log` format. The parser preserves malformed lines in its parsed CSV and reports parsing/preprocessing counts. Before fitting or validation calibration, preprocessing applies the exact application endpoint allowlist in `config/default.yaml`. Allowlisted method/path pairs and route names go to `normal_route_events.csv`; every unlisted endpoint goes to `review_route_events.csv` and is excluded from fitting/calibration until explicitly added to the allowlist. `curation_decisions.csv` and `curation_manifest.json` record the decisions. Raw logs and the uncurated prepared CSV remain unchanged. Unlisted means “not approved for normal training,” not “confirmed malicious.”

State dimensions are configured with `state.fields` in `config/default.yaml`. The default is `[method, url_group, status_category]`; for example, set it to `[method, url_group]` to omit response status from the state definition. Training, evaluation, uploads, and live monitoring use the same saved field selection. Reprocess and rebuild after changing this setting.

Every successful build and evaluation appends its configuration, model identity, dataset, and result summary to `reports/experiment_history.jsonl`. Set `AEP_EXPERIMENT_LOG` to choose another history file. To compare recorded model parameters and metrics, run:

```powershell
python scripts/summarize_experiments.py --mode hybrid --metric f1
```

The script writes `reports/experiment_summary.csv`, ranked by the chosen metric. Use an independent selection dataset when choosing parameters; keep the final Test dataset for final reporting.

Requests are grouped by client IP and sorted by timestamp. A session ends when the gap between consecutive requests exceeds `window.timeout_seconds` (default 60 seconds). Variable-length sessions are scored independently; `window.min_events` defaults to 1. Missing IPs share the configurable `window.missing_ip` group (`unknown` by default). These settings live in `config/default.yaml` and are recorded with each model. Rebuild the model after changing them so training, validation calibration, and scoring use the same session definition.

## Build and evaluate

From the repository root, activate the Python environment and run:

```powershell
python -m src.aep_anomaly curate --input-dir Data/Train --output-dir Data/processed/Train
python -m src.aep_anomaly build
python -m src.aep_anomaly evaluate
```

`curate` can be run independently to inspect the generated normal/review CSVs and decision manifest before fitting. The allowlist is the application inventory in `config/default.yaml`; add a route only after confirming it belongs to the application.

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

The repository includes an empty starter file at `Data/live/routes-live.log`. Append route log entries to this file (or another `routes-*.log` file in `Data/live`) and start the poller after building the detector:

```powershell
python -m src.aep_anomaly monitor --watch-dir Data/live --model-dir models/default --database Data/alerts.sqlite3 --interval 1
```

The API creates the default live file at startup if it is missing. The dashboard shows its path. The monitor polls appended and rotated files every second and scores each complete request line immediately. It keeps a rolling request history per IP: a request within the configured inactivity timeout is appended and the full session is rescored; a later request after that timeout starts a new session. An anomalous session creates an alert, and subsequent requests update that same alert as the score changes; it resolves when the latest score is normal or a new session begins. Partial final lines wait until completed, while malformed and excluded application-route lines are retained in the SQLite skipped-line ledger. The API exposes alert listing and acknowledgement; the dashboard refreshes alert data every second and can request a one-time scan. Set `AEP_WATCH_FILE` to choose a different live file or `AEP_WATCH_DIR` to change its folder. Direct hosted-site ingestion and external notification services are future extensions.

Append lines using the application's route log format, for example:

```text
[2026-10-10 10:00:00] production.INFO: Route request completed. {"method":"GET","route_name":"dashboard","uri":"/dashboard","status":200,"ip":"192.0.2.10"}
```

## Statistical outputs

Preprocessing assigns each extracted state a deterministic opaque string ID and stores a separate description containing the configured state fields. The default description is `(method, URL group, status category)`. Windowing consumes only those IDs. The Markov model does not interpret HTTP fields; it models the supplied symbols and maps unseen IDs to a generic reserved `UNK` symbol. Per-session results include client IP, event count, normalized self-information, entropy rate, AEP deviation and threshold, KDE information-score density and threshold, detector decision, source events, and least-probable transitions. Output separately records original unseen IDs and descriptions; novelty alone does not force an anomaly decision. Model and density artifacts should be loaded only from trusted sources because the KDE wrapper is stored using Python pickle.

The default state catalog describes `(HTTP method, URL group, status category)`. URL groups retain API namespace/resource families and common two-segment route families; they do not infer whether a request is legitimate or a probe. The explicit application endpoint allowlist controls which events are eligible for fitting and validation calibration. Status categories distinguish success, redirects, authentication failures, not-found responses, rate limits, other client errors, server errors, and unknown/informational outcomes. Prepared CSVs retain inspection columns and add `state_id` and `state_description`. Legacy prepared CSVs are upgraded in preprocessing; the windowing and statistical layers require state IDs. Rebuild the model after changing the state encoding; prior model bundles are rejected to prevent silently scoring with mismatched states.
