# Server Statistical Anomaly Detection

This project analyzes server request logs with interpretable probability models, normalized self-information, AEP deviation, and KDE-based information-score density. The current checked-in configuration uses independent URL-group and status-category marginals (`markov.enabled: false`); the first-order Markov implementation remains available as a configurable alternative. The output describes activity that is statistically atypical under the fitted detector; it does not establish malicious intent.

## Current model structure

The Python pipeline is organized by responsibility:

```text
src/aep_anomaly/
  log_parser.py        Parse raw application route logs and retain parse statistics
  route_normalizer.py  Normalize dynamic URI segments
  route_grouper.py     Map normalized paths to route families
  event_encoder.py     Encode selected request fields as deterministic state IDs
  curation.py          Apply the reviewed application route allowlist
  windowing.py         Sort events and form IP sessions or fixed windows
  independent.py       Score URL/status marginals, joint pairs, or conditional status
  markov.py            Optional smoothed first-order chain and entropy-rate model
  aep.py               AEP deviation and validation-quantile threshold
  density.py           KDE of normalized self-information scores
  pipeline.py          Train, persist, load, score, evaluate, and log experiments
  monitor.py           Poll live log files and persist alerts
  api.py               Local dashboard API
  __main__.py          CLI commands
frontend/              Vite/React dashboard
config/default.yaml    Dataset, state, window, model, and threshold settings
models/default/        Persisted model.json and density.pkl (after build)
reports/evaluation/    Held-out evaluation JSON and per-method session scores
tests/                 Parser, preprocessing, core model, and workflow tests
```

The configured flow is: parse and preprocess request records; curate normal-route events; encode each request as `(url_group, status_category)`; group chronologically by IP into sessions; fit the selected probability model on Train; calibrate AEP, KDE, and hybrid thresholds on Validate; then score held-out Test sessions. The encoder keeps readable state descriptions alongside deterministic opaque IDs. A reserved unknown category handles unseen values explicitly. The raw request events and least-probable transitions/state costs are retained in per-session explanations.

With the current defaults, the request model estimates `P(url_group)P(status_category)` with additive smoothing. It does not learn sequence transitions. For each request it sums the two negative log probabilities, and averages those costs across its IP session to obtain normalized self-information `Z` in bits/request. The AEP reference is the sum of the two marginal entropies. The optional Markov model instead estimates initial and transition probabilities, scores sequences in log space, and uses the stationary entropy rate as its AEP reference. `request_probability.mode` also supports a joint URL/status distribution and `P(url_group)P(status_category|url_group)`.

The anomaly components remain separately interpretable: AEP uses `|Z - H_ref|`; KDE estimates the information-score density and scores `-ln(density + epsilon)`. Hybrid z-normalizes those scores using Train statistics and applies the configured weighted sum, with warning and critical thresholds calibrated on Validate data. `detector.method` selects the model's default decision, while evaluation always reports AEP, density, and hybrid comparisons.

Configuration values can change between runs. The sections below call out the current `config/default.yaml` values where they affect interpretation. Rebuild the saved bundle after changing state encoding, windowing, probability mode, or detector settings.

## Dataset folders

The default locations are configurable in `config/default.yaml` and are placeholders until you add the datasets:

```text
Data/Train/       # fit transition probabilities, entropy rate, and KDE
Data/Validate/    # calibrate AEP and density thresholds
Data/Test/        # held-out evaluation only
```

The folder workflow does not split the folders again. Raw route logs should use the supported `routes-*.log` format. The parser preserves malformed lines in its parsed CSV and reports parsing/preprocessing counts. Training always applies the exact application endpoint allowlist when `curation.enabled` is true. Validation applies it when `curation.apply_allowlist_to_validation: true` (default); set it to `false` to calibrate thresholds with all valid validation routes. Explicit `exclude_paths` and `exclude_route_names` are still applied in either mode. Allowlisted method/path pairs and route names go to `normal_route_events.csv`; unlisted requests go to `review_route_events.csv` and are excluded from fitting/calibration until explicitly added to the allowlist. Set `curation.session_control: true` (default) to exclude every request in an IP session if any request in that session is unlisted; `false` excludes only the unlisted requests. Sessions use `window.timeout_seconds` and `window.missing_ip`. `curation_decisions.csv` and `curation_manifest.json` record the decisions. Raw logs and the uncurated prepared CSV remain unchanged. Unlisted means “not approved for normal training,” not “confirmed malicious.”

State dimensions are configured with `state.fields` in `config/default.yaml`. The default is `[url_group, status_category]`: one state pairs a normalized URL group with its response category, such as `route.env → not_found` or `api.tenant.orders → server_error`. Markov transitions are learned between these paired request outcomes. Training, evaluation, uploads, and live monitoring use the same saved field selection. Reprocess and rebuild after changing this setting; older model bundles are rejected when their state-encoding version differs.

`markov.enabled` independently controls whether first-order transitions between paired request states are modeled. When it is `false`, `request_probability.mode` selects the per-request URL/status probability: `independent` uses `P(url_group)P(status_category)`, `joint` uses `P(url_group,status_category)`, and `status_given_url` uses `P(url_group)P(status_category|url_group)`. `request_probability.smoothing` controls additive smoothing for these per-request models; `markov.smoothing` applies only to the Markov model. The non-Markov models require both `url_group` and `status_category` in `state.fields`. Rebuild the model after changing these settings.

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

`build` fits the statistical detector using allowlisted Train requests and calibrates thresholds from Validate requests according to `curation.apply_allowlist_to_validation`. It saves `models/default/model.json` and `models/default/density.pkl`, plus prepared CSV files under `Data/processed/`. `evaluate` scores the original sessions in the separate Test folder and labels a request positive when it falls outside the exact application route allowlist. A session is positive when it contains at least one such request. Set `evaluation.counting_unit` to `session` (default) to count each positive session once, or `request` to count each unallowlisted request separately; session decisions are mapped to their requests in request mode. Reports compare AEP-only, density-only, and hybrid results. These allowlist-based labels are an evaluation proxy and do not establish malicious intent.

`detector.method` selects the model's decision method: `AEP`, `KDE`, or `HYBRID` (default `AEP`). Rebuild the model after changing it. Evaluation still reports all three methods for comparison. Hybrid uses ScoreFusion: it z-normalizes AEP deviation and KDE negative log-density using Train score means and standard deviations, then combines them as `alpha * AEP_norm + (1 - alpha) * KDE_norm`. Fused-score quantiles from the configured Validate partition set the WARNING and CRITICAL thresholds (`detector.hybrid.warning_quantile` and `critical_quantile`). Both severities create live alerts and set `final_anomalous`; NORMAL does not. `detector.hybrid.alpha` controls the AEP weight. Older model bundles without fusion calibration cannot score in hybrid mode.

## How a request window becomes an anomaly score

This section follows the configured pipeline from an HTTP request to the final decision. With the current configuration, `state.fields` is `[url_group, status_category]`, `markov.enabled` is `false`, `window.type` is `ip_session`, and `detector.method` is `AEP`. The Markov alternative and the KDE and HYBRID decision paths are described below as well.

### 1. Define one request state

The parser extracts the request timestamp, method, URI, status, and client IP when available. The encoder then normalizes each field before forming a state:

1. The method is uppercased; a missing method becomes `unknown`.
2. The URI query and fragment are removed. UUIDs, `{parameter}` segments, and numeric ID segments with at least six digits become `:id`; other path details are retained.
3. The normalized URI is mapped to a route family. API paths retain their first three segments, such as `/api/tenant/orders/:id` → `api.tenant.orders`. Other paths retain the first two segments; a single-segment route is named `route.<segment>`.
4. The status is grouped into an outcome: for example, 100–199 → `informational`, 200–299 → `success`, 300–399 → `redirect`, 401/403 → `auth_failure`, 404 → `not_found`, 429 → `rate_limited`, other 4xx → `client_error`, and 5xx → `server_error`. Missing or invalid status values become `unknown`.

The current fields therefore define the request state as:

```text
state = (url_group, status_category)
       = (api.tenant.orders, success)
```

If `method` is added to `state.fields`, the method becomes another state component. The selected fields are serialized deterministically and hashed into an opaque state ID. The readable state description is retained with the event; the hash itself has no numeric or ordering meaning. Rebuild after changing `state.fields` so training and scoring use the same definition.

### 2. Build a chronological session window

Events are ordered by timestamp and grouped by client IP. A new session starts when the gap between consecutive requests from that IP is greater than `window.timeout_seconds` (currently 60 seconds). Sessions with fewer than `window.min_events` (currently 3) are skipped. Missing IPs use the configured `unknown` group. The resulting ordered states are the sequence scored together:

```text
x₁, x₂, …, xₙ
```

During training, the route allowlist and session curation settings determine which Train and Validate events contribute to the normal model and calibration. Test events remain held out for evaluation. An unallowlisted route is an evaluation label/proxy; it is not automatically proof of malicious activity.

### 3. Calculate the normalized information score

`markov.enabled` selects transition modeling. When disabled, `request_probability.mode` selects the per-request probability model. Both model families use additive smoothing and reserve an explicit unknown category so future states do not silently become a known state.

**Current configuration: independent URL and status marginals.** The model counts URL groups and status categories separately. For feature value `v`, its smoothed probability is:

```text
P(v) = (count(v) + λ) / (N + λV)
```

Here `N` is the number of training requests, `V` is the number of categories including the reserved unknown category, and `λ` is the smoothing value. For request `i`, the information cost is:

```text
cᵢ = -log₂ P(url_groupᵢ) - log₂ P(status_categoryᵢ)
```

For a window of `n` requests, the summed log probability and normalized self-information are:

```text
log₂ P(window) = -Σᵢ cᵢ
Z = -log₂ P(window) / n = (Σᵢ cᵢ) / n   bits/request
```

This mode scores URL and status frequencies independently; it does not learn transitions or a joint URL/status probability. Set `request_probability.mode` to `joint` for a smoothed joint URL/status table, or `status_given_url` for `P(url_group)P(status_category|url_group)`. These settings apply when `markov.enabled` is false.

**When `markov.enabled: true`.** The encoder's request states are modeled as a first-order chain. With `M` states (including reserved `__UNK__`), initial and transition probabilities use additive smoothing:

```text
P(x₁) = (initial_count(x₁) + λ) / (number_of_training_sequences + λM)
P(xᵢ | xᵢ₋₁) = (transition_count(xᵢ₋₁, xᵢ) + λ)
                 / (outgoing_count(xᵢ₋₁) + λM)
log₂ P(window) = log₂ P(x₁) + Σᵢ₌₂ⁿ log₂ P(xᵢ | xᵢ₋₁)
Z = -log₂ P(window) / n
```

The model estimates the stationary distribution `π` of its transition matrix and its entropy rate:

```text
H_rate = -Σₛ π(s) Σₜ P(t | s) log₂ P(t | s)
```

For either probability model, scoring is done in log space. Any state not observed during fitting is scored through the reserved unknown symbol and reported as novel; it is not mapped to a familiar request state.

### 4. Calculate AEP deviation

The AEP anomaly score is the distance between the window information score and the model's normal information reference:

```text
A = |Z - H_ref|
```

`H_ref` is the Markov entropy rate when Markov mode is enabled. In the current independent-marginal mode it is the sum of the URL-group entropy and status-category entropy, in bits per request. The AEP threshold is the configured quantile (`aep.quantile`, currently 0.9) of these deviations on Validate windows:

```text
AEP anomaly ⇔ A > AEP_threshold
```

The threshold is fit on Validate data and then held fixed for Test and live scoring. Quantiles use linear interpolation between adjacent ordered validation scores.

### 5. Calculate the KDE information-score rarity

Gaussian KDE is fit to the normal Train window scores `Z`. For a scored window, it estimates the information-score density `f̂(Z)` and converts it to a rarity score:

```text
K = -ln(f̂(Z) + ε)
```

The current KDE bandwidth is `scott` and `ε` is `density.epsilon`. Larger `K` means the window's information score lies in a lower-density part of the learned normal distribution. The KDE threshold is the configured quantile (`density.quantile`, currently 0.9) of the Validate rarity scores, using the same linear interpolation rule:

```text
KDE anomaly ⇔ K > KDE_threshold
```

### 6. Apply the configured detector method

The saved model reads `detector.method` and uses that method for its default decision. The current default is `AEP`:

| `detector.method` | Decision |
| --- | --- |
| `AEP` | Anomalous when `A > AEP_threshold`. |
| `KDE` | Anomalous when `K > KDE_threshold`. |
| `HYBRID` | Normalize and fuse `A` and `K` with ScoreFusion, then classify the fused score. |

For HYBRID, the means and population standard deviations (`μA`, `σA`, `μK`, `σK`) are estimated from normal Train window scores. A zero standard deviation produces a normalized component score of zero. Validation fused scores then calibrate the two configured quantile thresholds:

```text
A_norm = (A - μA) / σA
K_norm = (K - μK) / σK
S = α × A_norm + (1 - α) × K_norm

if S ≥ τ₂:       CRITICAL
else if S ≥ τ₁:  WARNING
else:            NORMAL
```

`α` is `detector.hybrid.alpha` (currently 0.5), `τ₁` is the `warning_quantile` cutoff (currently 0.95), and `τ₂` is the `critical_quantile` cutoff (currently 0.99). Both WARNING and CRITICAL set `final_anomalous` and create/update a live alert; NORMAL does not. The alert retains the component scores, normalized scores, fused score, severity, thresholds, request events, and anomaly explanations. The evaluation command deliberately scores all three methods to compare them, regardless of which method is selected for the saved model's default operation.

The values above describe the configured procedure, not a claim that every atypical window is malicious. Route encoding, traffic drift, finite training data, the Markov assumption, and KDE bandwidth all affect the scores and can produce false positives or false negatives.

Override configured folders when needed:

```powershell
python -m src.aep_anomaly build --train-dir Data/Train --validate-dir Data/Validate
python -m src.aep_anomaly evaluate --test-dir Data/Test
```

Existing `parse`, CSV `train`, and `detect` CLI commands remain available for direct pipeline use. `train` retains its legacy chronological split behavior; use `build` for the separate-folder workflow above.

## Evaluation report for the current saved model

The checked-in report in [`reports/evaluation/evaluation.json`](reports/evaluation/evaluation.json) evaluates the saved `independent_marginals` model on 95 held-out Test IP sessions. The model bundle was created on 2026-10-12 and uses the current session settings (60-second inactivity timeout, minimum 3 requests). Evaluation labels a session positive if it contains at least one request outside the configured application route allowlist: 60 positive sessions and 35 negative sessions. At request level, 3,110 requests were unallowlisted. This is an operational proxy label based on route inventory, not an independently verified attack label.

| Method | Anomaly catch rate | False alarms | Final score |
| --- | ---: | ---: | ---: |
| AEP | 98.3% | 3 | 93.7% |
| DENSITY | 98.3% | 3 | 93.7% |
| HYBRID | 96.7% | 3 | 92.1% |

On the reported evaluation run, AEP and DENSITY each caught 98.3% of positive sessions and produced 3 false alarms; HYBRID caught 96.7% with the same number of false alarms. The CLI's final score is the project-specific `TP / (positive_units + false_alarms)` measure. Precision, recall, F1, false-positive rate, ROC-AUC, and PR-AUC remain available as secondary metrics in the JSON report. Thresholds were calibrated from Validate data; Test data was scored only for reporting.

### Evaluation calculations

The CLI evaluates at the configured counting unit (sessions by default). Let `TP` be labeled-positive units flagged anomalous, `FP` be labeled-negative units flagged anomalous, and `P` be all labeled-positive units. Then:

```text
Anomaly catch rate = TP / P
False alarms       = FP
Final score        = TP / (P + FP)
```

For this report, `P = 60`. AEP and DENSITY each have `TP = 59` and `FP = 3`, giving a catch rate of `59 / 60 = 98.3%` and final score `59 / (60 + 3) = 93.7%`. HYBRID has `TP = 58` and `FP = 3`, giving `58 / 60 = 96.7%` and `58 / (60 + 3) = 92.1%`. False alarms are a count of normal-labeled sessions classified as anomalous, not a percentage; the JSON report also includes the false alarm rate.

Per-method session scores and their explanations are in [`aep.jsonl`](reports/evaluation/aep.jsonl), [`density.jsonl`](reports/evaluation/density.jsonl), and [`hybrid.jsonl`](reports/evaluation/hybrid.jsonl). To regenerate the evaluation report with the current files and model, run `python -m src.aep_anomaly evaluate`. Results may change when the datasets, allowlist, configuration, or saved model changes. Treat these as dataset-specific results, not a guarantee of future detection performance.

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

Preprocessing assigns each extracted state a deterministic opaque string ID and stores a separate description containing the configured state fields. The default description is `(URL group, status category)`. Windowing consumes only those IDs. The Markov model does not interpret HTTP fields; it models the supplied symbols and maps unseen IDs to a generic reserved `UNK` symbol. Per-session results include client IP, event count, normalized self-information, entropy rate, AEP deviation and threshold, KDE information-score density and threshold, detector decision, source events, and least-probable transitions. Output separately records original unseen IDs and descriptions; novelty alone does not force an anomaly decision. Model and density artifacts should be loaded only from trusted sources because the KDE wrapper is stored using Python pickle.

The default state catalog describes `(URL group, status category)`. URL groups retain API namespace/resource families and common two-segment route families; they do not infer whether a request is legitimate or a probe. The explicit application endpoint allowlist controls which events are eligible for fitting and validation calibration. Status categories distinguish success, redirects, authentication failures, not-found responses, rate limits, other client errors, server errors, and unknown/informational outcomes. Prepared CSVs retain inspection columns and add `state_id` and `state_description`. Legacy prepared CSVs are upgraded in preprocessing; the windowing and statistical layers require state IDs. Rebuild the model after changing the state encoding; prior model bundles are rejected to prevent silently scoring with mismatched states.
