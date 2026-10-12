# Server Request Anomaly Detection

This project detects statistically atypical request sessions in application route logs. The active model uses a conditional request probability model and an AEP deviation score. An alert indicates behavior that is unusual relative to the fitted normal data; it does not establish malicious intent.

## Current model

The pipeline parses route logs, preserves parse statistics, normalizes dynamic path identifiers, maps paths to route groups, applies a reviewed application-route allowlist, and groups events into chronological sessions by client IP. A request is represented by its URL group and status category. The configured probability model estimates:

```text
P(request) = P(url_group) × P(status_category | url_group)
```

Additive smoothing (`request_probability.smoothing`, currently `0.5`) gives unseen categories nonzero probability. An explicit unknown category is used for future URL groups and status categories. For each request, the information cost is:

```text
cost = -log₂ P(url_group) - log₂ P(status_category | url_group)
```

For a session of `n` requests, normalized self-information is the mean request cost, in bits per request:

```text
Z = (sum of request costs) / n
```

The reference information level is the model's expected per-request information, calculated from the learned URL-group probabilities and conditional status probabilities. The AEP deviation is:

```text
A = |Z - H_ref|
```

The model classifies a session as anomalous when its AEP deviation exceeds the threshold. The threshold is the configured validation quantile (`aep.quantile`, currently `0.9`) and is calibrated on Validate data, then held fixed for Test and live scoring.

## Data and session settings

The default folders are configured in `config/default.yaml`:

```text
Data/Train/       Fit request probabilities on curated normal traffic
Data/Validate/    Calibrate the AEP threshold
Data/Test/        Held-out evaluation
```

The checked-in configuration uses IP sessions with a 60-second inactivity timeout, a minimum of three requests, and `unknown` as the group for requests without an IP. Events are ordered by timestamp before session formation. Curation uses the exact route and route-name inventory in the configuration. Unlisted requests are held for review and excluded from normal fitting; when session control is enabled, an entire IP session is excluded if it contains an unlisted request.

The parser retains malformed input for debugging and reports skipped-line statistics. Dynamic identifiers are normalized to reduce unnecessary route categories. Prepared events retain their timestamps, source information, and readable state descriptions. The saved model uses the same configured preprocessing for training, evaluation, uploads, and live monitoring.

## Build and evaluate

Run these commands from the repository root:

```powershell
python -m src.aep_anomaly curate --input-dir Data/Train --output-dir Data/processed/Train
python -m src.aep_anomaly build
python -m src.aep_anomaly evaluate
```

`build` fits the configured probability model using curated Train data and calibrates the AEP threshold with Validate data. `evaluate` scores the separate Test data. The model bundle is saved under `models/default/`; the held-out report and per-session scores are written under `reports/evaluation/`.

## Latest evaluation result

The checked-in evaluation report was produced on 2026-10-12 for the saved `independent_marginals` model bundle. It scored 95 held-out IP sessions. A session is labeled positive for this evaluation if it contains at least one request outside the configured application route allowlist. This proxy produced 60 positive and 35 negative sessions; 3,110 requests were outside the allowlist. These labels reflect route inventory membership, not independently confirmed attacks.

| Measure | AEP result |
| --- | ---: |
| True positives | 54 / 60 |
| True negatives | 33 / 35 |
| False positives | 2 |
| False negatives | 6 |
| Precision | 96.4% |
| Recall / anomaly catch rate | 90.0% |
| F1 | 93.1% |
| False-positive rate | 5.7% |
| ROC-AUC | 0.975 |
| PR-AUC | 0.985 |

The report's project-specific final score is `TP / (positive sessions + false alarms)`, which is `54 / (60 + 2) = 87.1%`. Threshold calibration used Validate data; Test data was held out for this report. These values describe this dataset and saved model and may change when the data, route inventory, or configuration changes.

## Outputs and explanation

Each scored session retains its time range, client IP, original request events, encoded request descriptions, event count, log probability, normalized information score, reference information level, AEP deviation, threshold, anomaly decision, and details of unknown categories. This supports reviewing why a session was flagged and which requests contributed unusual information costs.

The project also includes a local dashboard and continuous log monitoring. Start the API with:

```powershell
python -m src.aep_anomaly serve
```

Start monitoring a log directory with:

```powershell
python -m src.aep_anomaly monitor --watch-dir Data/live --model-dir models/default --database Data/alerts.sqlite3 --interval 1
```

The frontend is in `frontend/`. The monitor groups requests by IP and inactivity timeout, scores updated sessions, and persists alerts in SQLite.

## Limitations

- Finite datasets do not perfectly satisfy asymptotic assumptions.
- Server traffic can be non-stationary, and user behavior can drift.
- Route normalization and grouping affect the learned probability model.
- Rare legitimate activity can produce false positives.
- The evaluation labels are based on the configured route allowlist and are not ground-truth attack labels.
- Statistically anomalous behavior is not necessarily malicious.
