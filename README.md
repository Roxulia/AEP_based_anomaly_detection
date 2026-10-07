# AEP + Markov + Entropy-Density Server Anomaly Detection

## Parse logs

Activate the project virtual environment, then run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m src.aep_anomaly
```

The parser reads `Data/logs` and writes `routes.csv`, `controllers.csv`, and
`services.csv` under `Data/processed`. Override either directory with
`--input-dir` or `--output-dir`.

Each CSV keeps the original log line and includes a `parse_status` column.
Malformed lines remain in the output and are counted in the command summary.

## Core scoring classes

The reusable mathematical components are available from `src.aep_anomaly`:

- `MarkovModel` fits first-order transition and initial-state probabilities,
  exposes entropy rate, and scores a caller-provided sequence in log space.
- `AEPDetector` learns a deviation threshold from validation information scores
  and classifies scores against a supplied entropy rate.
- `InformationScoreDensity` fits a Gaussian KDE to normal information scores
  and returns density and negative log-density scores.

These classes do not read files, create windows, or call each other. For this
project, callers can represent a request as `(method, normalized_uri,
status_class)` and pass sequences of those states to `MarkovModel`.
