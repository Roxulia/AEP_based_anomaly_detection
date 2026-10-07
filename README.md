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
