# AEP + Markov + Entropy-Density Server Anomaly Detection

## Workflow

Run commands from the repository root (activate `.venv` first if used):

```powershell
python -m src.aep_anomaly parse --input-dir Data/logs --output-dir Data/processed
python -c "from src.aep_anomaly import RoutePreprocessor; RoutePreprocessor().process_csv('Data/processed/routes.csv', 'Data/processed/route_events.csv')"
python -m src.aep_anomaly train --input-csv Data/processed/route_events.csv --model-dir models/default --config config/default.yaml
python -m src.aep_anomaly detect --input-csv Data/processed/route_events.csv --model-dir models/default --output Data/processed/detections.jsonl
```

The no-argument command remains equivalent to `parse`. Parsing preserves raw
lines and reports malformed entries. Preprocessing keeps valid route events,
normalizes routes, and orders them by timestamp. Training and detection consume
that preprocessed event CSV.

## Training and detection behavior

`config/default.yaml` selects non-overlapping 50-event windows and a chronological
65% training / 15% validation / 20% testing split. Incomplete final windows are
excluded. Set `window.type` to `fixed_time` and `window.size` to a duration in
seconds for time windows. Models and KDE are fit on training windows; AEP and
density thresholds are learned from validation windows. The test partition is
reserved and is not used for fitting or thresholds.

The default `hybrid` mode flags a window when either AEP deviation or
information-score density flags it. Use `aep` or `density` for individual
detectors. Each JSONL detection row includes the events and encoded states,
Markov log probability, information score, entropy rate, both detector scores
and thresholds, component decisions, final decision, and least-probable
transitions. A state not present during training raises an explicit error.

The model bundle contains `model.json` (versioned configuration, state mapping,
Markov probabilities, thresholds, and split counts) and `density.pkl` (the fitted
SciPy KDE wrapper). Only load pickle artifacts from trusted sources.

## Reusable components

`MarkovModel`, `AEPDetector`, `InformationScoreDensity`, `load_windows`,
`chronological_split`, `train_model`, and `TrainedDetector` are available from
`src.aep_anomaly`. Markov probabilities and sequence likelihoods use log-space
scoring; encoded request states are `(method, normalized_uri, status_class)`.
