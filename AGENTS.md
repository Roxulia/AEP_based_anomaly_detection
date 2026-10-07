# AGENTS.md

## Project Name
AEP + Markov + Entropy-Density Server Anomaly Detection

## Project Goal
Build an interpretable server-log anomaly-detection system based on:

1. Asymptotic Equipartition Property (AEP)
2. First-order Markov chains and entropy rate
3. Probability-density estimation of normalized information scores

The system should learn normal server-request behavior and flag windows that are statistically atypical or lie in a low-density region of the learned normal score distribution.

## Core Research Question
Can abnormal server behavior be detected by combining Markov-based sequence probability, AEP-based typicality, and density estimation of normalized information scores?

Compare three detectors:
- AEP-only
- Density-only
- Hybrid AEP + density

## Theory

### Entropy
For a discrete random variable:

\[
H(X)=-\sum_x p(x)\log_2 p(x)
\]

### AEP
For a sequence \(X^n=(X_1,\dots,X_n)\), define normalized self-information:

\[
Z(X^n)=-\frac{1}{n}\log_2 P(X^n)
\]

For sufficiently long typical sequences, \(Z(X^n)\) should be close to the entropy or entropy rate.

AEP deviation score:

\[
S_{AEP}=|Z-H_{rate}|
\]

### First-Order Markov Model
Model sequential dependence using:

\[
P(X_t\mid X_{t-1})
\]

Sequence probability:

\[
P(X_1,\ldots,X_n)=P(X_1)\prod_{t=2}^{n}P(X_t\mid X_{t-1})
\]

Transition probability:

\[
P_{ij}=P(X_t=j\mid X_{t-1}=i)
\]

### Entropy Rate
For a stationary first-order Markov chain:

\[
H_{rate}=-\sum_i\pi_i\sum_jP_{ij}\log_2P_{ij}
\]

where \(\pi_i\) is the stationary probability of state \(i\).

### Information-Score Density
For normal windows, compute \(Z_1,\dots,Z_m\) and estimate:

\[
\hat f_Z(z)
\]

Use Kernel Density Estimation (KDE) initially.

Density anomaly score:

\[
S_{density}=-\log(\hat f_Z(z)+\epsilon)
\]

Higher values indicate rarer observations.

Prefer the terms:
- information-score density
- entropy-score density
- density of normalized self-information

Avoid using only “density of entropy” without defining it.

## Main Data Pipeline

```text
Raw Server Logs
        |
        v
Log Parsing
        |
        v
Cleaning / Route Normalization
        |
        v
Event Encoding
        |
        v
Sequence Window Generation
        |
        v
Markov Model
        |
        v
Transition Probabilities
        |
        v
Entropy Rate
        |
        v
Sequence Log Probability
        |
        v
Normalized Information Score
        |
        v
AEP Deviation
        |
        v
Density Estimation
        |
        v
Anomaly Decision
        |
        v
Dashboard / Report / Alert
```

Mathematical pipeline:

\[
\text{Logs}\rightarrow X_1,\dots,X_n\rightarrow P(X_t\mid X_{t-1})\rightarrow P(X^n)
\rightarrow -\frac1n\log P(X^n)\rightarrow f_Z(z)\rightarrow \text{Anomaly}
\]

## Input Data
Initial implementation should work with:
- timestamp
- HTTP method
- URI / route
- HTTP status code

Optional fields:
- client IP
- response time
- request duration
- tenant/user identifier
- request metadata

Do not assume optional fields always exist.

## Log Parsing Rules
The parser should:
- tolerate malformed lines
- preserve raw lines for debugging
- report skipped-line statistics
- preserve timestamps
- sort chronologically where needed
- never silently discard invalid data

Preferred parsed event:

```python
{
    "timestamp": ...,
    "method": ...,
    "route": ...,
    "status": ...,
    "ip": ...
}
```

## Route Normalization
Dynamic identifiers should not create unnecessary states.

Example:

```text
/users/123
/users/581
/users/999
```

becomes:

```text
/users/:id
```

Use explicit normalization rules and avoid over-normalizing meaningful differences.

## Event Encoding
Use an interpretable state definition such as:

```text
(method, route_category, status_class)
```

Example:

```text
A = GET  | auth        | 2xx
B = GET  | dashboard   | 2xx
C = POST | accounting  | 2xx
D = GET  | unknown     | 4xx
E = GET  | sensitive   | 4xx
```

The encoder must:
- be deterministic
- save and reload mappings
- handle unknown future states explicitly
- never map unknown states silently to existing states

## Sequence Windowing
Support:
1. Fixed event-count windows
2. Fixed time windows

Initial experiment sizes:

```text
n = 10
n = 20
n = 50
n = 100
```

Support non-overlapping windows first. Sliding windows are optional.

## Dataset Split
Prefer chronological splitting:

```text
60-70% training
10-20% validation
20-30% testing
```

Do not leak future data into training.
Do not tune thresholds on the test set.

## Markov Training
Count transitions and estimate:

\[
P_{ij}=\frac{N(i\rightarrow j)}{\sum_k N(i\rightarrow k)}
\]

Use additive/Laplace smoothing to avoid zero-probability transitions.
Make smoothing configurable.

Always compute probabilities in log-space.

## Numerical Stability
Do not multiply many tiny probabilities directly.

Preferred:

```python
log_prob = 0.0
for transition in sequence:
    log_prob += math.log2(transition_probability)

information_score = -log_prob / len(sequence)
```

Never allow NaN, +inf, or -inf to propagate silently.

## AEP Module
Input:
- sequence log probability
- entropy rate

Output:

```python
{
    "information_score": ...,
    "entropy_rate": ...,
    "aep_deviation": ...,
    "is_typical": ...
}
```

Simple rule:

```python
if abs(z - entropy_rate) > epsilon:
    atypical = True
```

Prefer thresholds learned from validation data rather than arbitrary constants.

## Density Module
Fit KDE using information scores from normal training windows.

Input:

```text
Z1, Z2, ..., Zm
```

Output:
- density
- negative log-density
- optional density percentile

Use:

\[
S_{density}=-\log(\hat f_Z(z)+\epsilon)
\]

## Hybrid Detection
Keep AEP and density scores separate in the first version.

Expected output:

```python
{
    "aep_score": ...,
    "density_score": ...,
    "information_score": ...,
    "entropy_rate": ...,
    "density": ...,
    "final_anomalous": ...
}
```

Optional later score:

\[
S=\alpha S_{AEP}+(1-\alpha)S_{density}
\]

Normalize component scores before combining them.
Validate \(\alpha\) rather than choosing it arbitrarily.

## Explainability
Every anomaly should retain:
- original events
- encoded states
- transition probabilities
- least-probable transitions
- information score
- entropy rate
- AEP deviation
- density / density percentile
- threshold used

Example alert:

```text
Window: 2026-09-20 07:30–07:31
Information Score:   4.83 bits/request
Entropy Rate:        1.94 bits/request
AEP Deviation:       2.89
Density Percentile:  0.3%
Status: ANOMALOUS

Reason:
- sequence information is far from the learned entropy rate
- score lies in a very low-density region
- several transitions were rarely observed during training
```

## Evaluation
Compare:
1. AEP-only
2. Density-only
3. Hybrid AEP + density

If labels exist, compute:
- precision
- recall
- F1
- false-positive rate
- false-negative rate
- ROC-AUC where appropriate
- PR-AUC for strongly imbalanced data

Do not rely only on accuracy.

## Synthetic Anomalies
If no ground-truth labels exist, generate controlled test anomalies only in validation/testing.

Examples:

### Route Scanning
```text
/.env
/etc/passwd
/.aws/credentials
/admin
/wp-admin
```

### Request Flood
Unusually high request frequency.

### Transition Anomaly
Common states in unusual order.

### Error Burst
Windows dominated by 4xx or 5xx.

### Rare Route Burst
Repeated normally rare endpoints.

Never inject synthetic anomalies into normal training data.

## Recommended Repository Structure

```text
aep-server-anomaly/
│
├── AGENTS.md
├── README.md
├── pyproject.toml
├── requirements.txt
│
├── config/
│   └── default.yaml
│
├── data/
│   ├── raw/
│   ├── processed/
│   ├── training/
│   ├── validation/
│   └── testing/
│
├── src/
│   ├── parsing/
│   │   └── log_parser.py
│   ├── preprocessing/
│   │   ├── route_normalizer.py
│   │   └── event_encoder.py
│   ├── sequence/
│   │   └── windowing.py
│   ├── markov/
│   │   ├── model.py
│   │   └── transition_matrix.py
│   ├── information/
│   │   ├── entropy.py
│   │   ├── entropy_rate.py
│   │   └── aep.py
│   ├── density/
│   │   └── kde.py
│   ├── detection/
│   │   ├── detector.py
│   │   └── scoring.py
│   └── evaluation/
│       ├── metrics.py
│       └── synthetic_anomalies.py
│
├── scripts/
│   ├── preprocess.py
│   ├── train.py
│   ├── detect.py
│   └── evaluate.py
│
├── notebooks/
│   ├── 01_log_exploration.ipynb
│   ├── 02_markov_analysis.ipynb
│   ├── 03_aep_analysis.ipynb
│   └── 04_density_analysis.ipynb
│
├── models/
│   ├── encoder.json
│   ├── markov_model.json
│   ├── density_model.pkl
│   └── metadata.json
│
├── reports/
│   ├── figures/
│   ├── tables/
│   └── results/
│
└── tests/
    ├── test_parser.py
    ├── test_encoder.py
    ├── test_markov.py
    ├── test_entropy.py
    ├── test_aep.py
    └── test_density.py
```

## Module Responsibilities

### `log_parser.py`
- read raw logs
- parse supported fields
- preserve timestamps
- report malformed lines

### `route_normalizer.py`
- normalize dynamic IDs
- map similar routes to canonical forms
- preserve meaningful distinctions

### `event_encoder.py`
- convert events into deterministic states
- save/load state mapping
- handle unknown states

### `windowing.py`
- create fixed-count windows
- create optional time windows
- support optional sliding windows

### `markov/model.py`
- fit transition probabilities
- apply smoothing
- calculate transition log probabilities
- calculate sequence log probability
- save/load model

### `entropy_rate.py`
- estimate stationary distribution
- calculate Markov entropy rate

### `aep.py`
- calculate normalized information score
- calculate AEP deviation
- classify typical/atypical under configured rules

### `kde.py`
- fit density to training information scores
- evaluate unseen scores
- return density and negative log-density
- save/load model

### `detector.py`
Flow:

```text
sequence
 -> Markov log probability
 -> information score
 -> AEP deviation
 -> density score
 -> final decision
```

## Configuration
Use configuration rather than hard-coded experimental values.

```yaml
window:
  type: fixed_count
  size: 50
  sliding: false

markov:
  order: 1
  smoothing: 0.5

aep:
  threshold_method: validation_quantile
  quantile: 0.99

density:
  method: kde
  kernel: gaussian
  bandwidth: auto

detector:
  mode: hybrid
```

## Implementation Order

### Phase 1 — Data
- parser
- route normalization
- event encoding
- window creation

### Phase 2 — Markov
- transition counts
- transition probabilities
- smoothing
- sequence log probability

### Phase 3 — Entropy
- stationary distribution
- entropy rate
- normalized information score

### Phase 4 — AEP
- AEP deviation
- typicality threshold

### Phase 5 — Density
- KDE fitting
- density score
- low-density threshold

### Phase 6 — Evaluation
Compare AEP, density, and hybrid modes.

### Phase 7 — Interface
Only after the mathematical pipeline works:
- CLI
- API
- dashboard
- alerts

Do not start with frontend/dashboard work.

## Statistical Rules
Do not:
- train and test on the same windows
- tune on the final test set
- randomly shuffle sequential logs unless explicitly justified
- treat every rare event as malicious
- claim AEP guarantees anomaly detection
- claim low probability automatically means an attack

Prefer wording such as:
- statistically atypical
- rare relative to the learned normal model
- anomalous under the model

## Testing Requirements
At minimum, test:

### Entropy
```text
[0.5, 0.5] -> 1 bit
[1.0, 0.0] -> 0 bits
```

### Deterministic Markov Chain
```text
A -> B
B -> A
```
Expected entropy rate: approximately 0.

### Uniform Two-State Markov Chain
```text
P(A|A)=0.5
P(B|A)=0.5
P(A|B)=0.5
P(B|B)=0.5
```
Expected entropy rate: approximately 1 bit/transition.

Also test that:
- improbable sequences have larger information scores
- low-density samples have larger density anomaly scores

## Visualization Requirements
Generate:
1. requests over time
2. normalized route frequencies
3. Markov transition matrix
4. information score over time
5. entropy-rate reference line
6. AEP deviation over time
7. KDE of normal information scores
8. final anomaly timeline

## Expected Per-Window Output

```json
{
  "window_id": 142,
  "start_time": "2026-08-29T07:30:00",
  "end_time": "2026-08-29T07:31:00",
  "event_count": 50,
  "log_probability": -204.72,
  "information_score": 4.0944,
  "entropy_rate": 1.8621,
  "aep_deviation": 2.2323,
  "aep_anomalous": true,
  "density": 0.00082,
  "density_score": 7.105,
  "final_anomalous": true
}
```

## Project Limitations
State explicitly in the final report:
- finite datasets do not perfectly satisfy asymptotic assumptions
- server traffic may be non-stationary
- user behavior can drift over time
- first-order Markov dependence may be insufficient
- route encoding changes the learned probability model
- KDE bandwidth affects sensitivity
- rare legitimate behavior can create false positives
- anomalous statistical behavior is not necessarily malicious

## Future Extensions
Only after the core system is stable:
- higher-order Markov chains
- variable-length Markov models
- Hidden Markov Models
- online learning
- concept drift detection
- per-user/IP/tenant models
- conditional entropy
- KL divergence
- mutual information
- real-time streaming detection

## Agent Development Rules
When modifying the repository:
1. Preserve mathematical correctness.
2. Prefer interpretable implementations.
3. Do not replace the information-theoretic design with generic ML unless explicitly requested.
4. Keep training and detection separate.
5. Keep preprocessing deterministic.
6. Save model metadata for reproducibility.
7. Use log probabilities.
8. Write tests for mathematical functions.
9. Document assumptions.
10. Do not silently change encoding/model semantics.
11. Avoid data leakage.
12. Keep parameters configurable.
13. Preserve timestamps through the pipeline.
14. Make anomaly explanations available in model output.

## Definition of Done
The minimum successful system must:
1. Read server logs.
2. Parse requests.
3. Normalize routes.
4. Encode requests into states.
5. Create sequences.
6. Train a first-order Markov model.
7. Calculate transition probabilities.
8. Calculate entropy rate.
9. Calculate normalized sequence information scores.
10. Calculate AEP deviation.
11. Fit a density model to normal scores.
12. Score unseen windows.
13. Classify normal/anomalous windows.
14. Explain detected anomalies.
15. Compare AEP-only, density-only, and hybrid detection.
16. Produce report-ready figures.

Primary conceptual pipeline:

\[
\boxed{
\text{Server Logs}
\rightarrow
\text{Markov Sequence Model}
\rightarrow
\text{Entropy Rate}
\rightarrow
\text{AEP Information Score}
\rightarrow
\text{Score Density}
\rightarrow
\text{Anomaly Detection}
}
\]
