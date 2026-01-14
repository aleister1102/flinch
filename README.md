# httpfuzz

`httpfuzz` is a suite of tools for web server fingerprinting using fuzzing techniques. It allows you to generate mutated HTTP requests, survey web servers, and extract features from responses for analysis or machine learning classification.

This project implements the approach described in the associated paper, focusing on fingerprinting mitigation techniques by analyzing how servers handle malformed or mutated HTTP requests.

## Project Structure

- `cmd/fuzzy`: Generates fuzzed HTTP request lines.
- `cmd/survey`: Sends generated requests to a list of domains and collects responses.
- `cmd/filterResponses`: Filters out non-responsive or invalid server responses.
- `cmd/features`: Parses responses and extracts features into a CSV dataset for analysis.
- `ml/`: Python scripts for model training and prediction.
- `scripts/`: Helper scripts (e.g., domain sampling, header parsing).
- `data/`: Data files (e.g., target lists, ID maps, request sets).

## Prerequisites

- Go 1.16 or higher
- Make
- Python 3.11+ (managed via `uv` recommended)
- Python packages listed in `requirements.txt`

## Installation

To build all tools:

```bash
make build
```

### Docker (Optional)

If you want to run the end-to-end fingerprinting flow in a container (including dependency checks), use the provided `Dockerfile`.

Build:
```bash
docker build -t httpfuzz .
```

Run against a single domain (mounting your local training artifacts into the container):
```bash
docker run --rm -v "$PWD:/work" httpfuzz example.com
```

The container expects these to exist on the mounted workspace:
- `data/map.csv` and `data/vm_unique_*.json` (feature encoding maps)
- `model_artifacts/model.pkl`, `model_artifacts/scaler.pkl`, `model_artifacts/feature_names.pkl` (trained model artifacts)

It writes outputs under `out/`:
- `out/features.csv`
- `out/predictions.csv`

To install Python dependencies:

```bash
# Using uv (recommended)
uv pip install -r requirements.txt
```

The binaries will be created in the `bin/` directory:
- `bin/fuzzy`
- `bin/survey`
- `bin/features`
- `bin/filterResponses`

To install them to your `$HOME/.local/bin`:

```bash
make install
```

## Usage Guide

### 1. Generate Fuzzing Payloads

Use `fuzzy` to generate a set of mutated HTTP request lines (insertions, deletions, replacements).

```bash
./bin/fuzzy > data/request_set.txt
```

### 2. Collect and Prepare Domains

You can collect a list of target domains (e.g., from Majestic Million). We provide a helper script to download the top 100,000 domains.

```bash
# Downloads Majestic Million top 100k to data/majestic_100k.csv
uv run scripts/collect_domains.py
```

Create a targets file (CSV with domain in the first column) for the survey tool:

```bash
# Example: Use the first 50 domains
head -n 50 data/majestic_100k.csv > data/targets.csv
```

### 3. Survey Servers

Use `survey` to send the generated requests to a list of domains.

#### Optional: Filter Unresolvable Domains (Recommended)

To reduce DNS resolution errors (e.g. `no such host`) and speed up surveying, you can filter `data/targets.csv` down to only domains that resolve using `puredns` (must be installed separately). `puredns` requires `massdns` to be installed and runnable on your machine.

```bash
# Produces: data/targets.csv.resolved.csv
uv run scripts/puredns_filter_csv.py data/targets.csv -b 500 -s 2
```

**Example:**
```bash
./bin/survey -p http://127.0.0.1:8080 -f data/targets.csv.resolved.csv -w 50
```
Defaults:
- Input: `data/targets.csv.resolved.csv` if present, else `data/targets.csv`
- Column: `-C 1`
- Requests: `data/request_set.txt`
- Output: `responses/`

Each output file is JSON lines (one JSON object per request/response).

### 4. Generate ID Maps

Before extracting features, you need to generate mapping files that assign unique IDs to headers, status codes, and request types. This ensures consistent feature encoding.

**Step 4a: Generate Request Type Map**
Generates `data/map.csv` based on known request types.
```bash
uv run scripts/generate_map.py
```

**Step 4b: Parse Headers from Responses**
Scans your collected responses to build unique ID maps for headers and status codes.
```bash
uv run scripts/parse_headers.py --input responses --out-dir data
```

### 5. Filter Responses (Optional)

Use `filterResponses` to remove response files for domains that did not respond properly or timed out.

**Arguments:**
- `-dir`: Path to the directory containing response files.

**Example:**
```bash
./bin/filterResponses -dir responses/
```

### 6. Extract Features

Use `features` to parse the raw HTTP responses and extract features into a CSV file for machine learning.

**Arguments:**
- `-input`: Path to the directory containing response files.
- `-output`: Path to the output CSV file (default: `features.csv`).
- `-data`: Path to the data directory containing ID maps and helper CSVs (default: `data/`).

**Example:**
```bash
./bin/features -input responses/ -output data/dataset.csv
```

## Machine Learning & Fingerprinting

This project includes Python scripts to train a classification model and use it to fingerprint arbitrary domains.

### One-Time Setup (per dataset)

Complete steps 1–4 in the Usage Guide so you have:
- `data/request_set.txt`
- `responses/`
- `data/map.csv`
- `data/vm_unique_*.json`

### 1. Train the Model

Once you have collected a dataset (e.g., `dataset.csv`) using the `features` tool, you can train a model. This will save the trained model and artifacts to `model_artifacts/`.

```bash
UV_CACHE_DIR="$PWD/.uv_cache" uv run ml/train_model.py --input dataset.csv --out-dir model_artifacts
```

This script:
- Drops unnecessary columns.
- Removes low-variance features.
- Scales the features.
- Trains a Random Forest Classifier.
- Saves `model.pkl`, `scaler.pkl`, and `feature_names.pkl`.

### 2. Fingerprint an Arbitrary Domain

To fingerprint a new domain, reuse the same `data/` ID maps from training (so feature encoding matches). Then:

1. **Survey**: Run `survey` against the target domain into a dedicated output directory.
2. **Extract**: Run `features` to generate a CSV for the target using the existing `data/` maps.
3. **Predict**: Run `ml/predict.py` with the trained artifacts.

**Example Workflow:**

```bash
# 1. Survey the target (single-domain file, domain in column 1)
echo "target-domain.com" > data/target.csv
./bin/survey -f data/target.csv -C 1 -o target_responses -r data/request_set.txt

# 2. Extract features (reuse the same data/ maps generated from training)
./bin/features -input target_responses -output target_features.csv -data data

# 3. Predict
UV_CACHE_DIR="$PWD/.uv_cache" uv run ml/predict.py --input target_features.csv --model-dir model_artifacts
```

The script will output the predicted server type and confidence score.

## Development
- `make test`: Run tests.
- `make clean`: Clean up build artifacts.

## Citation

If you use this project in academic work, please cite the original paper:

Kar, A., Natadze, A., Branca, E., and Stakhanova, N. “HTTPFuzz: Web Server Fingerprinting with HTTP Request Fuzzing.” In Proceedings of the 19th International Conference on Security and Cryptography (SECRYPT 2022), pp. 261–271, 2022.

```bibtex
@inproceedings{kar2022httpfuzz,
  title     = {HTTPFuzz: Web Server Fingerprinting with HTTP Request Fuzzing},
  author    = {Kar, Animesh and Natadze, Andrei and Branca, Enrico and Stakhanova, Natalia},
  booktitle = {Proceedings of the 19th International Conference on Security and Cryptography (SECRYPT 2022)},
  pages     = {261--271},
  year      = {2022}
}
```
