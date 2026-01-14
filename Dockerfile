FROM golang:1.25.4-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY Makefile ./
RUN make build


FROM python:3.11-slim-bookworm

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates bash \
  && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir uv

COPY --from=build /src/bin/fuzzy /usr/local/bin/fuzzy
COPY --from=build /src/bin/survey /usr/local/bin/survey
COPY --from=build /src/bin/features /usr/local/bin/features
COPY --from=build /src/bin/filterResponses /usr/local/bin/filterResponses

COPY ml /opt/httpfuzz/ml
COPY scripts /opt/httpfuzz/scripts

RUN <<'EOF' bash
set -euo pipefail
cat > /usr/local/bin/httpfuzz-run <<'SH'
#!/usr/bin/env bash
set -euo pipefail

domain="${1:-}"
if [[ -z "$domain" ]]; then
  echo "usage: httpfuzz-run <domain>"
  echo
  echo "Required mounted inputs (defaults):"
  echo "  /work/data/map.csv"
  echo "  /work/data/vm_unique_*.json"
  echo "  /work/model_artifacts/{model.pkl,scaler.pkl,feature_names.pkl}"
  echo
  echo "Optional:"
  echo "  /work/data/request_set.txt (auto-generated if missing)"
  exit 2
fi

out_dir="${OUT_DIR:-/work/out}"
data_dir="${DATA_DIR:-/work/data}"
model_dir="${MODEL_DIR:-/work/model_artifacts}"
request_set="${REQUEST_SET:-$data_dir/request_set.txt}"

mkdir -p "$out_dir"
responses_dir="$out_dir/responses"
mkdir -p "$responses_dir"

if [[ ! -f "$request_set" ]]; then
  echo "data/request_set.txt not found; generating with fuzzy..."
  mkdir -p "$(dirname "$request_set")"
  /usr/local/bin/fuzzy > "$request_set"
fi

required_data_files=(
  "$data_dir/map.csv"
  "$data_dir/vm_unique_headers_ids.json"
  "$data_dir/vm_unique_status_code_ids.json"
  "$data_dir/vm_unique_status_message_ids.json"
  "$data_dir/vm_unique_header_values_ids.json"
)
for f in "${required_data_files[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "Missing required data file: $f"
    echo "Generate these from your training responses with:"
    echo "  uv run scripts/generate_map.py"
    echo "  uv run scripts/parse_headers.py --input responses --out-dir data"
    exit 1
  fi
done

required_model_files=("model.pkl" "scaler.pkl" "feature_names.pkl")
for f in "${required_model_files[@]}"; do
  if [[ ! -f "$model_dir/$f" ]]; then
    echo "Missing required model artifact: $model_dir/$f"
    exit 1
  fi
done

tmp_targets="$(mktemp)"
trap 'rm -f "$tmp_targets"' EXIT
printf "%s\n" "$domain" > "$tmp_targets"

echo "Surveying $domain..."
/usr/local/bin/survey -f "$tmp_targets" -C 1 -o "$responses_dir" -r "$request_set"

echo "Filtering non-responsive results..."
/usr/local/bin/filterResponses -dir "$responses_dir" || true

features_csv="$out_dir/features.csv"
echo "Extracting features..."
/usr/local/bin/features -input "$responses_dir" -output "$features_csv" -data "$data_dir"

echo "Predicting..."
cd "$out_dir"
uv run /opt/httpfuzz/ml/predict.py --input "$features_csv" --model-dir "$model_dir"

echo "Done."
echo "Outputs:"
echo "  $features_csv"
echo "  $out_dir/predictions.csv"
SH
chmod +x /usr/local/bin/httpfuzz-run
EOF

WORKDIR /work
ENTRYPOINT ["httpfuzz-run"]
