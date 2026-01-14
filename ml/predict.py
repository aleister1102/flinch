# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pandas",
#     "scikit-learn",
#     "joblib",
#     "numpy",
# ]
# ///

import argparse
import pandas as pd
import numpy as np
import joblib
import sys
import os

def main():
    parser = argparse.ArgumentParser(description="Predict server type using trained WSF model")
    parser.add_argument("--input", required=True, help="Path to input features CSV file")
    parser.add_argument("--model-dir", default="model_artifacts", help="Directory containing model artifacts")
    args = parser.parse_args()

    # Check artifacts
    required_files = ["model.pkl", "scaler.pkl", "feature_names.pkl"]
    for f in required_files:
        path = os.path.join(args.model_dir, f)
        if not os.path.exists(path):
            print(f"Error: Missing artifact {path}. Did you run train_model.py?")
            sys.exit(1)

    # Load artifacts
    print(f"Loading model artifacts from {args.model_dir}...")
    try:
        model = joblib.load(os.path.join(args.model_dir, "model.pkl"))
        scaler = joblib.load(os.path.join(args.model_dir, "scaler.pkl"))
        feature_names = joblib.load(os.path.join(args.model_dir, "feature_names.pkl"))
    except Exception as e:
        print(f"Error loading artifacts: {e}")
        sys.exit(1)

    # Load input data
    print(f"Loading input data from {args.input}...")
    try:
        df = pd.read_csv(args.input, low_memory=False)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        sys.exit(1)

    # Validate columns
    missing_cols = [col for col in feature_names if col not in df.columns]
    if missing_cols:
        print(f"Error: Input CSV is missing {len(missing_cols)} required features.")
        print(f"Missing: {missing_cols[:5]}...")
        sys.exit(1)

    # Select features
    X = df[feature_names]
    
    # Scale
    X_scaled = scaler.transform(X.values)

    # Predict
    print("Predicting...")
    predictions = model.predict(X_scaled)
    probabilities = model.predict_proba(X_scaled)

    # Output results
    # We can print a table of URL (if present) -> Prediction
    
    if 'url' in df.columns:
        urls = df['url']
    else:
        urls = [f"Row_{i}" for i in range(len(df))]

    # Get class labels order
    classes = model.classes_
    
    print("\nResults:")
    print("-" * 60)
    print(f"{'URL':<40} | {'Prediction':<15} | {'Confidence'}")
    print("-" * 60)
    
    for i, url in enumerate(urls):
        pred = predictions[i]
        # Find max probability
        prob = max(probabilities[i])
        print(f"{url:<40} | {pred:<15} | {prob:.2f}")
    
    # Save to CSV
    out_file = "predictions.csv"
    results_df = pd.DataFrame({
        "url": urls,
        "prediction": predictions,
        "confidence": [max(p) for p in probabilities]
    })
    results_df.to_csv(out_file, index=False)
    print("-" * 60)
    print(f"Results saved to {out_file}")

if __name__ == "__main__":
    main()
