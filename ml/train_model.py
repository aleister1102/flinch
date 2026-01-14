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
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import FunctionTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

def main():
    parser = argparse.ArgumentParser(description="Train a WSF model from features CSV")
    parser.add_argument("--input", required=True, help="Path to features CSV file")
    parser.add_argument("--out-dir", default="model_artifacts", help="Directory to save model artifacts")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input file {args.input} not found.")
        sys.exit(1)

    os.makedirs(args.out_dir, exist_ok=True)

    print(f"Loading data from {args.input}...")
    try:
        df = pd.read_csv(args.input, low_memory=False)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        sys.exit(1)

    # Initial column dropping as per notebook
    # Note: 'url' and 'request' might identify the row.
    # 'nmap_target' is likely ground truth or alternative label, dropping it to use 'target' as label.
    initial_drop_columns = [
        'url', 
        'request', 
        'request_type_id', 
        'nmap_target',
        'x-powered-by_value_id', 
        'str_parent1_request_type', 
        'str_parent2_request_type'
    ]

    # Only drop columns that exist
    drop_cols = [c for c in initial_drop_columns if c in df.columns]
    print(f"Dropping columns: {drop_cols}")
    df.drop(drop_cols, axis=1, inplace=True)

    # Separate features and label
    # Assuming 'target' is the label and is the last column after dropping 'nmap_target'
    # In features/main.go, 'target' is appended before 'nmap_target'.
    # If 'nmap_target' is dropped, 'target' should be the last one.
    # However, let's be explicit if 'target' exists.
    if 'target' in df.columns:
        labels = df['target']
        features = df.drop(['target'], axis=1)
    else:
        # Fallback to last column if 'target' not found by name (though it should be there)
        print("Warning: 'target' column not found. Using the last column as label.")
        labels = df.iloc[:, -1]
        features = df.iloc[:, :-1]

    print(f"Features shape: {features.shape}")
    print(f"Labels shape: {labels.shape}")

    features_np = features.to_numpy(dtype=np.float32, copy=False)
    np.nan_to_num(features_np, copy=False, nan=0.0, posinf=0.0, neginf=0.0)

    print("Removing constant features...")
    col_min = np.min(features_np, axis=0)
    col_max = np.max(features_np, axis=0)
    keep_mask = (col_max - col_min) != 0
    dropped = int((~keep_mask).sum())
    print(f"Dropping {dropped} constant columns.")

    if dropped > 0:
        features_np = features_np[:, keep_mask]
        kept_columns = features.columns.to_numpy()[keep_mask]
        feature_names = kept_columns.tolist()
    else:
        feature_names = features.columns.tolist()

    # Save the list of kept feature names to ensure alignment during prediction
    joblib.dump(feature_names, os.path.join(args.out_dir, "feature_names.pkl"))

    print("Preparing scaler...")
    scaler = FunctionTransformer(validate=False)
    scaled_features = scaler.fit_transform(features_np)
    joblib.dump(scaler, os.path.join(args.out_dir, "scaler.pkl"))

    # Train/Test split
    X_train, X_test, y_train, y_test = train_test_split(scaled_features, labels, test_size=0.2, random_state=42, stratify=labels)

    # Train Random Forest
    print("Training Random Forest Classifier...")
    # Parameters from notebook
    clf = RandomForestClassifier(
        n_estimators=50,
        n_jobs=-1, # Use all cores
        max_depth=6,
        min_samples_split=2,
        min_samples_leaf=1,
        bootstrap=True,
        oob_score=True,
        # max_features='auto', # 'auto' is deprecated in newer sklearn, default is 'sqrt' which is same
        criterion='entropy'
    )

    clf.fit(X_train, y_train)

    # Evaluate
    print("Evaluating model...")
    y_pred = clf.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:\n")
    print(classification_report(y_test, y_pred))

    # Save model
    model_path = os.path.join(args.out_dir, "model.pkl")
    joblib.dump(clf, model_path)
    print(f"Model saved to {model_path}")
    print("Done.")

if __name__ == "__main__":
    main()
