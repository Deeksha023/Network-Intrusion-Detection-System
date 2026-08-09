import sys
import os
import json
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import numpy as np
import joblib
import torch
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split

from feature_extraction.feature_names import FEATURE_NAMES
from scripts.train_classifier import LABEL_VARIANTS
from ml.anomaly_detector import PyTorchAutoencoder, AutoencoderDetector

def main():
    import sys, io
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print("=" * 70)
    print("IDS Pipeline Complete Analysis: Stage 1 Confusion Matrix & Stage 2 Anomaly Test")
    print("=" * 70)


    data_path = os.path.join(Path(__file__).resolve().parent.parent.parent, "data", "cicids2017")
    artifacts_dir = os.path.join(Path(__file__).resolve().parent.parent, "ml", "artifacts")


    # 1. Verify Autoencoder Threshold & Stats
    thresh_file = os.path.join(artifacts_dir, "autoencoder_threshold.json")
    if os.path.exists(thresh_file):
        with open(thresh_file) as f:
            thresh_data = json.load(f)
        print("\n--- 1. Stage 2 (PyTorch Autoencoder) Threshold & Validation MSE Distribution ---")
        print(f"  Anomaly Threshold (95th percentile) : {thresh_data.get('threshold'):.8f}")
        print(f"  Validation MSE Min                  : {thresh_data.get('val_mse_min'):.8f}")
        print(f"  Validation MSE Median (p50)         : {thresh_data.get('val_mse_p50'):.8f}")
        print(f"  Validation MSE p90                  : {thresh_data.get('val_mse_p90'):.8f}")
        print(f"  Validation MSE p95 (Threshold)      : {thresh_data.get('val_mse_p95'):.8f}")
        print(f"  Validation MSE p99                  : {thresh_data.get('val_mse_p99'):.8f}")
        print(f"  Validation MSE Max                  : {thresh_data.get('val_mse_max'):.8f}")
    else:
        print("\n[!] autoencoder_threshold.json not found yet.")

    # 2. Load dataset and models
    print("\nLoading dataset CSVs for evaluation...")
    csv_files = sorted(Path(data_path).glob("*.csv"))
    chunks = [pd.read_csv(f, low_memory=False, encoding="utf-8") for f in csv_files]
    df = pd.concat(chunks, ignore_index=True)

    df.columns = df.columns.str.strip()
    df = df.loc[:, ~df.columns.duplicated()]
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    X = df[FEATURE_NAMES].values.astype("float32")
    raw_labels = df["Label"].str.strip().values
    y_str = np.array([LABEL_VARIANTS.get(lbl, lbl) for lbl in raw_labels])

    encoder = joblib.load(os.path.join(artifacts_dir, "classifier_encoder.pkl"))
    scaler = joblib.load(os.path.join(artifacts_dir, "scaler.pkl"))
    clf = joblib.load(os.path.join(artifacts_dir, "classifier.joblib"))

    y = encoder.transform(y_str)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    X_test_scaled = scaler.transform(X_test)

    print("Evaluating Stage 1 RandomForest on test set (565,576 samples)...")
    y_pred = clf.predict(X_test_scaled)
    classes = list(encoder.classes_)

    # 3. Compute Binary & Multi-class Evaluation Metrics
    benign_idx = classes.index("BENIGN") if "BENIGN" in classes else 0
    y_test_binary = (y_test != benign_idx).astype(int)
    y_pred_binary = (y_pred != benign_idx).astype(int)

    tp_bin = int(np.sum((y_test_binary == 1) & (y_pred_binary == 1)))
    tn_bin = int(np.sum((y_test_binary == 0) & (y_pred_binary == 0)))
    fp_bin = int(np.sum((y_test_binary == 0) & (y_pred_binary == 1)))
    fn_bin = int(np.sum((y_test_binary == 1) & (y_pred_binary == 0)))

    total_test = len(y_test)
    benign_samples = int(np.sum(y_test_binary == 0))
    attack_samples = int(np.sum(y_test_binary == 1))

    accuracy = float((tp_bin + tn_bin) / total_test)
    precision = float(tp_bin / (tp_bin + fp_bin)) if (tp_bin + fp_bin) > 0 else 0.0
    recall = float(tp_bin / (tp_bin + fn_bin)) if (tp_bin + fn_bin) > 0 else 0.0
    specificity = float(tn_bin / (tn_bin + fp_bin)) if (tn_bin + fp_bin) > 0 else 0.0
    f1_score = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = float(fp_bin / (fp_bin + tn_bin)) if (fp_bin + tn_bin) > 0 else 0.0
    fnr = float(fn_bin / (fn_bin + tp_bin)) if (fn_bin + tp_bin) > 0 else 0.0
    balanced_acc = float((recall + specificity) / 2.0)

    print("\n" + "=" * 70)
    print("OFFLINE MODEL EVALUATION (HELD-OUT TEST SET RESULTS)")
    print("=" * 70)
    print(f"  Evaluation Source       : OFFLINE HELD-OUT TEST SET (NOT live alerts)")
    print(f"  Dataset                 : CICIDS2017")
    print(f"  Train / Test Split      : 80% Train / 20% Test")
    print(f"  Features Used           : {len(FEATURE_NAMES)}")
    print(f"  Total Test Samples      : {total_test:,}")
    print(f"  Benign Samples          : {benign_samples:,}")
    print(f"  Attack Samples          : {attack_samples:,}")
    print(f"  Number of Attack Classes: {len(classes) - 1}")
    print("-" * 70)
    print(f"  Accuracy                : {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print(f"  Precision               : {precision:.4f} ({precision * 100:.2f}%)")
    print(f"  Recall (Sensitivity)    : {recall:.4f} ({recall * 100:.2f}%)")
    print(f"  F1-Score                : {f1_score:.4f} ({f1_score * 100:.2f}%)")
    print(f"  Specificity             : {specificity:.4f} ({specificity * 100:.2f}%)")
    print(f"  False Positive Rate     : {fpr:.4f} ({fpr * 100:.2f}%)")
    print(f"  False Negative Rate     : {fnr:.4f} ({fnr * 100:.2f}%)")
    print(f"  Balanced Accuracy       : {balanced_acc:.4f} ({balanced_acc * 100:.2f}%)")
    print("-" * 70)
    print("  Binary Confusion Matrix:")
    print(f"    TP: {tp_bin:<12} FP: {fp_bin:<12}")
    print(f"    FN: {fn_bin:<12} TN: {tn_bin:<12}")


    # 4. Print Multi-class Confusion Matrix
    print("\n" + "=" * 70)
    print("Stage 1 Multi-class Confusion Matrix (Rows = True, Cols = Pred)")
    print("=" * 70)
    cm = confusion_matrix(y_test, y_pred)
    cm_df = pd.DataFrame(cm, index=classes, columns=classes)
    print(cm_df.to_string())

    # 5. Export Offline Evaluation JSON
    offline_metrics = {
        "evaluation_type": "OFFLINE MODEL EVALUATION",
        "dataset": "CICIDS2017",
        "train_test_split": "80% Train / 20% Test",
        "total_test_samples": total_test,
        "benign_samples": benign_samples,
        "attack_samples": attack_samples,
        "num_attack_classes": len(classes) - 1,
        "num_features": len(FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "confusion_matrix": {
            "tp": tp_bin,
            "tn": tn_bin,
            "fp": fp_bin,
            "fn": fn_bin,
            "total_evaluated": total_test,
        },
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
            "specificity": round(specificity, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "balanced_accuracy": round(balanced_acc, 4),
        },
        "classes": classes,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    eval_out_path = os.path.join(artifacts_dir, "offline_evaluation.json")
    with open(eval_out_path, "w") as f:
        json.dump(offline_metrics, f, indent=2)
    print(f"\n[✓] Exported offline evaluation metrics → {eval_out_path}")

    # 6. Test Weak Classes (Bot, Infiltration, XSS) through Stage 2 PyTorch Autoencoder
    pt_model_path = os.path.join(artifacts_dir, "autoencoder.pt")
    if os.path.exists(pt_model_path):
        print("\n" + "=" * 70)
        print("Stage 2 PyTorch Autoencoder Anomaly Detection on Stage 1 False BENIGN Samples")
        print("=" * 70)

        threshold = thresh_data.get("threshold", 0.04165823) if 'thresh_data' in locals() else 0.04165823
        detector = AutoencoderDetector(model_path=pt_model_path, threshold=threshold)
        detector.load()

        weak_classes = ["Bot", "Infiltration", "Web Attack - XSS"]

        for target_cls in weak_classes:
            if target_cls not in classes:
                continue
            cls_idx = classes.index(target_cls)
            missed_mask = (y_test == cls_idx) & (y_pred == benign_idx)
            n_missed = int(missed_mask.sum())
            total_cls = int((y_test == cls_idx).sum())

            print(f"\nTarget Class: '{target_cls}'")
            print(f"  Total test samples          : {total_cls}")
            print(f"  Stage 1 Misclassified as BENIGN: {n_missed}")

            if n_missed > 0:
                X_missed = X_test_scaled[missed_mask]
                flagged_anomalies = 0
                errors = []
                for i in range(len(X_missed)):
                    sample = X_missed[i:i+1]
                    is_anom, mse = detector.detect(sample)
                    errors.append(mse)
                    if is_anom:
                        flagged_anomalies += 1

                mean_mse = float(np.mean(errors))
                pct_flagged = float(100.0 * flagged_anomalies / n_missed)
                print(f"  Stage 2 Reconstruction Error Mean : {mean_mse:.8f} (Threshold = {threshold:.8f})")
                print(f"  Stage 2 Flagged as Anomaly        : {flagged_anomalies} / {n_missed} ({pct_flagged:.1f}%)")
                if pct_flagged > 0:
                    print(f"  --> SUCCESS: Stage 2 hybrid escalation caught {pct_flagged:.1f}% of Stage 1 missed attacks!")


if __name__ == "__main__":
    main()


if __name__ == "__main__":
    main()
