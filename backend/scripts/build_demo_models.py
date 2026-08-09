import os
import sys
from pathlib import Path
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from feature_extraction.feature_names import FEATURE_NAMES, FEATURE_COUNT

def build_demo_artifacts():
    artifacts_dir = backend_dir / "ml" / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    print(f"Building ML artifacts in {artifacts_dir}...")

    # Define classes including 'PortScan' and 'Port Scan'
    classes = [
        "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest",
        "DoS Slowloris", "FTP-Patator", "Heartbleed", "Infiltration", "PortScan",
        "Port Scan", "SSH-Patator", "Web Attack - Brute Force",
        "Web Attack - SQL Injection", "Web Attack - XSS", "SYN Flood", "ICMP Flood", "UDP Flood", "Brute Force"
    ]

    # Create synthetic training dataset (100 samples per class)
    np.random.seed(42)
    X_samples = []
    y_samples = []

    for cls in classes:
        for _ in range(100):
            row = np.random.normal(loc=0.0, scale=1.0, size=FEATURE_COUNT)
            # Add distinct feature signals for specific attack types
            if cls in ("PortScan", "Port Scan"):
                # Port scan signature: short duration, SYN flags high, high packet rate
                flow_dur_idx = FEATURE_NAMES.index("Flow Duration")
                syn_flag_idx = FEATURE_NAMES.index("SYN Flag Count")
                pkt_rate_idx = FEATURE_NAMES.index("Flow Packets/s")
                row[flow_dur_idx] = 150.0 + np.random.normal(0, 10)
                row[syn_flag_idx] = 2.0 + np.random.normal(0, 0.5)
                row[pkt_rate_idx] = 13333.33 + np.random.normal(0, 100)
            elif cls == "SYN Flood":
                syn_flag_idx = FEATURE_NAMES.index("SYN Flag Count")
                row[syn_flag_idx] = 50.0 + np.random.normal(0, 5)
            X_samples.append(row)
            y_samples.append(cls)

    X = np.array(X_samples, dtype=np.float32)
    y = np.array(y_samples)

    # 1. Fit StandardScaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    scaler_path = artifacts_dir / "scaler.pkl"
    joblib.dump(scaler, scaler_path)
    print(f"Saved StandardScaler to {scaler_path}")

    # 2. Fit LabelEncoder
    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)
    encoder_path = artifacts_dir / "classifier_encoder.pkl"
    joblib.dump(encoder, encoder_path)
    print(f"Saved LabelEncoder to {encoder_path}")

    # 3. Fit RandomForestClassifier
    rf = RandomForestClassifier(n_estimators=50, random_state=42)
    rf.fit(X_scaled, y_encoded)
    model_path = artifacts_dir / "classifier.joblib"
    joblib.dump(rf, model_path)
    print(f"Saved RandomForestClassifier to {model_path}")

    # 4. Save PyTorch Autoencoder weights using exact model definition
    try:
        from ml.anomaly_detector import PyTorchAutoencoder
        import torch

        ae = PyTorchAutoencoder(input_dim=FEATURE_COUNT)
        ae_path = artifacts_dir / "autoencoder.pt"
        torch.save(ae.state_dict(), ae_path)
        print(f"Saved Autoencoder weights to {ae_path}")
    except Exception as e:
        print(f"Note: Autoencoder weights skipped ({e})")

    print("All ML artifacts generated successfully!")

if __name__ == "__main__":
    build_demo_artifacts()
