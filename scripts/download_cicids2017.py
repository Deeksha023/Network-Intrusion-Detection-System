import os
import sys
from pathlib import Path
from huggingface_hub import hf_hub_download

repo_id = "c01dsnap/CIC-IDS2017"
csv_files = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
]

target_dir = Path(__file__).resolve().parent.parent / "data" / "cicids2017"
target_dir.mkdir(parents=True, exist_ok=True)

print(f"Downloading {len(csv_files)} official CICIDS2017 CSV files to {target_dir}...")

for filename in csv_files:
    dest_path = target_dir / filename
    if dest_path.exists() and dest_path.stat().st_size > 0:
        print(f"  [EXISTS] {filename} ({dest_path.stat().st_size / (1024*1024):.2f} MB)")
        continue

    print(f"  [DOWNLOADING] {filename}...")
    downloaded_file = hf_hub_download(
        repo_id=repo_id,
        filename=filename,
        repo_type="dataset",
        local_dir=target_dir,
    )
    print(f"  [DOWNLOADED] {filename} ({dest_path.stat().st_size / (1024*1024):.2f} MB)")

print("\nAll official CICIDS2017 CSV files downloaded successfully!")
