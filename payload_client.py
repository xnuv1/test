import sys
import os
import hashlib
import json
from typing import Dict, Tuple

import numpy as np
import requests


# URL of your FastAPI service.
API_URL = "http://localhost:8000/predict_payload"


# ---------- Helper functions ----------

def sha256_file(path: str) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_hist_entropy(byte_data: bytes) -> Tuple[np.ndarray, np.ndarray]:
    """
    Compute histogram and "entropy per segment" features.

    NOTE:
    -----
    This is a generic implementation that gives you:
      - hist[0..255]   : frequency of each byte value (0-255), normalized
      - ent[0..255]    : Shannon entropy of 256 equally-sized segments
    """
    if not byte_data:
        # Edge case: empty file
        return np.zeros(256, dtype=float), np.zeros(256, dtype=float)

    arr = np.frombuffer(byte_data, dtype=np.uint8)

    # 1) Histogram of byte values (0..255), normalized
    hist = np.bincount(arr, minlength=256).astype(float)
    hist = hist / hist.sum()

    # 2) Divide the file into 256 segments (as evenly as possible)
    total_len = len(arr)
    segment_size = max(total_len // 256, 1)

    ent = np.zeros(256, dtype=float)

    def shannon_entropy(segment: np.ndarray) -> float:
        if len(segment) == 0:
            return 0.0
        counts = np.bincount(segment, minlength=256).astype(float)
        probs = counts / counts.sum()
        non_zero = probs[probs > 0]
        return float(-np.sum(non_zero * np.log2(non_zero)))

    for i in range(256):
        start = i * segment_size
        if start >= total_len:
            ent[i] = 0.0
            continue
        end = min((i + 1) * segment_size, total_len)
        segment = arr[start:end]
        ent[i] = shannon_entropy(segment)

    #
    ent = ent / 8.0

    return hist, ent


def build_feature_dict(hist: np.ndarray, ent: np.ndarray) -> Dict[str, float]:
    """Map hist[0..255], ent[0..255] into the feature names your model expects."""
    feat = {}
    for i in range(256):
        feat[f"hist_{i}"] = float(hist[i])
    for i in range(256):
        feat[f"ent_{i}"] = float(ent[i])
    return feat


# ---------- Main client logic ----------

def analyze_file(file_path: str):
    if not os.path.exists(file_path):
        print(f"[ERROR] File does not exist: {file_path}")
        return

    print(f"[INFO] Reading file: {file_path}")
    with open(file_path, "rb") as f:
        data = f.read()

    print(f"[INFO] Computing hash and features...")
    file_hash = sha256_file(file_path)
    hist, ent = compute_hist_entropy(data)
    features = build_feature_dict(hist, ent)

    payload = {
        "file_hash": file_hash,
        "file_path": file_path,
        "features": features,
    }

    try:
        print(f"[INFO] Sending features to API: {API_URL}")
        resp = requests.post(API_URL, json=payload, timeout=5)
        resp.raise_for_status()
    except Exception as e:
        print(f"[ERROR] Request to API failed: {e}")
        return

    try:
        result = resp.json()
    except Exception as e:
        print(f"[ERROR] Could not decode JSON response: {e}")
        print(resp.text)
        return

    print("[INFO] API response:")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python payload_client.py <path_to_file>")
        sys.exit(1)

    file_path_arg = sys.argv[1]
    analyze_file(file_path_arg)



def analyze_file(file_path: str):
    if not os.path.exists(file_path):
        print(f"[ERROR] File does not exist: {file_path}")
        return

    print(f"[INFO] Reading file: {file_path}")
    with open(file_path, "rb") as f:
        data = f.read()

    print(f"[INFO] Computing hash and features...")
    file_hash = sha256_file(file_path)
    hist, ent = compute_hist_entropy(data)
    features = build_feature_dict(hist, ent)

    payload = {
        "file_hash": file_hash,
        "file_path": file_path,
        "features": features,
    }

    try:
        print(f"[INFO] Sending features to API: {API_URL}")
        resp = requests.post(API_URL, json=payload, timeout=5)
        resp.raise_for_status()
    except Exception as e:
        print(f"[ERROR] Request to API failed: {e}")
        return

    try:
        result = resp.json()
    except Exception as e:
        print(f"[ERROR] Could not decode JSON response: {e}")
        print(resp.text)
        return

    print("[INFO] API response:")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python payload_client.py <path_to_file>")
        sys.exit(1)

    file_path_arg = sys.argv[1]
    analyze_file(file_path_arg)
