"""Rebuild the v2 X_test (scaled) + y_test arrays and save as .npy.

The adversarial check probes the LSTM/CNN with these instead of uniform
random noise — they're in-distribution and the FGSM flip rate against
them is the *real* measurement.

Output:
- ../v2_test_samples.npy          shape (N, 122, 1), float32, scaled
- ../v2_test_labels.npy           shape (N,),       int64, label-encoded
- ../v2_test_attack_samples.npy   shape (M, 122, 1), only is_attack rows
- ../v2_test_attack_labels.npy    shape (M,),        matching labels
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

ROOT = Path(__file__).resolve().parent
OUT = ROOT.parent  # write artifacts at repo root

COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "label",
    "difficulty_level",
]

ATTACK_MAP = {
    "normal": "Normal",
    "back": "DoS",
    "land": "DoS",
    "neptune": "DoS",
    "pod": "DoS",
    "smurf": "DoS",
    "teardrop": "DoS",
    "apache2": "DoS",
    "udpstorm": "DoS",
    "processtable": "DoS",
    "worm": "DoS",
    "satan": "Probe",
    "ipsweep": "Probe",
    "nmap": "Probe",
    "portsweep": "Probe",
    "mscan": "Probe",
    "saint": "Probe",
    "guess_passwd": "R2L",
    "ftp_write": "R2L",
    "imap": "R2L",
    "phf": "R2L",
    "multihop": "R2L",
    "warezmaster": "R2L",
    "warezclient": "R2L",
    "spy": "R2L",
    "xlock": "R2L",
    "xsnoop": "R2L",
    "snmpguess": "R2L",
    "snmpgetattack": "R2L",
    "httptunnel": "R2L",
    "sendmail": "R2L",
    "named": "R2L",
    "buffer_overflow": "U2R",
    "loadmodule": "U2R",
    "rootkit": "U2R",
    "perl": "U2R",
    "sqlattack": "U2R",
    "xterm": "U2R",
    "ps": "U2R",
    "mailbomb": "U2R",
}

DEFAULT_UNKNOWN = "R2L"
RANDOM_STATE = 42


def main() -> int:
    train_df = pd.read_csv(ROOT / "KDDTrain+.txt", names=COLUMNS).drop(columns=["difficulty_level"])
    test_df = pd.read_csv(ROOT / "KDDTest+.txt", names=COLUMNS).drop(columns=["difficulty_level"])

    train_df["category"] = train_df["label"].map(ATTACK_MAP).fillna(DEFAULT_UNKNOWN)
    test_df["category"] = test_df["label"].map(ATTACK_MAP).fillna(DEFAULT_UNKNOWN)

    cat = ["protocol_type", "service", "flag"]
    train_enc = pd.get_dummies(train_df, columns=cat)
    test_enc = pd.get_dummies(test_df, columns=cat)
    train_enc, test_enc = train_enc.align(test_enc, join="left", axis=1, fill_value=0)

    feats = [c for c in train_enc.columns if c not in ("label", "category")]
    X_trainval = train_enc[feats].astype(np.float32).values
    X_test_raw = test_enc[feats].astype(np.float32).values

    le = LabelEncoder().fit(["DoS", "Normal", "Probe", "R2L", "U2R"])
    y_trainval = le.transform(train_df["category"])
    y_test = le.transform(test_df["category"])

    # Only the train fold's scaler is needed; val/test splits aren't used here.
    X_train_raw, _, _, _ = train_test_split(
        X_trainval,
        y_trainval,
        test_size=0.2,
        stratify=y_trainval,
        random_state=RANDOM_STATE,
    )

    scaler = StandardScaler().fit(X_train_raw)
    X_test = scaler.transform(X_test_raw)

    # Save 3D-shaped arrays for direct feeding into Conv1D/LSTM.
    X_test_3d = X_test.reshape(-1, X_test.shape[1], 1).astype(np.float32)
    y_test = y_test.astype(np.int64)

    np.save(OUT / "v2_test_samples.npy", X_test_3d)
    np.save(OUT / "v2_test_labels.npy", y_test)

    normal_idx = le.transform(["Normal"])[0]
    attack_mask = y_test != normal_idx
    X_test_attack = X_test_3d[attack_mask]
    y_test_attack = y_test[attack_mask]
    np.save(OUT / "v2_test_attack_samples.npy", X_test_attack)
    np.save(OUT / "v2_test_attack_labels.npy", y_test_attack)

    print(f"X_test_3d: {X_test_3d.shape} dtype={X_test_3d.dtype}")
    print(f"attack-only: {X_test_attack.shape}  class breakdown: {dict(Counter(y_test_attack))}")
    print(f"classes (encoded -> name): {dict(enumerate(le.classes_))}")
    print(f"saved to: {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
