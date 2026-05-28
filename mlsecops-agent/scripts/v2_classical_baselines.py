"""Reproduce the classical-baseline portion of nids_pipeline_v2.

CNN/LSTM in v2 take > 15 min/epoch on CPU; skipping them lets us produce
honest numbers for LogReg + RandomForest + HistGBM in about two minutes.
These three models are the comparison baseline anyway; the deep models
are flair on top and run in Colab.

Inputs (relative to where the script is invoked from):
- KDDTrain+.txt, KDDTest+.txt

Outputs (written into ``../../nids_v2_outputs/`` at the repo root, the
same directory the top-level README links to):
- classical_results.json: per-model accuracy/F1 on val + test
- confusion_matrix.png: panel grid for the classical models

Run from .v2_run/ where the KDD files live:

    cd .v2_run
    .venv/Scripts/python.exe ../mlsecops-agent/scripts/v2_classical_baselines.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

# Force the headless backend before importing pyplot — running in CI / a venv
# without a display would otherwise fail on plt.subplots().
os.environ.setdefault("MPLBACKEND", "Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Where the rendered artifacts land. Resolved from this file's location so
# the script doesn't care where it was invoked from.
_OUTPUTS_DIR = (Path(__file__).resolve().parent.parent.parent / "nids_v2_outputs").resolve()

RANDOM_STATE = 42

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
    # DoS
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
    # Probe
    "satan": "Probe",
    "ipsweep": "Probe",
    "nmap": "Probe",
    "portsweep": "Probe",
    "mscan": "Probe",
    "saint": "Probe",
    # R2L
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
    # U2R
    "buffer_overflow": "U2R",
    "loadmodule": "U2R",
    "rootkit": "U2R",
    "perl": "U2R",
    "sqlattack": "U2R",
    "xterm": "U2R",
    "ps": "U2R",
    "mailbomb": "U2R",
}


def main() -> int:
    started = time.perf_counter()

    train_df = pd.read_csv("KDDTrain+.txt", names=COLUMNS)
    test_df = pd.read_csv("KDDTest+.txt", names=COLUMNS)

    print(f"loaded train={len(train_df)} test={len(test_df)}")

    # v2 fix #1: difficulty_level dropped
    train_df = train_df.drop(columns=["difficulty_level"])
    test_df = test_df.drop(columns=["difficulty_level"])

    DEFAULT_UNKNOWN = "R2L"

    def categorize(df: pd.DataFrame, split_name: str) -> pd.DataFrame:
        known = df["label"].isin(ATTACK_MAP)
        unknown = df.loc[~known, "label"].value_counts()
        df["category"] = df["label"].map(ATTACK_MAP).fillna(DEFAULT_UNKNOWN)
        if len(unknown):
            total = int(unknown.sum())
            share = total / len(df) * 100
            print(
                f"[{split_name}] {total} rows ({share:.2f}%) had unknown labels "
                f"-> '{DEFAULT_UNKNOWN}'"
            )
            print(f"[{split_name}] fall-through labels: {unknown.to_dict()}")
        else:
            print(f"[{split_name}] no unknown labels.")
        return df

    train_df = categorize(train_df, "train")
    test_df = categorize(test_df, "test")

    cat_features = ["protocol_type", "service", "flag"]
    train_enc = pd.get_dummies(train_df, columns=cat_features)
    test_enc = pd.get_dummies(test_df, columns=cat_features)
    train_enc, test_enc = train_enc.align(test_enc, join="left", axis=1, fill_value=0)

    feature_cols = [c for c in train_enc.columns if c not in ("label", "category")]
    X_trainval = train_enc[feature_cols].astype(np.float32).values
    X_test_raw = test_enc[feature_cols].astype(np.float32).values

    le = LabelEncoder().fit(train_df["category"])
    y_trainval_enc = le.transform(train_df["category"])
    y_test_enc = le.transform(test_df["category"])

    # v2 fix #2: stratified split first, THEN SMOTE on train fold only.
    X_train_raw, X_val_raw, y_train, y_val = train_test_split(
        X_trainval,
        y_trainval_enc,
        test_size=0.2,
        stratify=y_trainval_enc,
        random_state=RANDOM_STATE,
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_val = scaler.transform(X_val_raw)
    X_test = scaler.transform(X_test_raw)

    smote = SMOTE(random_state=RANDOM_STATE, k_neighbors=3)
    X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)
    print(f"SMOTE: before={dict(Counter(y_train))}  after={dict(Counter(y_train_bal))}")

    models = {
        "LogReg": LogisticRegression(max_iter=1000, n_jobs=-1, random_state=RANDOM_STATE),
        "RandomForest": RandomForestClassifier(
            n_estimators=200, n_jobs=-1, random_state=RANDOM_STATE
        ),
        "HistGBM": HistGradientBoostingClassifier(max_iter=200, random_state=RANDOM_STATE),
    }

    rows: list[dict[str, float | str]] = []
    preds: dict[str, np.ndarray] = {}

    for name, model in models.items():
        t0 = time.perf_counter()
        model.fit(X_train_bal, y_train_bal)
        train_secs = time.perf_counter() - t0
        for split, X, y in (("val", X_val, y_val), ("test", X_test, y_test_enc)):
            y_pred = model.predict(X)
            row = {
                "model": name,
                "split": split,
                "accuracy": round(float(accuracy_score(y, y_pred)), 4),
                "f1_macro": round(float(f1_score(y, y_pred, average="macro", zero_division=0)), 4),
                "f1_weighted": round(
                    float(f1_score(y, y_pred, average="weighted", zero_division=0)), 4
                ),
                "train_secs": round(train_secs, 1),
            }
            rows.append(row)
            print(f"  {name} {split}: acc={row['accuracy']:.4f}  f1_macro={row['f1_macro']:.4f}")
        preds[name] = model.predict(X_test)

    # Per-class report for the best model on test (by macro-F1).
    test_rows = [r for r in rows if r["split"] == "test"]
    best = max(test_rows, key=lambda r: r["f1_macro"])
    print(f"\n=== {best['model']} per-class on held-out test ===")
    print(
        classification_report(
            y_test_enc,
            preds[best["model"]],
            target_names=le.classes_,
            digits=4,
            zero_division=0,
        )
    )

    # Confusion-matrix grid (3 classical models)
    _, axes = plt.subplots(1, 3, figsize=(15, 4.5))
    for ax, name in zip(axes, models.keys(), strict=True):
        cm = confusion_matrix(y_test_enc, preds[name], labels=range(len(le.classes_)))
        cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True).clip(min=1)
        sns.heatmap(
            cm_norm,
            annot=True,
            fmt=".2f",
            cmap="Blues",
            xticklabels=le.classes_,
            yticklabels=le.classes_,
            ax=ax,
            cbar=False,
        )
        ax.set_title(f"{name} (test, row-normalised)")
        ax.set_xlabel("predicted")
        ax.set_ylabel("true")
    plt.tight_layout()
    _OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    cm_path = _OUTPUTS_DIR / "confusion_matrix.png"
    plt.savefig(cm_path, dpi=120, bbox_inches="tight")
    print(f"\nwrote {cm_path.relative_to(_OUTPUTS_DIR.parent)}")

    results_path = _OUTPUTS_DIR / "classical_results.json"
    results_path.write_text(
        json.dumps({"results": rows, "best_model": best["model"]}, indent=2),
        encoding="utf-8",
    )
    print(f"wrote {results_path.relative_to(_OUTPUTS_DIR.parent)}")

    print(f"\ntotal wall: {time.perf_counter() - started:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
