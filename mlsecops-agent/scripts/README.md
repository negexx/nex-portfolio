# scripts/

Repeatable helpers for things that don't belong in `src/` but that someone
needs to be able to run later.

## extract_v2_probes.py

Rebuilds the four `.npy` arrays used by `mlsecops audit --adversarial-probes`:

- `v2_test_samples.npy` — full scaled KDDTest+ (22544, 122, 1)
- `v2_test_labels.npy` — encoded labels (22544,)
- `v2_test_attack_samples.npy` — attack-only subset, ~12833 samples
- `v2_test_attack_labels.npy` — matching attack labels

```bash
# Needs scipy / pandas / sklearn / imbalanced-learn / KDD files.
# Easiest to run in the .v2_run venv that already has the deps:
cd .v2_run
.venv/Scripts/python.exe ../mlsecops-agent/scripts/extract_v2_probes.py
```

The arrays land at the repo root. Re-run only when the v2 preprocessing
pipeline changes (column drop, encoder choice, scaler fit, etc.).
