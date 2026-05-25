# Fixtures

Two fixtures per check, minimum:

- `positive_*` — code containing the issue the check must flag
- `negative_*` — superficially similar code the check must *not* flag

The eval harness consumes everything in this folder and asserts the finding set against `EVAL_BASELINE.json`. A check is not "done" until both fixture types pass.

## Layout

```
fixtures/
├── leakage/
│   ├── positive_smote_before_split.py
│   ├── positive_difficulty_proxy.ipynb
│   ├── negative_correct_split_order.py
│   └── negative_smote_in_pipeline.py
├── deserialization/
│   ├── positive_joblib_load.py
│   ├── negative_safetensors_load.py
│   └── ...
└── EVAL_BASELINE.json
```

## EVAL_BASELINE.json

The expected finding set per fixture. Generated once a check is stable; updated only via explicit `chore: bump eval baseline` commits.
