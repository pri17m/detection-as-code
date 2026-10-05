# Quarantine (non-shipping content)

This folder contains **non-shipping** detection placeholders and metadata-only stubs that are kept for future work and reference.

They are intentionally moved out of `detections/` so that:

- they are **not** included in CI validation (`pipelines/validate/validate_repo.py`)
- they are **not** counted in coverage metrics (`content/mitre/coverage.json`)
- they are not mistaken for production-ready detections

Do not assume anything under `quarantine/` is correct or deployable without implementation, validation, and tuning.

