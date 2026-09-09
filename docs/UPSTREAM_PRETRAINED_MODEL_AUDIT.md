# Upstream IoT-23 pretrained model audit

Audited on 2026-09-09 for the selected reference repository:
[Iretha/IoT23-network-traffic-anomalies-classification](https://github.com/Iretha/IoT23-network-traffic-anomalies-classification).

## Result

The repository does not contain a complete pretrained model that can be safely loaded by this application. It contains source code for preparing IoT-23 data, fitting several scikit-learn pipelines, and writing experiment results. The public tree exposes `logs`, `output`, `src`, `config.py`, and `versions.py`; the visible `output` tree contains charts and experiment-result directories rather than a committed `.joblib`, `.pkl`, or equivalent model bundle.

The upstream code can create a pickle during a local training run: `src/helpers/model_helper.py` calls `model.fit(...)` and then `pickle.dump(...)` into a generated experiment `models` directory. That is a training output mechanism, not a pretrained artifact shipped by the repository, and it does not include a package that our application can verify against its live extractor.

The repository README also describes a training workflow: download and prepare the dataset, then run `run_demo.py` or `run_experiments.py`. It does not document a model-artifact download or a preprocessing-artifact package.

Evidence:

- [Repository tree](https://github.com/Iretha/IoT23-network-traffic-anomalies-classification/tree/main)
- [README training workflow](https://github.com/Iretha/IoT23-network-traffic-anomalies-classification#option-1-run-demo)
- [Output tree](https://github.com/Iretha/IoT23-network-traffic-anomalies-classification/tree/main/output)
- [Feature metadata and selections](https://github.com/Iretha/IoT23-network-traffic-anomalies-classification/blob/main/src/iot23.py)
- [Demo training code](https://github.com/Iretha/IoT23-network-traffic-anomalies-classification/blob/main/src/run_demo.py)
- [Upstream model creation/loading code](https://github.com/Iretha/IoT23-network-traffic-anomalies-classification/blob/main/src/helpers/model_helper.py)
- [Upstream data preparation and random train/test split](https://github.com/Iretha/IoT23-network-traffic-anomalies-classification/blob/main/src/helpers/data_helper.py)

## Compatibility checks

| Check | Upstream repository | Current application | Result |
|---|---|---|---|
| Serialized model | Training code writes a generated pickle, but no committed reusable model artifact is exposed | Trusted `joblib` bundle required | **Fail** |
| Preprocessing artifact | Hard-coded source mappings and `99` replacement rules | Train-fitted imputer and one-hot encoder embedded in the candidate pipeline | **Fail** |
| Feature contract | F14/F17/F18/F19 variants include ports, protocol/service, connection fields, and in some variants IP addresses, history, local flags, or `tunnel_parents`; the selected feature list also includes `detailed-label` | `zeek-conn-v1`: 8 numeric fields plus `proto`, `service`, and `conn_state` | **Fail** |
| Target contract | `benign`/`Malicious` plus detailed attack labels | `normal`/`attack` binary target | **Requires adaptation** |
| Runtime parity | Training uses preprocessed CSVs and in-memory pipelines; the helper uses a random train/test split | Runtime consumes completed Zeek JSON/TSV connection records and requires capture-disjoint evidence | **Fail for promotion** |
| Dependency parity | README pins scikit-learn 0.24.1 and older Python packages | Current candidate records scikit-learn 1.6.1 | **Fail for direct loading** |

The upstream project is therefore useful as a dataset and experiment reference, but it is not a drop-in model provider. Passing our 11 fields into one of its feature variants, or loading an unverified serialized object if one is found outside Git, would create an unproven schema mismatch.

## Decision in this repository

The Iretha repository is not used as a pretrained model provider. A second inspection selected the public `iot-audit` repository because it publishes a complete LightGBM pipeline with preprocessing in `models/binary_lightgbm.joblib`:

[iot-audit model directory](https://github.com/emanuelepiodebernardis/iot-audit/tree/main/models)

The artifact is copied into the ignored local runtime directory and loaded by `backend.iot_audit_candidate`. Its exact 13-field contract, SHA-256, serialized dependency version, and binary class mapping are verified before use. It is displayed as an offline candidate only.

The application keeps the existing real-data IoT-23 candidate as its live-model fallback:

`runtime/iot23-model-v2-20260909/model.joblib`

`backend.detection.Detector` continues to require all of the following before loading a model:

- exact `zeek-conn-v1` schema and feature list;
- `real_iot23` provenance;
- matching scikit-learn version;
- typed evaluation report;
- model hash linked to local promotion evidence;
- independent live validation before `response_eligible` becomes true.

The IoT-23 candidate remains ineligible because its untouched test recall is `0.34375` and its false-positive rate is `0.195967`. The new iot-audit candidate also remains ineligible: its cross-dataset IoT-23 test false-positive rate is `0.9053` and its ROC AUC is `0.134`. Live predictions and automated response remain gated. See [IOT_AUDIT_CANDIDATE.md](IOT_AUDIT_CANDIDATE.md) for the full artifact and evaluation record.

## What would make integration possible

Integration can be reconsidered only when a specific upstream artifact is supplied together with:

1. the exact serialized pipeline or separately serialized preprocessing objects;
2. the exact feature-selection variant and column order;
3. the training dependency versions;
4. a hash for every artifact;
5. an independent capture-disjoint evaluation report; and
6. live validation using the same Zeek extractor used by this application.

Until then, the current candidate remains the only locally reproducible model, and its failed quality gate is intentionally visible in the dashboard.
