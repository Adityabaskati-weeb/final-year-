# GitHub model/repository audit

Inspected on 2026-09-09. These projects were treated as references; no third-party model artifact or code was copied into this repository. README claims were not accepted as validation evidence. The selected IoT-23 repository received a separate artifact-level audit in [UPSTREAM_PRETRAINED_MODEL_AUDIT.md](UPSTREAM_PRETRAINED_MODEL_AUDIT.md).

| Repository | Data and model | Input compatibility | Reproducibility / risk | Decision |
|---|---|---|---|---|
| [Adithi1367/CICIoT2023-project](https://github.com/Adithi1367/CICIoT2023-project) | CICIoT2023; XGBoost; README describes 39 flow features and binary/multiclass attack categories; dataset is external | Not compatible with this live path: its API example uses CIC-specific names such as `Header_Length`, `Rate`, `syn_flag_number`, `TCP`, `HTTP`, not the Zeek `conn.log` contract | Training and Flask code are present, but dataset is not. README reports about 85% overall accuracy and notes class imbalance | Useful reference for CIC ingestion only; do not pad or rename live Zeek fields into this model |
| [lynnazz3/ML-project-IOT-IDS](https://github.com/lynnazz3/ML-project-IOT-IDS) | CICIoT2023-oriented LightGBM, differential-evolution threshold/feature work, FastAPI and Docker | Requires its exact CIC feature engineering and external artifacts; no demonstrated parity with the current Zeek JSON flow | Deployment shape is relevant, but external model artifacts and training assumptions must be retrieved/rebuilt before use | Borrow deployment ideas only; not a drop-in model |
| [rafiahkhan/iot-intrusion-detection-ml](https://github.com/rafiahkhan/iot-intrusion-detection-ml) | CICIoT2023; Decision Tree, Random Forest, SVM and KNN; README advertises 99%+ accuracy | CIC feature schema differs from this project's 11 Zeek fields | Group/capture split methodology is the useful part; aggregate accuracy is not evidence of live generalization without independent replay | Reference evaluation methodology; do not import the reported model |
| [Iretha/IoT23-network-traffic-anomalies-classification](https://github.com/Iretha/IoT23-network-traffic-anomalies-classification) | IoT-23 labelled Zeek/Bro connection logs; source-level RF/scaler workflow in `src/iot23.py` and `src/run_demo.py`; `model_helper.py` writes pickles only after a local training run; no committed reusable model bundle found in the public tree | Closest data representation: IoT-23 `conn.log.labeled` is the source family used here, but its F14/F17/F18/F19 variants have different columns, encodings and targets | README requires preparing data and running training; output contains experiment results rather than a shipped model artifact. Its random train/test split is not evidence for our capture-disjoint live gate | Best reference for dataset and split context; current code independently implements a smaller 11-field Zeek contract and validates it |
| [DevSecOpsLab-CSIE-NPU/schema-portable-ee-ids](https://github.com/DevSecOpsLab-CSIE-NPU/schema-portable-ee-ids) | Research-oriented schema portability, early exit and edge deployment; supports multiple datasets as documented by the project | Not a drop-in extractor or artifact for this project; its encoder and dataset adapters are different | Heavy research/deployment dependency surface; reported results cannot be transferred to this model | Future methodology reference, not current integration |
| [emanuelepiodebernardis/iot-audit](https://github.com/emanuelepiodebernardis/iot-audit) | Multi-dataset IoT/IIoT supervised pipeline with feature engineering and interpretability | Dataset-specific loaders/features; no verified Zeek-live parity with this app | Useful for external validation and reporting ideas, but requires its own data and dependency setup | Future cross-dataset evaluation reference |
| [comsyssec/datasets](https://github.com/comsyssec/datasets) | Dataset catalogue/ingestion mappings, not a compatible trained model | Provides sources rather than this app's inference contract | Dataset licensing, versions and transformations still need independent checks | Reference for adding future real datasets |

## Selected path

The current choice is IoT-23 labelled Zeek connection logs plus a Random Forest because the public data is already in the same family as the runtime extractor and the implementation remains lightweight. The canonical fields are:

`duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `orig_ip_bytes`, `resp_pkts`, `resp_ip_bytes`, `missed_bytes`, `proto`, `service`, `conn_state`.

The live path uses actual Zeek JSON or an authenticated forwarder. It does not convert arbitrary Scapy packet summaries into these fields. A CICIoT2023 model can be evaluated later only after implementing its exact flow extractor and preprocessing and retraining/evaluating with capture-disjoint splits.

## Current evidence

The real IoT-23 v2 candidate in `runtime/iot23-model-v2-20260909` uses untouched capture-disjoint evaluation: accuracy 0.80096, recall 0.34375, precision 0.01165 and false-positive rate 0.19597. It is ineligible and `live_validated=false`. This result is why the backend returns `UNKNOWN` for live telemetry and does not trigger alarms or automated response.

## Licenses and reuse

Review each repository's current license and the dataset's own terms before redistributing code or data. This repository stores download manifests and hashes, not the IoT-23 dataset itself. External repository claims are links for audit, not endorsements or reproduced benchmarks.
