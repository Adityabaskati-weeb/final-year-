# Real-data ML Pipeline

## Schema

zeek-conn-v1: duration, orig_bytes, resp_bytes, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes, missed_bytes, proto, service, conn_state.

These are 8 numeric and 3 categorical fields from Zeek conn.log. This replaces the former 13-field synthetic-trained model. The number of features does not determine whether data is real; provenance and extraction do.

IP addresses, ports, identifiers, timestamps and labels are metadata, not predictors. Optional missing numeric fields are imputed using training medians; categories use one-hot encoding with unknown-category handling. No scaling is needed for this tree model.

## Provenance and evaluation

Official source: https://www.stratosphereips.org/datasets-iot23
Download directory: https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/

scripts/download_iot23.py downloads labelled connection logs only, not malware binaries. Nine preselected captures are assigned to train/validation/test before fitting. Manifests retain capture IDs, URLs and SHA-256 hashes. Captures and identical files cannot cross splits. Coarse feature overlaps are reported in a secondary diagnostic, not excluded from the primary holdout population. Capture splitting does not eliminate all near-duplicate or environmental leakage.

The training pipeline fits preprocessing on training only and chooses a probability threshold using validation only. Test data is evaluated afterward, not used for tuning. The subset is small and unrepresentative, especially its attack counts. It is not the full IoT-23 benchmark.

Historical filtered run: train 37,209; validation 2,300; test 3,217 rows after overlap filtering. Threshold 0.98. Test confusion matrix [[2914,283],[20,0]] (normal, attack order). Accuracy 0.9058128691; recall/precision/F1/F2 0; FPR 0.088520488. Preserved, not overwritten.

Current v2 primary evaluation uses untouched capture-disjoint holdouts, not exclusion of coincident coarse feature vectors. Test has 4,793 connections; confusion [[3828,933],[21,11]], accuracy 0.80095973, precision 0.01165254, recall 0.34375, F1 0.02254098, F2 0.05130597, ROC-AUC 0.54082979, average precision 0.00891011, FPR 0.19596723, FNR 0.65625. Candidate still FAILS. Full split distributions/per-capture metrics and the secondary overlap diagnostic are in runtime/iot23-model-v2-20260909/evaluation.json. No hyperparameters were tuned against test scores.

The artifact is saved as a candidate even when evaluation fails. Offline eligibility requires recall >=0.8 and FPR <=0.05. Live use additionally requires independent live validation; this run sets live_validated=false. Do not edit report flags to bypass validation.

The separate local lab pipeline uses the same 11-field contract with the `scapy-lab-flow-v1` extractor. It was trained only from labelled captures of the registered ESP32 and promoted through `promotion.json` after independent test sessions met the same sample and quality gates. Its current evidence is 108 normal and 50 bounded private-probe flows with recall 1.0 and FPR 0.0. Those numbers are deliberately scoped to this device, topology, extractor and experiment; they do not replace the failed IoT-23 evaluation or establish general IoT detection.

An optional second-stage trainer is available as `python -m ml.train_attack_type`. It consumes the same manifest and requires explicit `attack_type` labels, at least two attack families plus `normal` in every split, and capture-disjoint evaluation. Its artifact is never loaded for live traffic unless it has independent validation evidence and a matching `promotion.json`. Until then, binary detection falls back to the documented `tcp_connection_probe` lab attribution or `unknown_attack_pattern`.

Newly trained artifacts record `data_quality` coverage: independent captures,
device IDs, attack families, and extractor identity. Run
`python scripts/audit_model_scope.py --model <path-to-model.joblib>` before
making a deployment claim. A model trained from one registered ESP32 remains a
registered-device model even when its held-out score is perfect.

Current outputs: runtime/iot23-model-v2-20260909/model.joblib and evaluation.json. Select the artifact explicitly with run_project.py --model. Candidate predicts normal/attack only, not attack families. Probabilities are not calibrated; explanations are descriptive, not causal. Promotion also requires typed fields and a model-hash-linked independent live-evidence record; see LAB_RUNBOOK.md.

## Next experiment

Expand independently sourced attack and benign captures, pre-register new capture/device/day-disjoint splits, retrain and measure false alarms and attack recall. Keep this failed test result in the experiment history; repeated optimization against it is test leakage. Use the same actual Zeek extractor/version/settings on labelled lab captures and live traffic. Validate ESP32 and other devices separately. Temperature anomalies are not proof of a cyberattack.

## References

The Iretha project was inspected as a training-workflow reference:
https://github.com/Iretha/IoT23-network-traffic-anomalies-classification

No code was copied from it in this integration. Its available models are not assumed compatible. Dataset authors: Stratosphere Laboratory. Follow source attribution/license requirements before redistribution; downloaded data is ignored by Git.

Zeek field documentation: https://docs.zeek.org/en/current/reference/logs/conn.html
