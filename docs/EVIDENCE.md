# Evidence Export

`scripts/export_evidence.py` creates a repeatable, local evidence bundle from one exact `run_id` and `origin` selection in the runtime SQLite database. It accepts only `live` and `dataset`; synthetic/demo rows are rejected as evidence.

The database is opened through SQLite read-only URI mode. The exporter copies stored `traffic` predictions, matching `alerts`, matching `blocks`, and matching events into JSON. It does not run inference, call the network, invoke a firewall adapter, or alter the database.

## Command

```powershell
python scripts/export_evidence.py `
  --db runtime/iot.sqlite3 `
  --run-id <runtime-run-id> `
  --origin live `
  --output runtime/evidence/<run-id> `
  --source-conn-log C:\path\to\conn.log
```

`--source-conn-log` is optional. When an existing file is supplied, the bundle records its path and SHA-256 without copying or modifying it. Without one, the source reference is explicitly marked missing.

The default export does not create parquet. An optional `--parquet` flag may export `flows.parquet` and `features.parquet` only when the selected stored traffic rows already contain real feature records; missing features fail the export rather than being fabricated. PCAP is never created.

## Bundle and integrity

The bundle contains `predictions.json`, `alerts.json`, `firewall.json`, `report.json`, `report.md`, `provenance.json`, and `manifest.json`; optional parquet files are included only when requested and backed by stored features. The manifest includes SHA-256 and byte-size entries for every generated artifact, plus `report_sha256` and `provenance_sha256` fields. Selection is exact on both run ID and origin; rows from other runs or origins are excluded.

`firewall.json` reports stored application block rows only. Every exported row is forced to `verified: false` and `verification: not_performed`; legacy `blocked` and `simulated_block` statuses are retained but labeled `legacy_unverified`. New `dry_run`, `block_requested`, `block_applied`, `block_failed`, and `released` statuses remain application states, not independent proof that an OS or gateway rule was installed. The export itself takes no firewall action.

By default the manifest explicitly lists `pcap`, `parquet`, and `verified_blocks` as missing artifacts. With `--parquet`, parquet is present only as a hash-checked export of stored flow/features; the exporter never fabricates packet captures or parquet rows and never marks blocks as verified. A runtime export is therefore evidence of stored traffic and application outputs, not proof of a working detector, live protection, or a complete experiment.

## Interpretation limits

This bundle does not re-evaluate the model. The corrected v2 candidate remains a failed gate: untouched test recall 34.375%, 21 missed attacks and 933 false alarms. Historical filtered evaluation had zero recall. Read evidence alongside its corresponding model report; recorded traffic is not live validation.

The exporter does not manufacture missing provenance. It carries `model_sha256`, `schema`, and `model_scope` values from selected traffic rows into the report, provenance, and manifest, and marks model provenance incomplete when required fields are absent. If a source `conn.log`, PCAP, parquet conversion, independent firewall observation, or other artifact was not stored or supplied, the manifest keeps that gap visible for audit and follow-up collection.

## ML evaluation population

New `ml.train` runs report `real-iot23-evaluation-v2`. The primary model is fit on the untouched capture-disjoint train partition, selects its threshold on the untouched validation partition, and reports untouched validation/test metrics plus per-capture test metrics. Exact-feature overlap removal is not used to tune the primary threshold or test result.

The prior exact-feature-exclusion methodology remains under `secondary_filtered_evaluation` as a diagnostic, with its own validation-derived threshold and metrics. `capture_counts_before_after` records normal/attack counts for every capture before and after that diagnostic filter. A single-class capture reports undefined AUC and undefined rates whose denominator is absent as JSON `null`, with an explanatory note; it is not treated as a zero-quality score.

Training refuses to overwrite existing artifacts. The actual corrected run is runtime/iot23-model-v2-20260909 and still fails its gate. Evidence from 237 genuine historical connections is saved at evidence/iot23-recorded-20260909. It includes eight hashed output artifacts, source conn.log hash and model hash; PCAP and block verification are absent.
