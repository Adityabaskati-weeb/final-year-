"""Export repeatable evidence from one stored runtime run without side effects."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3


REAL_ORIGINS = {"live", "dataset"}
TABLES = ("traffic", "alerts", "blocks", "events")
LEGACY_FIREWALL_STATUSES = {"blocked", "simulated_block"}
MISSING_ARTIFACTS = (
    ("pcap", "This exporter never creates or infers packet captures."),
    ("parquet", "This exporter never creates or infers parquet data."),
    ("verified_blocks", "No independent firewall verification is stored by this exporter."),
)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_only_database(path):
    path = Path(path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"SQLite database not found: {path}")
    database = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    database.execute("PRAGMA query_only=ON")
    return database, path


def _table_names(database):
    return {row[0] for row in database.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def _table_rows(database, table, table_names):
    if table not in table_names:
        return []
    rows = []
    for row_id, stored_ts, payload in database.execute(
            f"SELECT id, ts, data FROM {table} ORDER BY ts ASC, id ASC"):
        try:
            row = json.loads(payload)
        except (TypeError, json.JSONDecodeError) as error:
            raise ValueError(f"Invalid JSON in {table} row {row_id}") from error
        if not isinstance(row, dict):
            raise ValueError(f"Expected object in {table} row {row_id}")
        row.setdefault("id", row_id)
        row.setdefault("stored_ts", stored_ts)
        rows.append(row)
    return rows


def _selected(rows, run_id, origin):
    return [row for row in rows
            if row.get("run_id") == run_id and row.get("origin") == origin]


def _count_values(rows, key):
    return {str(value): int(count) for value, count in sorted(
        Counter(row.get(key) for row in rows if row.get(key) is not None).items(),
        key=lambda item: str(item[0]))}


def _model_provenance(rows):
    values = {}
    missing_rows = {}
    for key in ("model_sha256", "schema", "model_scope"):
        values[key] = sorted({str(row[key]) for row in rows
                              if row.get(key) not in (None, "")})
        missing_rows[key] = sum(row.get(key) in (None, "") for row in rows)
    required = ("model_sha256", "schema")
    return {
        **values,
        "status": "complete" if not any(missing_rows[key] for key in required) else "incomplete",
        "rows": len(rows),
        "missing_rows": missing_rows,
        "missing_fields": [key for key in required if missing_rows[key]],
    }


def _firewall_rows(rows, run_id):
    normalized = []
    for row in rows:
        item = dict(row)
        item.pop("verified", None)
        item.pop("verification", None)
        item["run_id"] = item.get("run_id") or run_id
        item["scope"] = item.get("scope") or "unknown"
        item["verified"] = False
        item["verification"] = "not_performed"
        item["status_semantics"] = (
            "legacy_unverified" if item.get("status") in LEGACY_FIREWALL_STATUSES
            else "application_status_unverified")
        normalized.append(item)
    return normalized


def _write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _artifact(path, name):
    path = Path(path)
    return {"name": name, "path": name, "bytes": path.stat().st_size,
            "sha256": sha256_file(path), "status": "present"}


def _source_reference(path):
    if path is None:
        return {"status": "missing", "path": None, "sha256": None,
                "reason": "No --source-conn-log was supplied."}
    path = Path(path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Source conn.log not found: {path}")
    return {"status": "available", "path": str(path), "sha256": sha256_file(path)}


def export_evidence(database_path, run_id, origin, output, source_conn_log=None, parquet=False):
    """Export one exact runtime selection and return the manifest object.

    The database is opened with SQLite's read-only URI mode and this function
    never calls model, network, or firewall code.
    """
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("run_id must be a non-empty string")
    if origin not in REAL_ORIGINS:
        raise ValueError("origin must be live or dataset; synthetic/demo data is not evidence")

    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError(f"Evidence output already exists: {output}")

    database, database_path = _read_only_database(database_path)
    try:
        database.execute("BEGIN")
        table_names = _table_names(database)
        tables = {table: _table_rows(database, table, table_names) for table in TABLES}
        traffic = _selected(tables["traffic"], run_id, origin)
        if not traffic:
            raise ValueError(f"No stored traffic for run_id={run_id!r}, origin={origin!r}")
        alerts = _selected(tables["alerts"], run_id, origin)
        blocks = _firewall_rows(_selected(tables["blocks"], run_id, origin), run_id)
        events = _selected(tables["events"], run_id, origin)
        unscoped_blocks = [row for row in tables["blocks"]
                           if row.get("origin") == origin and row.get("run_id") is None]
    finally:
        database.close()

    source_reference = _source_reference(source_conn_log)
    if parquet:
        import pyarrow as pa
        import pyarrow.parquet as pq
        if any(not isinstance(row.get("features"), dict) or not row["features"] for row in traffic):
            raise ValueError("Parquet requires stored real feature records; missing features are not fabricated")
    model_provenance = _model_provenance(traffic)
    database_files = []
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(database_path) + suffix)
        if candidate.is_file():
            database_files.append({"path": str(candidate), "sha256": sha256_file(candidate)})

    output.mkdir(parents=True)
    selection = {"run_id": run_id, "origin": origin}
    _write_json(output / "predictions.json", {
        **selection,
        "source_table": "traffic",
        "rows": traffic,
    })
    _write_json(output / "alerts.json", {
        **selection,
        "source_table": "alerts",
        "rows": alerts,
    })
    _write_json(output / "firewall.json", {
        **selection,
        "source_table": "blocks",
        "observed_blocks": blocks,
        "unscoped_same_origin_rows_excluded": len(unscoped_blocks),
        "verification": {
            "status": "not_performed",
            "verified": False,
            "reason": "Stored block intent/status is not independent firewall verification.",
        },
        "status_counts": _count_values(blocks, "status"),
        "exporter_actions": {"network": False, "firewall": False},
    })

    report = {
        "report_version": "runtime-evidence-v1",
        **selection,
        "status": "stored_runtime_traffic_export",
        "traffic_rows": len(traffic),
        "alert_rows": len(alerts),
        "observed_firewall_rows": len(blocks),
        "prediction_counts": _count_values(traffic, "prediction"),
        "ground_truth_counts": _count_values(traffic, "ground_truth"),
        "event_rows": len(events),
        "firewall_verification": "not_performed",
        "model_provenance": model_provenance,
        "model_performance_evaluated": False,
        "live_protection_verified": False,
        "network_actions_taken_by_exporter": False,
        "firewall_actions_taken_by_exporter": False,
    }
    _write_json(output / "report.json", report)
    (output / "report.md").write_text(
        f"# Experiment Record\n\nRun: {run_id}\n\nOrigin: {origin}\n\n"
        f"Stored connections: {len(traffic)}; alerts: {len(alerts)}.\n\n"
        "This export does not evaluate model accuracy or verify a block. "
        "Historical dataset records are not a live sensor experiment. "
        "See manifest.json and provenance.json for hashes and missing evidence.\n",
        encoding="utf-8")
    if parquet:
        flow_keys = ("id", "uid", "run_id", "origin", "capture_id", "started_at", "ended_at",
                     "source_ip", "destination_ip", "source_port", "destination_port", "protocol")
        pq.write_table(pa.Table.from_pylist([{key: row.get(key) for key in flow_keys} for row in traffic]), output / "flows.parquet")
        pq.write_table(pa.Table.from_pylist([{"id": row["id"], "uid": row.get("uid"),
                       "model_sha256": row.get("model_sha256"), **row["features"]} for row in traffic]), output / "features.parquet")

    provenance = {
        "provenance_version": "runtime-evidence-v1",
        **selection,
        "database": {
            "path": str(database_path),
            "files": database_files,
            "selection_mode": "sqlite_read_only_uri",
        },
        "source_tables": {"predictions": "traffic", "alerts": "alerts",
                          "firewall": "blocks", "events": "events"},
        "source_conn_log": source_reference,
        "model_provenance": model_provenance,
        "limitations": [
            "Rows are copied from stored runtime records; no new model inference was run.",
            "PCAP is not created. Optional parquet files contain only stored flow/feature values.",
            "Database file hashes describe files observed after the read transaction, not an atomic backup.",
            "Source conn.log is a caller-supplied reference; its hash alone does not establish row correspondence.",
            "Firewall records are observations of stored application state, not verified OS rules.",
        ],
    }
    _write_json(output / "provenance.json", provenance)

    artifacts = [_artifact(output / name, name) for name in (
        "predictions.json", "alerts.json", "firewall.json", "report.json", "provenance.json", "report.md")]
    if parquet:
        artifacts.extend(_artifact(output / name, name) for name in ("flows.parquet", "features.parquet"))
    missing = [{"name": name, "status": "missing", "reason": reason}
               for name, reason in MISSING_ARTIFACTS if not (parquet and name == "parquet")]
    report_hash = next(item["sha256"] for item in artifacts if item["name"] == "report.json")
    provenance_hash = next(item["sha256"] for item in artifacts if item["name"] == "provenance.json")
    manifest = {
        "manifest_version": "runtime-evidence-v1",
        **selection,
        "hash_algorithm": "sha256",
        "artifacts": artifacts,
        "report_sha256": report_hash,
        "provenance_sha256": provenance_hash,
        "model_provenance": model_provenance,
        "source_conn_log": source_reference,
        "missing_artifacts": missing,
    }
    _write_json(output / "manifest.json", manifest)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path("runtime/iot.sqlite3"),
                        help="Local SQLite runtime database; opened read-only")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--origin", required=True, choices=sorted(REAL_ORIGINS))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-conn-log", type=Path,
                        help="Optional existing source conn.log to reference and hash")
    parser.add_argument("--parquet", action="store_true", help="Export stored real flows/features; requires requirements-evidence.txt")
    args = parser.parse_args(argv)
    try:
        manifest = export_evidence(args.db, args.run_id, args.origin, args.output,
                                   args.source_conn_log, args.parquet)
    except (FileExistsError, FileNotFoundError, OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    main()
