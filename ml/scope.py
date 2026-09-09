"""Data-coverage and deployment-scope summaries for trained model reports."""


def summarize_sources(sources, provenance):
    """Describe what a model has actually seen without inferring missing labels."""
    capture_ids = sorted({str(source.get("capture_id")) for source in sources
                          if source.get("capture_id")})
    device_ids = sorted({str(source.get("device_id")) for source in sources
                         if source.get("device_id")})
    attack_types = sorted({str(source.get("attack_type")) for source in sources
                           if source.get("attack_type")})
    extractors = sorted({str(source.get("extractor")) for source in sources
                         if source.get("extractor")})

    if provenance == "real_lab_capture":
        deployment_scope = "multi_device_lab" if len(device_ids) >= 2 else "registered_device_only"
    else:
        deployment_scope = "offline_dataset_only"

    warnings = []
    if provenance == "real_lab_capture" and len(device_ids) < 2:
        warnings.append("Only one or zero device IDs are represented; do not claim cross-device generalization.")
    if provenance == "real_lab_capture" and len(attack_types) < 2:
        warnings.append("Fewer than two labelled attack families are represented; attack-type classification is not supported.")
    if len(capture_ids) < 3:
        warnings.append("Fewer than three independent captures are represented; estimate uncertainty before deployment.")

    return {
        "capture_count": len(capture_ids),
        "capture_ids": capture_ids,
        "device_count": len(device_ids),
        "device_ids": device_ids,
        "attack_type_count": len(attack_types),
        "attack_types": attack_types,
        "extractors": extractors,
        "deployment_scope": deployment_scope,
        "warnings": warnings,
    }
