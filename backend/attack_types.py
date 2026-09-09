"""Conservative attribution for the controlled live-lab attack patterns.

The promoted live model is binary.  This module only names a pattern when the
flow matches a documented lab experiment; it is not presented as a trained
multi-class attack-family classifier.
"""


def classify_live_flow(flow: dict, result: dict, family_detector=None) -> dict:
    """Add a bounded lab attribution to a binary live-model result."""
    if result.get("prediction") != "malicious":
        return result

    if family_detector is not None and family_detector.compatible_extractor(flow.get("extractor")):
        family = family_detector.predict(flow["features"])
        if family is not None and family[0] != "normal":
            attack_type, confidence = family
            return {
                **result,
                "attack_type": attack_type,
                "classification_source": "trained_multiclass",
                "attack_type_confidence": confidence,
                "reasons": [
                    *result.get("reasons", []),
                    f"Promoted attack-family model classified this flow as {attack_type}",
                ],
            }

    protocol = str(flow.get("protocol", "")).lower()
    destination_port = flow.get("destination_port")
    if protocol == "tcp" and destination_port == 80:
        return {
            **result,
            "attack_type": "tcp_connection_probe",
            "classification_source": "lab_attribution",
            "reasons": [
                *result.get("reasons", []),
                "Lab attribution: bounded TCP connection probe against the registered private sensor",
            ],
        }

    return {
        **result,
        "attack_type": "unknown_attack_pattern",
        "classification_source": "binary_only",
        "reasons": [
            *result.get("reasons", []),
            "Binary attack detected, but this flow does not match a documented lab attribution",
        ],
    }
