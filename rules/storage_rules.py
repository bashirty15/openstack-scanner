def check_storage_rules(data):
    findings = []

    for vol in data.get("volumes", []):
        encrypted = getattr(vol, "encrypted", False)
        vol_name = getattr(vol, "name", None) or getattr(vol, "id", "Unknown")

        if not encrypted:
            findings.append({
                "check": "Unencrypted Volume",
                "severity": "MEDIUM",
                "resource": f"Volume: {vol_name}",
                "detail": f"Volume '{vol_name}' does not have encryption enabled",
                "remediation": "Enable volume encryption to protect data at rest.",
            })

    return findings
