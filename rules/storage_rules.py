def check_storage_rules(data):
    findings = []

    for vol in data.get("volumes", []):
        encrypted = getattr(vol, "encrypted", False)
        vol_name = getattr(vol, "name", None) or getattr(vol, "id", "Unknown")
        status = getattr(vol, "status", "").lower()
        attachments = getattr(vol, "attachments", [])

        # Unencrypted volume
        if not encrypted:
            findings.append({
                "check": "Unencrypted Volume",
                "severity": "MEDIUM",
                "resource": f"Volume: {vol_name}",
                "detail": f"Volume '{vol_name}' does not have encryption enabled",
                "remediation": "Enable volume encryption to protect data at rest.",
            })

        # Volume in error state — NEW
        if status == "error":
            findings.append({
                "check": "Volume in Error State",
                "severity": "MEDIUM",
                "resource": f"Volume: {vol_name}",
                "detail": f"Volume '{vol_name}' is in an error state — this may indicate infrastructure or configuration issues",
                "remediation": "Investigate the volume error via 'openstack volume show' and check Cinder logs.",
            })

        # Volume not attached to any instance — NEW
        if status == "available" and not attachments:
            findings.append({
                "check": "Unattached Volume",
                "severity": "LOW",
                "resource": f"Volume: {vol_name}",
                "detail": f"Volume '{vol_name}' is allocated but not attached to any instance",
                "remediation": "Attach the volume to an instance or delete it if no longer needed to reduce cost and attack surface.",
            })

    return findings
