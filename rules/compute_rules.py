def check_compute_rules(data):
    findings = []

    for server in data.get("servers", []):
        server_name = getattr(server, "name", None) or getattr(server, "id", "Unknown")
        status = getattr(server, "status", "").upper()
        security_groups = getattr(server, "security_groups", [])

        # Instance with no security group — NEW
        if not security_groups:
            findings.append({
                "check": "Instance With No Security Group",
                "severity": "HIGH",
                "resource": f"Instance: {server_name}",
                "detail": f"Instance '{server_name}' has no security group assigned — it has no firewall protection",
                "remediation": "Assign at least one security group with appropriate rules to this instance.",
            })

        # Instance in error state — NEW
        if status == "ERROR":
            findings.append({
                "check": "Instance in Error State",
                "severity": "MEDIUM",
                "resource": f"Instance: {server_name}",
                "detail": f"Instance '{server_name}' is in ERROR state — may indicate a misconfiguration or resource issue",
                "remediation": "Investigate via 'openstack server show' and check Nova logs for the root cause.",
            })

    return findings
