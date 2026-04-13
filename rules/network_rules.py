def check_network_rules(data):
    findings = []

    sg_names = {
        sg.id: sg.name
        for sg in data.get("security_groups", [])
    }

    for rule in data.get("rules", []):
        remote_ip = getattr(rule, "remote_ip_prefix", None)
        protocol = getattr(rule, "protocol", None)
        port_min = getattr(rule, "port_range_min", None)
        port_max = getattr(rule, "port_range_max", None)
        sg_id = getattr(rule, "security_group_id", None)
        sg_name = sg_names.get(sg_id, sg_id)

        is_public = remote_ip in ("0.0.0.0/0", "::/0")

        if not is_public:
            continue

        # SSH open to world
        if protocol == "tcp" and port_min == 22:
            findings.append({
                "check": "Public SSH Access",
                "severity": "HIGH",
                "resource": f"Security Group: {sg_name}",
                "detail": f"Rule allows SSH (port 22) from {remote_ip}",
                "remediation": "Restrict SSH access to known IP ranges only.",
            })

        # RDP open to world
        elif protocol == "tcp" and port_min == 3389:
            findings.append({
                "check": "Public RDP Access",
                "severity": "HIGH",
                "resource": f"Security Group: {sg_name}",
                "detail": f"Rule allows RDP (port 3389) from {remote_ip}",
                "remediation": "Restrict RDP access to known IP ranges only.",
            })

        # Database ports open to world
        elif protocol == "tcp" and port_min in (3306, 5432, 1433):
            db_names = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL"}
            db = db_names[port_min]
            findings.append({
                "check": "Public Database Port",
                "severity": "CRITICAL",
                "resource": f"Security Group: {sg_name}",
                "detail": f"Rule exposes {db} (port {port_min}) from {remote_ip}",
                "remediation": "Database ports should never be publicly accessible. Remove this rule immediately.",
            })

        # HTTP open to world — NEW
        elif protocol == "tcp" and port_min == 80:
            findings.append({
                "check": "Public HTTP Access",
                "severity": "MEDIUM",
                "resource": f"Security Group: {sg_name}",
                "detail": f"Rule allows unencrypted HTTP (port 80) from {remote_ip}",
                "remediation": "Serve traffic over HTTPS (port 443) instead. HTTP transmits data in plaintext.",
            })

        # HTTPS open to world — NEW
        elif protocol == "tcp" and port_min == 443:
            findings.append({
                "check": "Public HTTPS Access",
                "severity": "LOW",
                "resource": f"Security Group: {sg_name}",
                "detail": f"Rule allows HTTPS (port 443) from {remote_ip}",
                "remediation": "Verify this exposure is intentional. Restrict to known IPs if this is an internal service.",
            })

        # Allow-all rule
        elif protocol is None and port_min is None and port_max is None:
            findings.append({
                "check": "Allow-All Rule",
                "severity": "CRITICAL",
                "resource": f"Security Group: {sg_name}",
                "detail": f"Rule allows ALL traffic from {remote_ip} with no protocol or port restriction",
                "remediation": "Replace with specific rules that allow only required ports and protocols.",
            })

    # Security groups with no rules at all — NEW
    sgs_with_rules = {getattr(r, "security_group_id") for r in data.get("rules", [])}
    for sg in data.get("security_groups", []):
        if sg.id not in sgs_with_rules:
            findings.append({
                "check": "Empty Security Group",
                "severity": "LOW",
                "resource": f"Security Group: {sg.name}",
                "detail": f"Security group '{sg.name}' has no rules defined",
                "remediation": "Either configure rules for this security group or delete it if unused.",
            })

    return findings
