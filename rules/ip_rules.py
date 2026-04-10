def check_ip_rules(data):
    findings = []

    for ip in data.get("floating_ips", []):
        fixed = getattr(ip, "fixed_ip_address", None)
        ip_addr = getattr(ip, "floating_ip_address", "Unknown")

        if not fixed:
            findings.append({
                "check": "Orphaned Floating IP",
                "severity": "LOW",
                "resource": f"Floating IP: {ip_addr}",
                "detail": f"{ip_addr} is allocated but not attached to any instance",
                "remediation": "Release unattached floating IPs to reduce attack surface and save cost.",
            })

    return findings
