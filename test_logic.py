from rules.network_rules import check_network_rules
from rules.storage_rules import check_storage_rules
from rules.ip_rules import check_ip_rules
from scoring.risk_scorer import calculate_score
from reporting.report_generator import generate_report


# Fake OpenStack objects using type() — no real connection needed
dummy_data = {
    "security_groups": [
        type("SG", (), {"id": "sg-001", "name": "default"})(),
        type("SG", (), {"id": "sg-002", "name": "web-servers"})(),
    ],
    "rules": [
        # SSH open to the world
        type("Rule", (), {
            "remote_ip_prefix": "0.0.0.0/0",
            "protocol": "tcp",
            "port_range_min": 22,
            "port_range_max": 22,
            "security_group_id": "sg-001",
        })(),
        # MySQL open to the world
        type("Rule", (), {
            "remote_ip_prefix": "0.0.0.0/0",
            "protocol": "tcp",
            "port_range_min": 3306,
            "port_range_max": 3306,
            "security_group_id": "sg-001",
        })(),
        # Allow-all rule
        type("Rule", (), {
            "remote_ip_prefix": "0.0.0.0/0",
            "protocol": None,
            "port_range_min": None,
            "port_range_max": None,
            "security_group_id": "sg-002",
        })(),
    ],
    "floating_ips": [
        # Unattached floating IP
        type("IP", (), {
            "fixed_ip_address": None,
            "floating_ip_address": "192.168.100.55",
        })(),
    ],
    "volumes": [
        # Unencrypted volume
        type("Volume", (), {
            "encrypted": False,
            "name": "data-vol-01",
            "id": "vol-abc123",
        })(),
    ],
}


findings = []
findings += check_network_rules(dummy_data)
findings += check_ip_rules(dummy_data)
findings += check_storage_rules(dummy_data)

score = calculate_score(findings)
generate_report(findings, score)
