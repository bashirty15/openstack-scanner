from rules.network_rules import check_network_rules
from rules.storage_rules import check_storage_rules
from rules.ip_rules import check_ip_rules
from scoring.risk_scorer import calculate_score
from reporting.report_generator import generate_report

dummy_data = {
    "rules": [
        type("Rule", (), {
            "remote_ip_prefix": "0.0.0.0/0",
            "protocol": "tcp",
            "port_range_min": 22,
            "port_range_max": 22
        })(),
        type("Rule", (), {
            "remote_ip_prefix": "0.0.0.0/0",
            "protocol": "tcp",
            "port_range_min": 3306,
            "port_range_max": 3306
        })(),
    ],
    "floating_ips": [
        type("IP", (), {
            "fixed_ip_address": None
        })()
    ],
    "volumes": [
        type("Volume", (), {
            "encrypted": False
        })()
    ]
}

findings = []
findings += check_network_rules(dummy_data)
findings += check_ip_rules(dummy_data)
findings += check_storage_rules(dummy_data)

score = calculate_score(findings)

generate_report(findings, score)