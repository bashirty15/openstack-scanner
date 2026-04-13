from rules.network_rules import check_network_rules
from rules.storage_rules import check_storage_rules
from rules.ip_rules import check_ip_rules
from rules.compute_rules import check_compute_rules
from rules.identity_rules import check_identity_rules
from scoring.risk_scorer import calculate_score
from reporting.report_generator import generate_report


dummy_data = {
    # --- Neutron ---
    "security_groups": [
        type("SG", (), {"id": "sg-001", "name": "default"})(),
        type("SG", (), {"id": "sg-002", "name": "web-servers"})(),
        type("SG", (), {"id": "sg-003", "name": "empty-sg"})(),     # no rules
    ],
    "rules": [
        type("Rule", (), {"remote_ip_prefix": "0.0.0.0/0", "protocol": "tcp", "port_range_min": 22,   "port_range_max": 22,   "security_group_id": "sg-001"})(),  # SSH
        type("Rule", (), {"remote_ip_prefix": "0.0.0.0/0", "protocol": "tcp", "port_range_min": 3306, "port_range_max": 3306, "security_group_id": "sg-001"})(),  # MySQL
        type("Rule", (), {"remote_ip_prefix": "0.0.0.0/0", "protocol": "tcp", "port_range_min": 80,   "port_range_max": 80,   "security_group_id": "sg-002"})(),  # HTTP
        type("Rule", (), {"remote_ip_prefix": "0.0.0.0/0", "protocol": "tcp", "port_range_min": 443,  "port_range_max": 443,  "security_group_id": "sg-002"})(),  # HTTPS
        type("Rule", (), {"remote_ip_prefix": "0.0.0.0/0", "protocol": None,  "port_range_min": None, "port_range_max": None, "security_group_id": "sg-002"})(),  # allow-all
    ],

    # --- Neutron floating IPs ---
    "floating_ips": [
        type("IP", (), {"fixed_ip_address": None, "floating_ip_address": "192.168.100.55"})(),
    ],

    # --- Cinder ---
    "volumes": [
        type("Volume", (), {"encrypted": False, "name": "data-vol-01",     "id": "vol-1", "status": "in-use",   "attachments": [{"server_id": "srv-1"}]})(),  # unencrypted, attached
        type("Volume", (), {"encrypted": False, "name": "unattached-vol",  "id": "vol-2", "status": "available","attachments": []})(),                         # unencrypted + unattached
        type("Volume", (), {"encrypted": True,  "name": "broken-vol",      "id": "vol-3", "status": "error",    "attachments": []})(),                         # error state
    ],

    # --- Nova ---
    "servers": [
        type("Server", (), {"name": "web-01",      "id": "srv-1", "status": "ACTIVE", "security_groups": [{"name": "default"}]})(),  # normal
        type("Server", (), {"name": "no-sg-server","id": "srv-2", "status": "ACTIVE", "security_groups": []})(),                      # no SG
        type("Server", (), {"name": "broken-vm",   "id": "srv-3", "status": "ERROR",  "security_groups": [{"name": "default"}]})(),  # error state
    ],

    # --- Keystone ---
    "roles": [
        type("Role", (), {"id": "role-admin", "name": "admin"})(),
        type("Role", (), {"id": "role-member","name": "member"})(),
    ],
    "users": [
        type("User", (), {"id": "u-001", "name": "admin",       "is_enabled": True,  "last_active_at": "2026-01-01"})(),  # expected admin
        type("User", (), {"id": "u-002", "name": "barry",       "is_enabled": True,  "last_active_at": "2026-03-01"})(),  # normal user
        type("User", (), {"id": "u-003", "name": "test-user",   "is_enabled": True,  "last_active_at": None})(),          # never logged in
        type("User", (), {"id": "u-004", "name": "rogue-admin", "is_enabled": True,  "last_active_at": "2026-02-01"})(),  # unexpected admin
    ],
    "role_assignments": [
        type("RA", (), {"role_id": "role-admin",  "user_id": "u-001"})(),  # admin user → expected
        type("RA", (), {"role_id": "role-admin",  "user_id": "u-004"})(),  # rogue-admin → flag this
        type("RA", (), {"role_id": "role-member", "user_id": "u-002"})(),  # barry → fine
    ],
}


findings = []
findings += check_network_rules(dummy_data)
findings += check_ip_rules(dummy_data)
findings += check_storage_rules(dummy_data)
findings += check_compute_rules(dummy_data)
findings += check_identity_rules(dummy_data)

score = calculate_score(findings)
generate_report(findings, score)
