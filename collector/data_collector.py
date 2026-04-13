def collect_data(conn):
    data = {
        "security_groups": [],
        "rules": [],
        "servers": [],
        "floating_ips": [],
        "volumes": [],
        "users": [],
    }

    try:
        data["security_groups"] = list(conn.network.security_groups())
    except Exception as e:
        print(f"  [!] Could not collect security groups: {e}")

    try:
        data["rules"] = list(conn.network.security_group_rules())
    except Exception as e:
        print(f"  [!] Could not collect security group rules: {e}")

    try:
        data["servers"] = list(conn.compute.servers(all_projects=True))
    except Exception as e:
        print(f"  [!] Could not collect servers: {e}")

    try:
        data["floating_ips"] = list(conn.network.ips())
    except Exception as e:
        print(f"  [!] Could not collect floating IPs: {e}")

    try:
        data["volumes"] = list(conn.block_storage.volumes(all_projects=True))
    except Exception as e:
        print(f"  [!] Could not collect volumes: {e}")

    try:
        data["users"] = list(conn.identity.users())
    except Exception as e:
        print(f"  [!] Could not collect users: {e}")

    try:
        data["role_assignments"] = list(conn.identity.role_assignments())
    except Exception as e:
        print(f"  [!] Could not collect role assignments: {e}")
        data["role_assignments"] = []

    try:
        data["roles"] = list(conn.identity.roles())
    except Exception as e:
        print(f"  [!] Could not collect roles: {e}")
        data["roles"] = []

    total = sum(len(v) for v in data.values())
    print(f"  ✔ Collected {total} resources across {len(data)} categories\n")

    return data
