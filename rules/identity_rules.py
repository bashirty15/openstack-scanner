def check_identity_rules(data):
    findings = []

    users = data.get("users", [])
    role_assignments = data.get("role_assignments", [])
    roles = data.get("roles", [])

    # Build a lookup: role id -> role name
    role_names = {r.id: r.name for r in roles}

    # Build a lookup: user id -> username
    user_names = {u.id: getattr(u, "name", u.id) for u in users}

    # Find admin role id
    admin_role_ids = {
        r.id for r in roles
        if getattr(r, "name", "").lower() == "admin"
    }

    # Track which users have admin role
    admin_users = set()
    for assignment in role_assignments:
        role_id = getattr(assignment, "role_id", None) or getattr(getattr(assignment, "role", {}), "id", None)
        user_id = getattr(assignment, "user_id", None) or getattr(getattr(assignment, "user", {}), "id", None)

        if role_id in admin_role_ids and user_id:
            admin_users.add(user_id)

    # Flag users with admin role — NEW
    for user_id in admin_users:
        username = user_names.get(user_id, user_id)
        # Skip the main admin account — it's expected
        if username == "admin":
            continue
        findings.append({
            "check": "Non-Default User With Admin Role",
            "severity": "HIGH",
            "resource": f"User: {username}",
            "detail": f"User '{username}' has been granted the admin role — this gives full cloud access",
            "remediation": "Revoke admin role if not required. Follow the principle of least privilege.",
        })

    # Flag users that have never logged in — NEW
    for user in users:
        username = getattr(user, "name", "Unknown")
        last_login = getattr(user, "last_active_at", None)
        enabled = getattr(user, "is_enabled", True)

        if enabled and last_login is None:
            # Skip service accounts (they typically have no login)
            if any(svc in username.lower() for svc in ["nova", "neutron", "cinder", "glance", "heat", "keystone", "swift", "barbican", "placement"]):
                continue
            findings.append({
                "check": "User Never Logged In",
                "severity": "LOW",
                "resource": f"User: {username}",
                "detail": f"User '{username}' is enabled but has never logged in",
                "remediation": "Verify this account is still needed. Disable or delete unused accounts.",
            })

    return findings
