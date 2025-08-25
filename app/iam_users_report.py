def describe_iam_users_audit(iam_audit: dict) -> str:
    """
    Takes the output of audit_iam_users and returns a human-readable summary
    of IAM user risks and AWS security impact.
    """
    if not iam_audit:
        return "No IAM user audit data available."

    lines = []
    no_mfa = iam_audit.get("no_mfa_console_users", [])
    users_with_keys = iam_audit.get("users_with_access_keys", [])
    stale_users = iam_audit.get("stale_users", [])
    threshold = iam_audit.get("stale_days_threshold", None)
    treat_unknown = iam_audit.get("treat_unknown_as_stale", False)

    if no_mfa:
        title = "<br><b>Users with console access and NO MFA enabled:</b>"
        lines = [title]
        for user in no_mfa:
            lines.append(f"  - {user}")
        lines.append("\nIMPACT: These users are at high risk of account compromise. MFA should be enabled immediately.")

    if users_with_keys:
        title = "<br><b>Users with active access keys:</b>"
        lines = [title]
        for user in users_with_keys:
            uname = user.get("user", "<unknown>")
            arn = user.get("arn", "<unknown>")
            created = user.get("created", "<unknown>")
            keys = ", ".join(user.get("access_keys_active", []))
            lines.append(f"  - {uname} ({arn}), Created: {created}, Keys: {keys}")
        lines.append("\nIMPACT: Active access keys increase risk of credential leakage. Rotate keys regularly and remove unused keys.")

    if stale_users:
        lines.append(f"<br><b>Stale users (no activity for > {threshold} days):</b>")
        for user in stale_users:
            lines.append(f"  - {user}")
        lines.append("\nIMPACT: Stale users may be forgotten and abused. Remove or review these accounts.")

    return "\n".join(lines)
