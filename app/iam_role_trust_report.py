def describe_iam_role_trust_audit(role_trust_results: dict) -> str:
    """
    Takes the output of audit_iam_role_trust and returns a human-readable summary
    of IAM roles trusted by other accounts with high privileges and AWS security impact.
    """

    title = "<br><b>IAM Role Trust Relationships & Privilege Risks Report</b>"
    lines = [title]
    for role, meta in role_trust_results.items():
        if role == "error":
            lines.append(f"Error: {meta}")
            continue
        trusted_accounts = meta.get("trusted_accounts", [])
        high_priv = meta.get("high_privileges", False)
        priv_details = meta.get("privilege_details", {})
        lines.append(f"<br>Role: {role}")
        lines.append(f"  Trusted Accounts: {', '.join(trusted_accounts) if trusted_accounts else 'None'}")
        lines.append(f"  High Privileges: {'Yes' if high_priv else 'No'}")
        if priv_details:
            lines.append("  Privilege Details:")
            for pol, pol_doc in priv_details.items():
                lines.append(f"    Policy: {pol}")
                # Show summary of policy document
                stmts = pol_doc.get("Statement", [])
                for stmt in stmts:
                    effect = stmt.get("Effect", "<unknown>")
                    actions = stmt.get("Action", "<unknown>")
                    resource = stmt.get("Resource", "<unknown>")
                    lines.append(f"      Effect: {effect}, Actions: {actions}, Resource: {resource}")
        # Security impact description
        impact = "Roles trusted by other accounts and with high privileges can be abused for privilege escalation or cross-account attacks. Review trust relationships and attached policies carefully."
        lines.append(f"  \nIMPACT: {impact}")
    return "\n".join(lines)
