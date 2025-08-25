def describe_s3_public_acl_audit(s3_audit: dict) -> str:
    """
    Takes the output of audit_s3_public_and_acls and returns a human-readable summary
    of public S3 buckets, ACLs, and AWS security impact.
    """
    if not s3_audit:
        return "No S3 public/ACL audit data available."

    lines = []
    public_buckets = s3_audit.get("effective_public_buckets", [])
    buckets_with_acls = s3_audit.get("buckets_with_acls_enabled", [])
    scanned = s3_audit.get("scanned_buckets", None)

    if public_buckets:
        title = "<br><b>Publicly accessible S3 buckets detected:</b>"
        lines.append(title)
        for bucket in public_buckets:
            name = bucket.get("bucket", "<unknown>")
            region = bucket.get("region", "<unknown>")
            reasons = ", ".join(bucket.get("reasons", []))
            acl_grants = bucket.get("acl_grants", [])
            policy_actions = ", ".join(bucket.get("policy_public_actions", []))
            pab = bucket.get("public_access_block", {})
            website = bucket.get("website_enabled", False)
            lines.append(f"  - Bucket: {name} | Region: {region} | Reasons: {reasons}")
            if acl_grants:
                lines.append("    ACL Grants:")
                for grant in acl_grants:
                    grantee = grant.get("grantee", "<unknown>")
                    perm = grant.get("permission", "<unknown>")
                    lines.append(f"      {grantee}: {perm}")
            if policy_actions:
                lines.append(f"    Policy Public Actions: {policy_actions}")
            if pab:
                pab_bucket = pab.get("bucket", {})
                lines.append(f"    Public Access Block: {pab_bucket}")
            if website:
                lines.append("    Website hosting is ENABLED (publicly accessible)")
            # Security impact
            impact = "\nIMPACT: Public buckets can leak sensitive data or be abused for malware distribution. Restrict public access and review bucket policies and ACLs."
            lines.append(f"    {impact}")

    if buckets_with_acls:
        title = "<br><b>Buckets with ACLs enabled:</b>"
        lines = [title]
        for bucket in buckets_with_acls:
            name = bucket.get("bucket", "<unknown>")
            region = bucket.get("region", "<unknown>")
            obj_owner = bucket.get("object_ownership", "<unknown>")
            lines.append(f"  - Bucket: {name} | Region: {region}")
        # Add impact for ACLs
        lines.append("IMPACT: S3 buckets with ACLs enabled may have unintended access permissions. Review and restrict ACLs to minimize risk of data exposure.")

    return "\n".join(lines)
