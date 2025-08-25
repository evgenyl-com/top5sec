def describe_encryption_audit(encryption_results: dict) -> str:
    """
    Takes the output of audit_encryption and returns a human-readable summary
    of unencrypted resources and AWS security impact.
    """
    if not encryption_results:
        return None

    lines = []
    # EBS volumes
    ebs = encryption_results.get("EBS", {})
    unenc_ebs = [vid for vid, meta in ebs.items() if not meta.get("kms_key_id")]
    if unenc_ebs:
        lines.append("\n<br><b>Unencrypted EBS volumes detected:</b>")
        for vid in unenc_ebs:
            lines.append(f"  - Volume ID: {vid}")
        lines.append("\nIMPACT: Unencrypted EBS volumes can expose sensitive data if compromised. Enable encryption with KMS keys.")

    # SNS topics
    sns = encryption_results.get("SNS", {})
    unenc_sns = [arn for arn, meta in sns.items() if not meta.get("encrypted")]
    if unenc_sns:
        lines.append("\n<br><b>Unencrypted SNS topics detected:</b>")
        for arn in unenc_sns:
            lines.append(f"  - Topic ARN: {arn}")
        lines.append("\nIMPACT: Unencrypted SNS topics can leak sensitive messages. Enable encryption for all topics.")

    # RDS instances
    rds = encryption_results.get("RDS", {})
    unenc_rds = [rid for rid, meta in rds.items() if not meta.get("kms_key_id")]
    if unenc_rds:
        lines.append("\n<br><b>Unencrypted RDS instances detected:</b>")
        for rid in unenc_rds:
            meta = rds[rid]
            engine = meta.get("engine", "<unknown>")
            instance_class = meta.get("instance_class", "<unknown>")
            multi_az = meta.get("multi_az", False)
            lines.append(f"  - DB Instance: {rid} | Engine: {engine} | Class: {instance_class} | Multi-AZ: {multi_az}")
        lines.append("\nIMPACT: Unencrypted RDS databases can expose sensitive data at rest. Enable encryption with KMS keys for all RDS instances.")

    # Add similar logic for other resource types if needed

    return "\n".join(lines)
