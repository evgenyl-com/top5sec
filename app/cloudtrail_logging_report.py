def describe_cloudtrail_logging_coverage(ct_audit: dict) -> str:
    """
    Takes the output of audit_cloudtrail_logging_coverage and returns a human-readable summary
    of CloudTrail logging coverage and its AWS security impact.
    """
    if not ct_audit or not ct_audit.get("overall"):
        return "No CloudTrail logging information available."

    overall = ct_audit["overall"]
    lines = []
    logging_enabled = overall.get("has_any_logging_trail")
    all_covered = overall.get("all_regions_covered")
    if logging_enabled:
        lines.append("CloudTrail logging is ENABLED for this account.")
    else:
        lines.append("CloudTrail logging is NOT enabled for this account. This is a critical security risk.")

    # Only print uncovered regions and per-region coverage if logging is enabled
    if logging_enabled:
        if all_covered:
            lines.append("All AWS regions are covered by logging trails.")
        else:
            uncovered = overall.get("uncovered_regions", [])
            if uncovered:
                lines.append(f"WARNING: The following regions are NOT covered by any logging trail: {', '.join(uncovered)}")
            else:
                lines.append("Some regions may not be covered by logging trails.")
        # Per-region coverage
        per_region = ct_audit.get("per_region", {})
        for region, info in per_region.items():
            covered = info.get("covered", False)
            reasons = ", ".join(info.get("reasons", []))
            status = "COVERED" if covered else "NOT COVERED"
            lines.append(f"Region: {region} - {status}.")

    total_trails = overall.get("trail_counts", {}).get("total", 0)
    logging_trails = overall.get("trail_counts", {}).get("logging", 0)

    multi_region = overall.get("multi_region_trails_logging", [])
    if multi_region:
        lines.append("Multi-region logging trails:")
        for trail in multi_region:
            org_str = "(Organization Trail)" if trail.get("is_org") else ""
            lines.append(f"  - {trail.get('name')} {org_str} [Home: {trail.get('home_region')}] {trail.get('arn')}")
    single_region = overall.get("single_region_trails_logging", [])
    if single_region:
        lines.append("Single-region logging trails:")
        for trail in single_region:
            lines.append(f"  - {trail.get('name')} [Home: {trail.get('home_region')}] {trail.get('arn')}")

    # Security impact summary
    if not logging_enabled or not all_covered:
        lines.append("\nIMPACT: Without CloudTrail logging in all regions, malicious or unauthorized activity may go undetected. Immediate remediation is recommended.")
    else:
        lines.append("\nIMPACT: CloudTrail logging is comprehensive. This is a strong security posture for audit and incident response.")

    return "\n".join(lines)
