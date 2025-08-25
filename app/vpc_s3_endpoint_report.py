def describe_vpc_s3_endpoint_coverage(coverage: dict) -> str:
    """
    Takes the output of find_subnets_missing_s3_endpoints and returns a human-readable summary
    of VPCs/subnets missing S3 endpoints and AWS security impact.
    """
    if not coverage or not coverage.get("affected"):
        return None

    lines = []
    affected = coverage.get("affected", {})
    inspected = coverage.get("inspected", {})
    for vpc_id, subnets in affected.items():
        region = inspected.get(vpc_id, {}).get("region", "<unknown>")
        lines.append(f"<br><br>VPC: {vpc_id} | Region: {region}")
        for subnet_id, subnet_data in subnets.items():
            missing = ", ".join(subnet_data.get("missing", []))
            rtb = subnet_data.get("route_table", "<unknown>")
            lines.append(f"<br>Subnet: {subnet_id} | Missing endpoints: {missing} | Route Table: {rtb}")
            resources = subnet_data.get("resources", {})
            for service, res_dict in resources.items():
                lines.append(f"    Service: {service}")
                for res_id, res_meta in res_dict.items():
                    name = res_meta.get("name", "<unknown>")
                    created = res_meta.get("createdat", None)
                    created_str = f"Created: {created}" if created else ""
                    lines.append(f"      - Resource: {res_id} (name: {name}) {created_str}")
            # Security impact
            impact = "\nIMPACT: Without S3 endpoints, traffic to S3 from this subnet traverses the public internet, increasing risk of data interception and exposure. Configure gateway and interface endpoints for secure access."
            lines.append(f"    {impact}")
    return "\n".join(lines)
