def describe_public_subnets(public_subnets: list) -> str:
    """
    Takes the output of generate_public_subnet and returns a human-readable summary
    of public subnets, their VPCs, and AWS security impact.
    """
    if not public_subnets:
        return None

    title = "<br><b>Public Subnets Exposure Report</b>"
    lines = [title]
    for vpc in public_subnets:
        vpc_id = vpc.get("vpc_id", "<unknown>")
        is_default = vpc.get("is_default", False)
        has_public = vpc.get("has_public_subnets", False)
        lines.append(f"<br><br>VPC: {vpc_id} | Default: {is_default} | Has Public Subnets: {has_public}")
        if has_public:
            subnets = vpc.get("public_subnets", [])
            for subnet in subnets:
                subnet_id = subnet.get("subnet_id", "<unknown>")
                lines.append(f"<br>Public Subnet: {subnet_id}")
                inv = vpc.get("inventory", {}).get(subnet_id, {})
                for service, resources in inv.items():
                    lines.append(f"    Service: {service}")
                    for res_id, res_meta in resources.items():
                        name = res_meta.get("name", "<unknown>")
                        created = res_meta.get("createdat", None)
                        created_str = f"Created: {created}" if created else ""
                        lines.append(f"      - Resource: {res_id} (name: {name}) {created_str}")
            # Security impact description
            impact = "Public subnets allow direct inbound traffic from the internet if associated with an IGW and route tables. Resources in public subnets are at higher risk of exposure to attacks."
            lines.append(f"    \nIMPACT: {impact}")
        else:
            lines.append("  No public subnets in this VPC.")
    return "\n".join(lines)
