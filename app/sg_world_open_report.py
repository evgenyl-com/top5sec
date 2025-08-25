def describe_world_open_sgs(offenders: dict) -> str:
    """
    Takes the output of find_world_open_resources and returns a human-readable summary
    of world-open security groups, ports, and their AWS security impact.
    """
    if not offenders or not offenders.get("vpcs"):
        return None

    title = "<br><b>World-Open Security Groups Report</b>"
    lines = [title]
    impact_written = set()
    for vpc_id, vpc_data in offenders["vpcs"].items():
        lines.append(f"<br><br>VPC: {vpc_id}")
        subnets = vpc_data.get("subnets", {})
        for subnet_id, subnet_data in subnets.items():
            lines.append(f"<br>Subnet: {subnet_id}")
            for service, resources in subnet_data.items():
                lines.append(f"Service: {service}")
                for res_id, res_meta in resources.items():
                    name = res_meta.get("name", "<unknown>")
                    lines.append(f"      Resource: {res_id} (name: {name})")
                    sg_ids = res_meta.get("sg_ids", [])
                    for violation in res_meta.get("violations", []):
                        sg_id = violation.get("sg_id", sg_ids[0] if sg_ids else "<unknown>")
                        proto = violation.get("proto", "any")
                        from_port = violation.get("from")
                        to_port = violation.get("to")
                        cidr = violation.get("cidr", "<unknown>")
                        port_str = f"{proto}"
                        if from_port is not None:
                            port_str += f" {from_port}"
                            if to_port is not None and to_port != from_port:
                                port_str += f"-{to_port}"
                        lines.append(f"        - Security Group: {sg_id} | Open to: {cidr} | Ports: {port_str}")
                        if proto == "tcp" and (from_port == 22 or from_port == 3389):
                            impact = "IMPACT: This allows unrestricted inbound access from the internet, which can expose resources to attacks such as brute force, malware, or unauthorized access. Commonly targeted ports for SSH (22) or RDP (3389). Immediate remediation recommended."
                            if impact not in impact_written:
                                lines.append(f"          {impact}")
                                impact_written.add(impact)
                        elif proto == "-1":
                            impact = "IMPACT: This allows unrestricted inbound access from the internet, which can expose resources to attacks such as brute force, malware, or unauthorized access. All protocols and ports are open. This is extremely dangerous."
                            if impact not in impact_written:
                                lines.append(f"          {impact}")
                                impact_written.add(impact)
    return "\n".join(lines)
