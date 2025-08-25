"""
sg_world_open_finder.py

Find resources whose Security Groups are world-open (0.0.0.0/0 or ::/0) on ports other than 80/443.
"""

from typing import Dict, Any, List, Set, Tuple, Optional, Union
import os
import boto3
from botocore.exceptions import BotoCoreError, ClientError

# ---------- Session helper ----------

def _get_session() -> boto3.Session:
    """
    Return a boto3 session using environment region variables.
    """
    region = os.getenv("REGION") or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
    return boto3.Session(region_name=region)

# ---------- SG rule inspection ----------

_ALLOWED_WORLD_PORTS = {(6, 80), (6, 443)}  # (ip-proto-num, port); 6=tcp, 17=udp

def _proto_name_to_num(p: str) -> Optional[int]:
    """
    Convert protocol name to number.
    """
    if p is None:
        return None
    if p == "-1":
        return -1   # all
    if p.lower() == "tcp":
        return 6
    if p.lower() == "udp":
        return 17
    if p.lower() == "icmp":
        return 1
    if p.lower() == "icmpv6":
        return 58
    try:
        return int(p)
    except Exception:
        return None

def _is_world(cidr: Optional[str], cidr6: Optional[str]) -> bool:
    return (cidr == "0.0.0.0/0") or (cidr6 == "::/0")

def _port_range_includes_non_http(from_port: Optional[int], to_port: Optional[int], proto_num: int) -> bool:
    """
    Returns True if the range represents any port other than 80/443 for TCP,
    or any UDP/other protocol exposure (always considered violation).
    """
    # All protocols
    if proto_num == -1:
        return True
    # UDP: any exposure is a violation (not exempted)
    if proto_num == 17:
        return True
    # Non-TCP protocols (icmp etc.) treated as violation if world-open
    if proto_num not in (6, 17, -1):
        return True
    # TCP:
    if from_port is None or to_port is None:
        return True
    # If the only ports are 80 or 443, allow; otherwise violation
    # Single port
    if from_port == to_port:
        return (proto_num, from_port) not in _ALLOWED_WORLD_PORTS
    # Range:
    # If range includes anything other than 80/443, it's a violation.
    # That includes 0-65535, 1-65535, 22-22, 1-1024, 80-443 etc.
    allowed_only = (from_port == 80 and to_port == 80) or (from_port == 443 and to_port == 443)
    return not allowed_only

def _sg_world_violations(sg: dict) -> List[dict]:
    """
    Return list of violating ingress rules in this SG.
    """
    violations: List[dict] = []
    for perm in sg.get("IpPermissions", []) or []:
        proto = perm.get("IpProtocol")  # e.g., 'tcp', 'udp', '-1'
        proto_num = _proto_name_to_num(proto)
        from_p = perm.get("FromPort")
        to_p = perm.get("ToPort")

        # IPv4
        for rng in perm.get("IpRanges", []) or []:
            if _is_world(rng.get("CidrIp"), None):
                if _port_range_includes_non_http(from_p, to_p, proto_num):
                    violations.append({
                        "sg_id": sg["GroupId"],
                        "proto": proto,
                        "from": from_p,
                        "to": to_p,
                        "cidr": "0.0.0.0/0",
                    })
        # IPv6
        for rng6 in perm.get("Ipv6Ranges", []) or []:
            if _is_world(None, rng6.get("CidrIpv6")):
                if _port_range_includes_non_http(from_p, to_p, proto_num):
                    violations.append({
                        "sg_id": sg["GroupId"],
                        "proto": proto,
                        "from": from_p,
                        "to": to_p,
                        "cidr": "::/0",
                    })
    return violations

# ---------- Per-service lookups (resource -> SG IDs) ----------

def _chunk(lst: List[str], n: int) -> List[List[str]]:
    return [lst[i:i+n] for i in range(0, len(lst), n)]

def _collect_inventory_ids(inventory: Dict[str, Any], service: str) -> List[str]:
    ids: List[str] = []
    for vpc in inventory.values():
        for subnet in vpc.values():
            svc = subnet.get(service) or {}
            ids.extend(list(svc.keys()))
    # deduplicate, preserve order
    seen = set()
    out = []
    for x in ids:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def _map_resource_name(inventory: Dict[str, Any], service: str, resource_id: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Returns (name, vpc_id, subnet_id) for the resource_id if present in inventory.
    """
    for vpc_id, vpc in inventory.items():
        for subnet_id, subnet in vpc.items():
            svc = subnet.get(service) or {}
            if resource_id in svc:
                name = (svc[resource_id] or {}).get("name")
                return name, vpc_id, subnet_id
    return None, None, None

def _gather_ec2_sg_map(session: boto3.Session, inventory: Dict[str, Any]) -> Dict[str, List[str]]:
    ec2 = session.client("ec2")
    ids = _collect_inventory_ids(inventory, "ec2")
    sg_map: Dict[str, List[str]] = {}
    for batch in _chunk(ids, 200):
        if not batch:
            continue
        resp = ec2.describe_instances(InstanceIds=batch)
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                sg_ids = [g["GroupId"] for g in inst.get("SecurityGroups", [])]
                sg_map[inst["InstanceId"]] = sg_ids
    return sg_map

def _gather_elbv2_sg_map(session: boto3.Session, inventory: Dict[str, Any]) -> Dict[str, List[str]]:
    elb = session.client("elbv2")
    arns = _collect_inventory_ids(inventory, "elbv2")
    sg_map: Dict[str, List[str]] = {}
    for batch in _chunk(arns, 20):
        if not batch:
            continue
        resp = elb.describe_load_balancers(LoadBalancerArns=batch)
        for lb in resp.get("LoadBalancers", []):
            # Only ALB has SGs; NLB/GWLB do not
            if lb.get("Type") == "application":
                sg_map[lb["LoadBalancerArn"]] = lb.get("SecurityGroups", []) or []
    return sg_map

def _gather_rds_like_sg_map(session: boto3.Session, inventory: Dict[str, Any], service: str) -> Dict[str, List[str]]:
    """
    service in {"rds", "documentdb"}
    """
    if service == "rds":
        cli = session.client("rds")
        ids = _collect_inventory_ids(inventory, "rds")
        key = "DBInstances"; id_key = "DBInstanceIdentifier"
    else:
        cli = session.client("docdb")
        ids = _collect_inventory_ids(inventory, "documentdb")
        key = "DBInstances"; id_key = "DBInstanceIdentifier"

    sg_map: Dict[str, List[str]] = {}
    for rid in ids:
        try:
            if service == "rds":
                resp = cli.describe_db_instances(DBInstanceIdentifier=rid)
            else:
                resp = cli.describe_db_instances(DBInstanceIdentifier=rid)
        except ClientError:
            continue
        for inst in resp.get(key, []):
            sg_ids = [g.get("VpcSecurityGroupId") for g in inst.get("VpcSecurityGroups", []) if g.get("VpcSecurityGroupId")]
            sg_map[inst[id_key]] = sg_ids
    return sg_map

def _gather_redshift_sg_map(session: boto3.Session, inventory: Dict[str, Any]) -> Dict[str, List[str]]:
    red = session.client("redshift")
    ids = _collect_inventory_ids(inventory, "redshift")
    sg_map: Dict[str, List[str]] = {}
    for rid in ids:
        try:
            resp = red.describe_clusters(ClusterIdentifier=rid)
        except ClientError:
            continue
        for c in resp.get("Clusters", []):
            sg_ids = [g.get("VpcSecurityGroupId") for g in c.get("VpcSecurityGroups", []) if g.get("VpcSecurityGroupId")]
            sg_map[c["ClusterIdentifier"]] = sg_ids
    return sg_map

def _gather_elasticache_sg_map(session: boto3.Session, inventory: Dict[str, Any]) -> Dict[str, List[str]]:
    ec = session.client("elasticache")
    ids = _collect_inventory_ids(inventory, "elasticache")
    sg_map: Dict[str, List[str]] = {}
    # ElastiCache doesn't support batch-by-id describe; we describe all and filter
    paginator = ec.get_paginator("describe_cache_clusters")
    all_clusters = {}
    for page in paginator.paginate(ShowCacheNodeInfo=False):
        for cl in page.get("CacheClusters", []):
            all_clusters[cl["CacheClusterId"]] = cl
    for rid in ids:
        cl = all_clusters.get(rid)
        if not cl:
            continue
        sg_ids = [g.get("SecurityGroupId") for g in cl.get("SecurityGroups", []) if g.get("SecurityGroupId")]
        sg_map[rid] = sg_ids
    return sg_map

def _gather_msk_sg_map(session: boto3.Session, inventory: Dict[str, Any]) -> Dict[str, List[str]]:
    mk = session.client("kafka")
    arns = _collect_inventory_ids(inventory, "msk")
    sg_map: Dict[str, List[str]] = {}
    for arn in arns:
        try:
            d = mk.describe_cluster_v2(ClusterArn=arn)
            info = d.get("ClusterInfo", {})
            bgi = info.get("BrokerNodeGroupInfo", {})
            sg_ids = bgi.get("SecurityGroups", []) or []
            sg_map[arn] = sg_ids
        except ClientError:
            continue
    return sg_map

# ---------- Main analyzer ----------

_SERVICES = ("ec2", "elbv2", "rds", "documentdb", "redshift", "elasticache", "msk")

def find_world_open_resources(
    inventory: Dict[str, Any],
    net_analysis: Optional[Dict[str, Any]] = None,
    session: Optional[boto3.Session] = None,
) -> Dict[str, Any]:
    """
    Returns a structure containing ONLY resources whose SGs are world-open
    on ports other than 80/443.
    """
    session = session or _get_session()
    ec2 = session.client("ec2")

    # 1) Build per-service resource -> SG IDs maps
    r_to_sg: Dict[Tuple[str, str], List[str]] = {}   # (service, resource_id) -> [sg-ids]
    gatherers = {
        "ec2": _gather_ec2_sg_map,
        "elbv2": _gather_elbv2_sg_map,
        "rds": lambda s, inv: _gather_rds_like_sg_map(s, inv, "rds"),
        "documentdb": lambda s, inv: _gather_rds_like_sg_map(s, inv, "documentdb"),
        "redshift": _gather_redshift_sg_map,
        "elasticache": _gather_elasticache_sg_map,
        "msk": _gather_msk_sg_map,
    }

    all_sg_ids: Set[str] = set()
    for svc in _SERVICES:
        try:
            sg_map = gatherers[svc](session, inventory)
            for rid, sg_ids in sg_map.items():
                r_to_sg[(svc, rid)] = sg_ids or []
                all_sg_ids.update(sg_ids or [])
        except (BotoCoreError, ClientError) as e:
            # best-effort; skip service on error
            continue

    if not all_sg_ids:
        return {"vpcs": {}}

    # 2) Describe SGs, find violators
    violator_rules_by_sg: Dict[str, List[dict]] = {}
    for batch in _chunk(list(all_sg_ids), 200):
        if not batch:
            continue
        try:
            resp = ec2.describe_security_groups(GroupIds=batch)
        except ClientError:
            continue
        for sg in resp.get("SecurityGroups", []):
            violations = _sg_world_violations(sg)
            if violations:
                violator_rules_by_sg[sg["GroupId"]] = violations

    if not violator_rules_by_sg:
        return {"vpcs": {}}

    # 3) Build result grouped like the inventory, but only with offenders
    result: Dict[str, Any] = {"vpcs": {}}
    for vpc_id, vpc in inventory.items():
        vpc_out = {}
        for subnet_id, subnet in vpc.items():
            subnet_out = {}
            for svc in _SERVICES:
                svc_block = subnet.get(svc) or {}
                offenders = {}
                for rid, meta in svc_block.items():
                    sg_ids = r_to_sg.get((svc, rid), [])
                    offending_sgs = [sg for sg in sg_ids if sg in violator_rules_by_sg]
                    if not offending_sgs:
                        continue
                    offenders[rid] = {
                        "name": (meta or {}).get("name"),
                        "sg_ids": sg_ids,
                        "violations": sum((violator_rules_by_sg[sg] for sg in offending_sgs), []),
                    }
                if offenders:
                    subnet_out[svc] = offenders
            if subnet_out:
                vpc_out[subnet_id] = subnet_out
        if vpc_out:
            result["vpcs"][vpc_id] = {"subnets": vpc_out}

    return result

