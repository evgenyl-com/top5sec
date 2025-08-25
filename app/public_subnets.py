"""
public_subnets.py

Summarizes public subnet resources and categories for VPCs.
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
import json

_COMPUTE_SERVICES = {"ec2", "ecs_fargate_task", "elbv2"}
_DB_SERVICES = {"rds", "documentdb", "redshift", "elasticache", "msk"}


def _format_service_lines(inv_vpc: Dict[str, Any], subnet_id: str) -> List[str]:
    """
    Format a list of service/resource lines for a given subnet.
    """
    lines: List[str] = []
    subnet_body = inv_vpc.get(subnet_id, {})
    for service, resources in subnet_body.items():
        if not isinstance(resources, dict):
            continue
        for rid, meta in resources.items():
            name = (meta or {}).get("name") or rid
            created = (meta or {}).get("createdat")
            lines.append(f"- {service}: {name} (id: {rid}, created: {created})")
    return lines

def _service_categories_present(inv_vpc: Dict[str, Any], public_subnets: List[str]) -> Dict[str, bool]:
    """
    Determine if compute or database services are present in public subnets.
    """
    found = set()
    for subnet_id in public_subnets:
        for service in (inv_vpc.get(subnet_id) or {}).keys():
            found.add(str(service))
    return {
        "compute": bool(found & _COMPUTE_SERVICES),
        "databases": bool(found & _DB_SERVICES),
    }

def _summarize_vpc_general(vpc_id: str, inv_vpc: Dict[str, Any], vpc_analysis: Dict[str, Any]) -> Optional[str]:
    """
    Summarize public subnet resources and categories for a VPC.
    """
    is_default = bool(vpc_analysis.get("is_default"))
    public_subnets: List[str] = list(vpc_analysis.get("public_subnets") or [])
    if not public_subnets:
        return None
    subnets_meta: Dict[str, Any] = vpc_analysis.get("subnets") or {}

    header: List[str] = []
    if is_default:
        header.append(f"You are using the default VPC {vpc_id} where you have a couple of resources.")
    else:
        header.append(f"Public subnets in VPC {vpc_id}:")

    cats = _service_categories_present(inv_vpc, public_subnets)
    if cats["compute"] and cats["databases"]:
        header.append("You have compute and database resources deployed in public subnets.")
    elif cats["compute"]:
        header.append("You have compute resources deployed in public subnets.")
    elif cats["databases"]:
        header.append("You have database resources deployed in public subnets.")

    body: List[str] = []
    for subnet_id in public_subnets:
        smeta = subnets_meta.get(subnet_id, {})
        rtb = smeta.get("route_table") or "unknown"
        body.append(f"\nPublic Subnet {subnet_id} (route table: {rtb})")
        lines = _format_service_lines(inv_vpc, subnet_id)
        body.extend(lines or ["- No inventoried services/resources found in this subnet"])

    return "\n".join(header + [""] + body)

def _normalize_public_subnets(public_subnets: Any) -> List[Dict[str, Any]]:
    """
    Normalize various public_subnets shapes into a list of dicts:
      - ["subnet-1", "subnet-2"] -> [{"subnet_id":"subnet-1"}, {"subnet_id":"subnet-2"}]
      - {"subnet-1": {...}, "subnet-2": {...}} -> [{"subnet_id":"subnet-1", **{...}}, ...]
      - [{"subnet_id":"subnet-1", ...}, {...}] -> passthrough (ensuring subnet_id exists if possible)
    """
    out: List[Dict[str, Any]] = []

    if not public_subnets:
        return out

    if isinstance(public_subnets, list):
        for item in public_subnets:
            if isinstance(item, str):
                out.append({"subnet_id": item})
            elif isinstance(item, dict):
                # ensure there's a subnet_id if one of the common keys exists
                if "subnet_id" in item:
                    out.append(dict(item))
                else:
                    # Try to infer from common keys
                    sid = item.get("id") or item.get("subnet") or item.get("subnetId")
                    out.append({"subnet_id": sid, **{k: v for k, v in item.items() if k not in {"id", "subnet", "subnetId"}}})
            else:
                out.append({"subnet_id": None, "value": item})
        return out

    if isinstance(public_subnets, dict):
        for sid, meta in public_subnets.items():
            if isinstance(meta, dict):
                out.append({"subnet_id": sid, **meta})
            else:
                out.append({"subnet_id": sid, "value": meta})
        return out

    # Fallback: unknown shape
    return [{"subnet_id": None, "value": public_subnets}]


def generate_public_subnet(
    inventory: Union[Dict[str, Any], str],
    net_analysis: Union[Dict[str, Any], str],
    *,
    include_non_default: bool = True,        # allow non-default VPCs
    require_public_subnets: bool = True      # only include if public subnets exist
) -> Optional[Dict[str, Any]]:
    """
    Build a structured dict describing VPCs that have public subnets,
    based on `net_analysis` (analysis output) and enriched with `inventory`
    metadata when available.

    Returns None if nothing matches the filters.

    Output schema (best-effort and tolerant of input variability):
    {
      "summary": {
        "vpc_count": int,
        "public_subnet_count": int
      },
      "vpcs": [
        {
          "vpc_id": "vpc-xxxx",
          "is_default": bool or None,
          "has_public_subnets": bool,
          "inventory": { ...inv_vpc_raw... },     # whatever is present in inventory[vpc_id]
          "public_subnets": [
            { "subnet_id": "subnet-xxx", ...extra if present... }
          ]
        },
        ...
      ]
    }
    """
    # Accept JSON strings too
    if isinstance(inventory, str):
        inventory = json.loads(inventory)
    if isinstance(net_analysis, str):
        net_analysis = json.loads(net_analysis)

    if not isinstance(inventory, dict):
        raise TypeError("inventory must be a dict or JSON string")
    if not isinstance(net_analysis, dict):
        raise TypeError("net_analysis must be a dict or JSON string")

    vpcs = net_analysis.get("vpcs") or {}
    vpc_entries: List[Dict[str, Any]] = []

    total_public_subnets = 0

    for vpc_id, vpc_analysis in vpcs.items():
        if not isinstance(vpc_analysis, dict):
            continue

        is_default = vpc_analysis.get("is_default")
        public_subnets_raw = vpc_analysis.get("public_subnets") or []

        if not include_non_default and not is_default:
            continue
        if require_public_subnets and not public_subnets_raw:
            continue

        public_subnets = _normalize_public_subnets(public_subnets_raw)
        has_public = len(public_subnets) > 0

        if require_public_subnets and not has_public:
            continue

        inv_vpc = inventory.get(vpc_id, {}) if isinstance(inventory, dict) else {}

        vpc_entries.append(
            {
                "vpc_id": vpc_id,
                "is_default": is_default if isinstance(is_default, bool) else None,
                "has_public_subnets": has_public,
                "inventory": inv_vpc if isinstance(inv_vpc, dict) else {"value": inv_vpc},
                "public_subnets": public_subnets,
            }
        )
        total_public_subnets += len(public_subnets)

    if not vpc_entries:
        return None

    return vpc_entries