from typing import Dict, Any, Union, Tuple
import json
import boto3
import os
from botocore.exceptions import ClientError


def _get_session() -> boto3.Session:
    """
    Create a boto3 session honoring REGION/AWS_REGION/AWS_DEFAULT_REGION.
    Uses ambient credentials.
    """
    region = (
        os.getenv("REGION")
        or os.getenv("AWS_REGION")
        or os.getenv("AWS_DEFAULT_REGION")
    )
    return boto3.Session(region_name=region)

def _get_vpc_is_default(ec2: boto3.client, vpc_id: str) -> bool:
    """
    Check whether the given VPC is the default one.
    Returns True if default, False otherwise.
    """
    try:
        resp = ec2.describe_vpcs(VpcIds=[vpc_id])
        vpcs = resp.get("Vpcs", [])
        if not vpcs:
            return False
        return bool(vpcs[0].get("IsDefault", False))
    except ClientError as e:
        print(f"[warn] Could not check VPC {vpc_id}: {e}")
        return False

def _load_route_tables(ec2: boto3.client, vpc_id: str) -> Tuple[str, Dict[str, str], Dict[str, dict]]:
    """
    Load route tables for a given VPC.
    Returns main route table ID, subnet-to-RTB mapping, and RTB index.
    """
    subnet_to_rtb: Dict[str, str] = {}
    rtb_index: Dict[str, dict] = {}
    main_rtb_id = None

    paginator = ec2.get_paginator("describe_route_tables")
    for page in paginator.paginate(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
        for rtb in page.get("RouteTables", []):
            rtb_id = rtb["RouteTableId"]
            rtb_index[rtb_id] = rtb
            for assoc in rtb.get("Associations", []) or []:
                if assoc.get("SubnetId"):
                    subnet_to_rtb[assoc["SubnetId"]] = rtb_id
                if assoc.get("Main"):
                    main_rtb_id = rtb_id
    return main_rtb_id, subnet_to_rtb, rtb_index

def _rtb_has_igw_default_route(rtb: dict) -> bool:
    """
    Check if a route table has a default route to an Internet Gateway.
    Returns True if 0.0.0.0/0 or ::/0 route points to igw- and is not blackhole.
    """
    for route in rtb.get("Routes", []) or []:
        dest4 = route.get("DestinationCidrBlock") == "0.0.0.0/0"
        dest6 = route.get("DestinationIpv6CidrBlock") == "::/0"
        gw = route.get("GatewayId", "")
        blackhole = route.get("Blackhole", False)
        if (dest4 or dest6) and gw.startswith("igw-") and not blackhole:
            return True
    return False

def analyze_public_subnets(
    inventory: Union[Dict[str, Any], str],
    session: boto3.Session | None = None
) -> Dict[str, Any]:
    """
    Analyze public subnets in VPCs from inventory.
    Accepts a Python dict (preferred) or a JSON string.
    Returns a dict with VPCs, their subnets, and public subnet info.
    """
    if isinstance(inventory, str):
        try:
            inventory = json.loads(inventory)
        except json.JSONDecodeError as e:
            raise ValueError(f"inventory is a string but not valid JSON: {e}") from e

    if not isinstance(inventory, dict):
        raise TypeError(f"inventory must be dict or JSON string, got: {type(inventory).__name__}")

    session = session or _get_session()
    ec2 = session.client("ec2")

    result: Dict[str, Any] = {"vpcs": {}}

    for vpc_id, vpc_body in inventory.items():
        if not isinstance(vpc_body, dict):
            raise ValueError(
                "Expected top-level to be {<vpc-id>: {...}}. "
                f"Found non-dict at key {vpc_id!r}."
            )

        subnet_ids = [sid for sid in vpc_body.keys() if str(sid).startswith("subnet-")]
        if not subnet_ids:
            result["vpcs"][vpc_id] = {
                "is_default": _get_vpc_is_default(ec2, vpc_id),
                "subnets": {},
                "public_subnets": [],
            }
            continue

        is_default = _get_vpc_is_default(ec2, vpc_id)
        main_rtb_id, subnet_to_rtb, rtb_index = _load_route_tables(ec2, vpc_id)

        rtb_public_cache: Dict[str, bool] = {
            rtb_id: _rtb_has_igw_default_route(rtb) for rtb_id, rtb in rtb_index.items()
        }

        subnets_out: Dict[str, Any] = {}
        public_subnets: list[str] = []

        for subnet_id in subnet_ids:
            rtb_id = subnet_to_rtb.get(subnet_id) or main_rtb_id
            has_igw = bool(rtb_id and rtb_public_cache.get(rtb_id, False))
            is_public = has_igw

            subnets_out[subnet_id] = {
                "route_table": rtb_id,
                "has_igw_route": has_igw,
                "is_public": is_public,
            }
            if is_public:
                public_subnets.append(subnet_id)

        result["vpcs"][vpc_id] = {
            "is_default": is_default,
            "subnets": subnets_out,
            "public_subnets": public_subnets,
        }

    return result
