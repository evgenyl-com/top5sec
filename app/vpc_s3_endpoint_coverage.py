"""
vpc_s3_endpoint_coverage.py

Checks VPC subnets for S3 endpoint coverage (gateway or interface endpoints).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple, Set

import boto3
from botocore.exceptions import ClientError, BotoCoreError


# ---------------- Session ----------------

def _get_session(session: Optional[boto3.Session] = None) -> boto3.Session:
    if session:
        return session
    region = os.getenv("REGION") or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
    return boto3.Session(region_name=region)


# ---------------- Helpers: region/VPC/subnet/rtb ----------------

def _all_regions(session: boto3.Session) -> List[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    resp = ec2.describe_regions(AllRegions=True)
    return [r["RegionName"] for r in resp.get("Regions", []) if r.get("OptInStatus") != "not-opted-in"]


def _find_vpc_region(session: boto3.Session, vpc_id: str) -> Optional[str]:
    """
    Locate the region for a given VPC by probing regions (cached listing).
    """
    for r in _all_regions(session):
        ec2 = session.client("ec2", region_name=r)
        try:
            ec2.describe_vpcs(VpcIds=[vpc_id])
            return r
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in {"InvalidVpcID.NotFound", "AuthFailure", "UnauthorizedOperation"}:
                continue
        except BotoCoreError:
            continue
    return None


def _route_tables_for_vpc(ec2, vpc_id: str) -> Tuple[Optional[str], Dict[str, str], Dict[str, dict]]:
    """
    Return (main_rtb_id, subnet_to_rtb, rtb_index)
    """
    subnet_to_rtb: Dict[str, str] = {}
    rtb_index: Dict[str, dict] = {}
    main_rtb_id: Optional[str] = None

    paginator = ec2.get_paginator("describe_route_tables")
    for page in paginator.paginate(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
        for rtb in page.get("RouteTables", []) or []:
            rtb_id = rtb["RouteTableId"]
            rtb_index[rtb_id] = rtb
            for assoc in rtb.get("Associations", []) or []:
                if assoc.get("SubnetId"):
                    subnet_to_rtb[assoc["SubnetId"]] = rtb_id
                if assoc.get("Main"):
                    main_rtb_id = rtb_id

    return main_rtb_id, subnet_to_rtb, rtb_index


# ---------------- S3 endpoint discovery ----------------

def _collect_s3_endpoints(ec2, region: str, vpc_id: str) -> Tuple[Set[str], Set[str]]:
    """
    Returns (gateway_rtb_ids, interface_subnet_ids) for S3 endpoints in this VPC.
    We match any endpoint whose ServiceName contains '.s3' in this region.
    """
    gateway_rtb_ids: Set[str] = set()
    interface_subnet_ids: Set[str] = set()

    svc_prefixes = [
        f"com.amazonaws.{region}.s3",            # main S3
        f"com.amazonaws.{region}.s3-global.accesspoint",  # APs
        f"com.amazonaws.{region}.s3-outposts",   # outposts (rare)
        f"com.amazonaws.{region}.s3-object-lambda",  # object lambda
    ]

    paginator = ec2.get_paginator("describe_vpc_endpoints")
    for page in paginator.paginate(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
        for ep in page.get("VpcEndpoints", []) or []:
            svc = ep.get("ServiceName", "")
            ep_type = ep.get("VpcEndpointType", "")
            if not any(svc.startswith(pfx) for pfx in svc_prefixes):
                # Fallback heuristic: regional S3 names sometimes vary; accept if contains '.s3'
                if f".{region}." not in svc or ".s3" not in svc:
                    continue

            if ep_type == "Gateway":
                for rtb_id in ep.get("RouteTableIds", []) or []:
                    gateway_rtb_ids.add(rtb_id)
            elif ep_type == "Interface":
                for sn in ep.get("SubnetIds", []) or []:
                    interface_subnet_ids.add(sn)

    return gateway_rtb_ids, interface_subnet_ids


# ---------------- Main check ----------------

def find_subnets_missing_s3_endpoints(
    inventory: Dict[str, Any],
    session: Optional[boto3.Session] = None,
) -> Dict[str, Any]:
    """
    Inspect each VPC in 'inventory'. For subnets that contain EC2 or Fargate resources,
    flag those that lack both S3 Gateway coverage (via route table) and S3 Interface coverage (via subnet).

    Returns dict described in the module header.
    """
    sess = _get_session(session)
    out_affected: Dict[str, Dict[str, Any]] = {}
    out_inspected: Dict[str, Dict[str, Any]] = {}
    errors: List[Dict[str, str]] = []

    for vpc_id, vpc_body in (inventory or {}).items():
        # gather subnets that we must check (contain EC2 or Fargate)
        target_subnets = []
        for subnet_id, subnet_body in (vpc_body or {}).items():
            if not isinstance(subnet_body, dict):
                continue
            has_ec2 = isinstance(subnet_body.get("ec2"), dict) and bool(subnet_body["ec2"])
            has_fargate = isinstance(subnet_body.get("fargate"), dict) and bool(subnet_body["fargate"])
            if has_ec2 or has_fargate:
                target_subnets.append(subnet_id)

        if not target_subnets:
            continue  # nothing to check for this VPC

        # find region of this VPC
        region = _find_vpc_region(sess, vpc_id)
        if not region:
            errors.append({"scope": "vpc", "id": vpc_id, "op": "FindRegion", "code": "NotFound", "message": "VPC not found in any region"})
            continue

        ec2 = sess.client("ec2", region_name=region)

        # map subnets -> route tables
        try:
            main_rtb_id, subnet_to_rtb, _rtb_index = _route_tables_for_vpc(ec2, vpc_id)
        except Exception as e:
            code = "Unknown"
            msg = str(e)
            if isinstance(e, ClientError):
                code = e.response.get("Error", {}).get("Code", code)
                msg = e.response.get("Error", {}).get("Message", msg)
            errors.append({"scope": "vpc", "id": vpc_id, "op": "DescribeRouteTables", "code": code, "message": msg})
            continue

        # collect S3 endpoints coverage
        try:
            gateway_rtb_ids, interface_subnet_ids = _collect_s3_endpoints(ec2, region, vpc_id)
        except Exception as e:
            code = "Unknown"
            msg = str(e)
            if isinstance(e, ClientError):
                code = e.response.get("Error", {}).get("Code", code)
                msg = e.response.get("Error", {}).get("Message", msg)
            errors.append({"scope": "vpc", "id": vpc_id, "op": "DescribeVpcEndpoints", "code": code, "message": msg})
            gateway_rtb_ids, interface_subnet_ids = set(), set()

        out_inspected[vpc_id] = {
            "region": region,
            "gateway_endpoint_route_tables": sorted(gateway_rtb_ids),
            "interface_endpoint_subnets": sorted(interface_subnet_ids),
        }

        # evaluate each target subnet
        for subnet_id in target_subnets:
            rtb_id = subnet_to_rtb.get(subnet_id) or main_rtb_id
            has_gateway = bool(rtb_id and rtb_id in gateway_rtb_ids)
            has_interface = subnet_id in interface_subnet_ids

            if has_gateway or has_interface:
                continue  # covered

            # collect only ec2/fargate resources for reporting
            resources = {}
            sb = vpc_body.get(subnet_id, {}) or {}
            for svc in ("ec2", "fargate"):
                if isinstance(sb.get(svc), dict) and sb[svc]:
                    resources[svc] = {}
                    for rid, meta in sb[svc].items():
                        if isinstance(meta, dict):
                            resources[svc][rid] = {
                                "name": meta.get("name"),
                                "createdat": meta.get("createdat"),
                            }

            if not resources:
                continue  # shouldn't happen; this subnet was selected for ec2/fargate

            out_affected.setdefault(vpc_id, {})[subnet_id] = {
                "missing": ["gateway", "interface"],
                "route_table": rtb_id,
                "resources": resources,
            }

    return {
        "affected": out_affected,
        "inspected": out_inspected
    }
