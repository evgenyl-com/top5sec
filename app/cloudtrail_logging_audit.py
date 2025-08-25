"""
cloudtrail_logging_audit.py

Audit CloudTrail logging coverage across all enabled AWS regions.

Logic:
- Enumerate enabled regions via EC2 DescribeRegions.
- Collect all trails via CloudTrail DescribeTrails(includeShadowTrails=True).
- For each trail, query GetTrailStatus in its HomeRegion to check logging.
- A region is "covered" if:
    * At least one multi-region trail is logging, OR
    * There is a single-region trail whose HomeRegion == that region and is logging.

Returns:
    Dict with overall coverage, per-region details, and errors.
"""

from __future__ import annotations
import os
from typing import Any, Dict, List, Optional
import boto3
from botocore.exceptions import ClientError, BotoCoreError


# ------------- session & region helpers -------------

def _get_session(session: Optional[boto3.Session] = None) -> boto3.Session:
    """
    Return a boto3 session, using the provided session or environment region.
    """
    if session:
        return session
    region = os.getenv("REGION") or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
    return boto3.Session(region_name=region)


def _list_enabled_regions(session: boto3.Session) -> List[str]:
    """
    List all enabled AWS regions for the account.
    """
    ec2 = session.client("ec2", region_name="us-east-1")
    resp = ec2.describe_regions(AllRegions=True)
    regions = [r["RegionName"] for r in resp.get("Regions", []) if r.get("OptInStatus") != "not-opted-in"]
    return sorted(regions)


# ------------- trails collection & status -------------

def _collect_trails_all_regions(session: boto3.Session, regions: List[str], errors: List[Dict[str, str]]) -> Dict[str, Dict[str, Any]]:
    """
    Collect all CloudTrail trails across enabled regions.
    Returns a dict keyed by TrailARN with summary info.
    """
    trails: Dict[str, Dict[str, Any]] = {}
    for region in regions:
        ct = session.client("cloudtrail", region_name=region)
        try:
            resp = ct.describe_trails(includeShadowTrails=True)
        except (ClientError, BotoCoreError) as e:
            code = getattr(e, 'response', {}).get("Error", {}).get("Code", "BotoCoreError")
            message = getattr(e, 'response', {}).get("Error", {}).get("Message", str(e))
            errors.append({
                "scope": "region",
                "id": region,
                "op": "DescribeTrails",
                "code": code,
                "message": message,
            })
            continue
        for t in resp.get("trailList", []) or []:
            arn = t.get("TrailARN")
            if not arn or arn in trails:
                continue
            trails[arn] = {
                "name": t.get("Name"),
                "arn": arn,
                "home_region": t.get("HomeRegion"),
                "is_multi": bool(t.get("IsMultiRegionTrail")),
                "is_org": bool(t.get("IsOrganizationTrail")),
                "is_logging": False,  # filled later
            }
    return trails


def _fill_trail_status(session: boto3.Session, trails: Dict[str, Dict[str, Any]], errors: List[Dict[str, str]]) -> None:
    """
    Mutate trails dict in place to add "is_logging" for each trail.
    Calls GetTrailStatus in the trail's home region.
    """
    for arn, meta in trails.items():
        home = meta.get("home_region") or "us-east-1"
        ct = session.client("cloudtrail", region_name=home)
        try:
            status = ct.get_trail_status(Name=arn)
            meta["is_logging"] = bool(status.get("IsLogging"))
        except (ClientError, BotoCoreError) as e:
            meta["is_logging"] = False
            code = getattr(e, 'response', {}).get("Error", {}).get("Code", "BotoCoreError")
            message = getattr(e, 'response', {}).get("Error", {}).get("Message", str(e))
            errors.append({
                "scope": "trail",
                "id": arn,
                "op": "GetTrailStatus",
                "code": code,
                "message": message,
            })


# ------------- coverage evaluation -------------

def audit_cloudtrail_logging_coverage(session: Optional[boto3.Session] = None) -> Dict[str, Any]:
    """
    Audit CloudTrail logging coverage across all enabled regions.
    Returns a dict with overall coverage, per-region details, and errors.
    """
    sess = _get_session(session)
    errors: List[Dict[str, str]] = []

    regions = _list_enabled_regions(sess)
    trails = _collect_trails_all_regions(sess, regions, errors)
    _fill_trail_status(sess, trails, errors)

    multi_logging = [t for t in trails.values() if t["is_multi"] and t["is_logging"]]
    single_logging = [t for t in trails.values() if not t["is_multi"] and t["is_logging"]]
    any_logging = bool(multi_logging or single_logging)

    per_region: Dict[str, Dict[str, Any]] = {}
    covered_regions: List[str] = []
    uncovered_regions: List[str] = []

    multi_reason = []
    if multi_logging:
        names = [t["name"] or t["arn"] for t in multi_logging]
        multi_reason = [f"multi-region trail: {', '.join(names)}"]

    for r in regions:
        covered = False
        reasons: List[str] = []
        if multi_logging:
            covered = True
            reasons.extend(multi_reason)
        singles_here = [t for t in single_logging if t.get("home_region") == r]
        if singles_here:
            covered = True
            names = ", ".join([t["name"] or t["arn"] for t in singles_here])
            reasons.append(f"single-region trail(s) in {r}: {names}")
        per_region[r] = {"covered": covered, "reasons": reasons}
        (covered_regions if covered else uncovered_regions).append(r)

    return {
        "overall": {
            "has_any_logging_trail": any_logging,
            "all_regions_covered": (len(uncovered_regions) == 0) if regions else False,
            "covered_regions": covered_regions,
            "uncovered_regions": uncovered_regions,
            "trail_counts": {"total": len(trails), "logging": len(multi_logging) + len(single_logging)},
            "multi_region_trails_logging": [
                {
                    "name": t["name"],
                    "arn": t["arn"],
                    "home_region": t["home_region"],
                    "is_org": t["is_org"],
                } for t in multi_logging
            ],
            "single_region_trails_logging": [
                {
                    "name": t["name"],
                    "arn": t["arn"],
                    "home_region": t["home_region"],
                    "is_org": t["is_org"],
                } for t in single_logging
            ],
        },
        "per_region": per_region,
        "errors": errors
    }

