"""
s3_public_and_acl_audit.py

Finds effectively public S3 buckets and buckets with ACLs enabled across all regions.
"""

from __future__ import annotations

import os
import json
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, BotoCoreError


ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


# ---------------- Session / helpers ----------------

def _get_session() -> boto3.Session:
    """
    Return a boto3 session using environment region variables.
    """
    region = os.getenv("REGION") or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
    return boto3.Session(region_name=region)


def _get_account_id(session: boto3.Session) -> Optional[str]:
    """
    Get AWS account ID from session.
    """
    try:
        return session.client("sts").get_caller_identity()["Account"]
    except Exception:
        return None


def _record_error(errors: List[Dict[str, str]], bucket: str, op: str, e: Exception) -> None:
    code = ""
    msg = str(e)
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "")
        msg = e.response.get("Error", {}).get("Message", msg)
    errors.append({"bucket": bucket, "op": op, "code": code, "message": msg})


# ---------------- S3/S3Control queries ----------------

def _list_buckets(s3) -> List[Dict[str, Any]]:
    resp = s3.list_buckets()
    return resp.get("Buckets", [])


def _get_bucket_region(s3, bucket: str) -> Optional[str]:
    """
    Returns bucket region (e.g., 'us-east-1'). For classic us-east-1, LocationConstraint can be None.
    """
    try:
        r = s3.get_bucket_location(Bucket=bucket)
        lc = r.get("LocationConstraint")
        return "us-east-1" if lc in (None, "", "US") else lc
    except ClientError:
        return None


def _get_bucket_pab(s3_regional, bucket: str) -> Optional[Dict[str, bool]]:
    try:
        r = s3_regional.get_public_access_block(Bucket=bucket)
        cfg = r.get("PublicAccessBlockConfiguration", {})
        return {
            "BlockPublicAcls": bool(cfg.get("BlockPublicAcls")),
            "IgnorePublicAcls": bool(cfg.get("IgnorePublicAcls")),
            "BlockPublicPolicy": bool(cfg.get("BlockPublicPolicy")),
            "RestrictPublicBuckets": bool(cfg.get("RestrictPublicBuckets")),
        }
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"):
            return None
        raise


def _get_account_pab(session: boto3.Session, account_id: Optional[str]) -> Optional[Dict[str, bool]]:
    if not account_id:
        return None
    try:
        s3c = session.client("s3control")
        r = s3c.get_public_access_block(AccountId=account_id)
        cfg = r.get("PublicAccessBlockConfiguration", {})
        return {
            "BlockPublicAcls": bool(cfg.get("BlockPublicAcls")),
            "IgnorePublicAcls": bool(cfg.get("IgnorePublicAcls")),
            "BlockPublicPolicy": bool(cfg.get("BlockPublicPolicy")),
            "RestrictPublicBuckets": bool(cfg.get("RestrictPublicBuckets")),
        }
    except ClientError:
        return None


def _get_bucket_ownership_controls(s3_regional, bucket: str) -> Optional[str]:
    """
    Returns ObjectOwnership value:
      - 'BucketOwnerEnforced' (ACLs disabled)
      - 'BucketOwnerPreferred' or 'ObjectWriter' (ACLs enabled)
      - None if not configured / unknown
    """
    try:
        r = s3_regional.get_bucket_ownership_controls(Bucket=bucket)
        rules = r.get("OwnershipControls", {}).get("Rules", [])
        for rule in rules:
            oo = rule.get("ObjectOwnership")
            if oo:
                return oo
        return None
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("OwnershipControlsNotFoundError", "NoSuchOwnershipControls"):
            return None
        raise


def _get_bucket_acl_public_grants(s3_regional, bucket: str) -> List[Dict[str, str]]:
    """
    Returns grants that expose to AllUsers / AuthenticatedUsers.
    """
    grants_out: List[Dict[str, str]] = []
    r = s3_regional.get_bucket_acl(Bucket=bucket)
    for g in r.get("Grants", []) or []:
        grantee = g.get("Grantee", {}) or {}
        perm = g.get("Permission", "")
        uri = grantee.get("URI")
        if grantee.get("Type") == "Group" and uri in (ALL_USERS_URI, AUTH_USERS_URI):
            who = "AllUsers" if uri == ALL_USERS_URI else "AuthenticatedUsers"
            grants_out.append({"grantee": who, "permission": perm})
    return grants_out


def _get_bucket_policy_public_actions(s3_regional, bucket: str) -> List[str]:
    """
    Return a set of actions that are publicly allowed by bucket policy (Principal='*').
    This is a *heuristic*; it does not fully evaluate conditions.
    """
    try:
        p = s3_regional.get_bucket_policy(Bucket=bucket)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("NoSuchBucketPolicy", "NoSuchPolicy"):
            return []
        raise

    doc = json.loads(p.get("Policy", "{}") or "{}")
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    public_actions: set[str] = set()

    def _is_public_principal(pr):
        if pr == "*" or pr == ["*"]:
            return True
        if isinstance(pr, dict):
            # Principal can be {"AWS":"*"} or {"CanonicalUser":"*"} etc.
            for v in pr.values():
                if v == "*" or (isinstance(v, list) and "*" in v):
                    return True
        if isinstance(pr, list):
            return "*" in pr
        return False

    for s in statements:
        if not isinstance(s, dict):
            continue
        if str(s.get("Effect", "")).lower() != "allow":
            continue
        principal = s.get("Principal", {})
        if not _is_public_principal(principal):
            continue

        actions = s.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for a in actions:
            public_actions.add(a)

    return sorted(public_actions)


def _get_bucket_website_enabled(s3_regional, bucket: str) -> bool:
    try:
        s3_regional.get_bucket_website(Bucket=bucket)
        return True
    except ClientError:
        return False


# ---------------- Evaluation logic ----------------

def _effective_blocks(pab_bucket: Optional[Dict[str, bool]], pab_account: Optional[Dict[str, bool]]) -> Tuple[bool, bool]:
    """
    Returns (block_acls, block_policy) booleans combining bucket and account PAB.
    If either level blocks, we treat it as blocked.
    """
    block_acls = False
    block_policy = False
    for src in (pab_bucket or {}, pab_account or {}):
        if src.get("BlockPublicAcls") or src.get("IgnorePublicAcls"):
            block_acls = True
        if src.get("BlockPublicPolicy") or src.get("RestrictPublicBuckets"):
            block_policy = True
    return block_acls, block_policy


def audit_s3_public_and_acls(session: Optional[boto3.Session] = None) -> Dict[str, Any]:
    """
    Main entry. Returns the dictionary described in the module docstring.
    """
    session = session or _get_session()
    s3 = session.client("s3")
    account_id = _get_account_id(session)
    pab_account = _get_account_pab(session, account_id)

    buckets = _list_buckets(s3)
    errors: List[Dict[str, str]] = []
    effective_public: List[Dict[str, Any]] = []
    acls_enabled_list: List[Dict[str, Any]] = []

    for b in buckets:
        name = b.get("Name")
        if not name:
            continue

        # Discover region
        try:
            region = _get_bucket_region(s3, name) or "us-east-1"
            s3_regional = session.client("s3", region_name=region)
        except Exception as e:
            _record_error(errors, name, "GetBucketLocation", e)
            continue

        # Bucket-level Public Access Block
        try:
            pab_bucket = _get_bucket_pab(s3_regional, name)
        except Exception as e:
            _record_error(errors, name, "GetPublicAccessBlock", e)
            pab_bucket = None

        # Ownership controls => ACLs enabled?
        acls_enabled = True
        obj_ownership = None
        try:
            obj_ownership = _get_bucket_ownership_controls(s3_regional, name)
            if obj_ownership == "BucketOwnerEnforced":
                acls_enabled = False
        except Exception as e:
            # Missing/denied -> treat as unknown (assume enabled for safety)
            _record_error(errors, name, "GetBucketOwnershipControls", e)
            obj_ownership = None
            acls_enabled = True

        if acls_enabled:
            acls_enabled_list.append({
                "bucket": name,
                "region": region,
                "object_ownership": obj_ownership or "<unknown>",
            })

        # Public via ACL?
        public_acl_grants: List[Dict[str, str]] = []
        if acls_enabled:
            try:
                public_acl_grants = _get_bucket_acl_public_grants(s3_regional, name)
            except Exception as e:
                _record_error(errors, name, "GetBucketAcl", e)
                public_acl_grants = []

        has_public_acl = len(public_acl_grants) > 0

        # Public via Policy?
        policy_public_actions: List[str] = []
        try:
            policy_public_actions = _get_bucket_policy_public_actions(s3_regional, name)
        except Exception as e:
            _record_error(errors, name, "GetBucketPolicy", e)
            policy_public_actions = []

        has_public_policy = len(policy_public_actions) > 0

        # Effective block evaluation
        block_acls, block_policy = _effective_blocks(pab_bucket, pab_account)

        # Effective public if public setting exists AND not blocked by PAB
        is_effective_public = (has_public_acl and not block_acls) or (has_public_policy and not block_policy)

        if is_effective_public:
            website_enabled = False
            try:
                website_enabled = _get_bucket_website_enabled(s3_regional, name)
            except Exception as e:
                _record_error(errors, name, "GetBucketWebsite", e)

            reasons = []
            if has_public_acl and not block_acls:
                reasons.append("public-acl")
            if has_public_policy and not block_policy:
                reasons.append("public-policy")

            effective_public.append({
                "bucket": name,
                "region": region,
                "reasons": reasons,
                "acl_grants": public_acl_grants,
                "policy_public_actions": policy_public_actions,
                "public_access_block": {"bucket": pab_bucket, "account": pab_account},
                "website_enabled": website_enabled,
            })

    return {
        "effective_public_buckets": effective_public,
        "buckets_with_acls_enabled": acls_enabled_list,
        "scanned_buckets": len(buckets)
    }

