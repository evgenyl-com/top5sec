"""
iam_audit_users.py

Audit IAM users for security best practices:
- Users with console access but no MFA
- Users with active access keys
- Users with stale last activity (password or key)

Usage:
    from iam_audit_users import audit_iam_users
    result = audit_iam_users(session=session, stale_days=100)
    print(result)
"""

from __future__ import annotations

import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, BotoCoreError


def _get_session() -> boto3.Session:
    """
    Return a boto3 session using environment region variables.
    """
    region = os.getenv("REGION") or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
    return boto3.Session(region_name=region)


# def _iso(dt: Optional[datetime]) -> Optional[str]:
#     return dt.astimezone(timezone.utc).isoformat() if isinstance(dt, datetime) else None


def _user_has_console_access(iam, username: str) -> Optional[bool]:
    """
    Check if user has console access (login profile).
    Returns True, False, or None if access denied.
    """
    try:
        iam.get_login_profile(UserName=username)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in {"AccessDenied", "AccessDeniedException"}:
            return None
        raise


def _user_has_mfa(iam, username: str) -> bool:
    """
    Check if user has any MFA devices enabled.
    """
    paginator = iam.get_paginator("list_mfa_devices")
    for page in paginator.paginate(UserName=username):
        if page.get("MFADevices"):
            return True
    return False


def _list_users(iam) -> List[Dict[str, Any]]:
    """
    List all IAM users in the account.
    """
    users: List[Dict[str, Any]] = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        users.extend(page.get("Users", []))
    return users


def _list_active_access_keys(iam, username: str) -> List[str]:
    """
    List all active access keys for a user.
    """
    keys: List[str] = []
    paginator = iam.get_paginator("list_access_keys")
    for page in paginator.paginate(UserName=username):
        for md in page.get("AccessKeyMetadata", []):
            if md.get("Status") == "Active":
                keys.append(md["AccessKeyId"])
    return keys


def _get_access_key_last_used(iam, access_key_id: str) -> Optional[datetime]:
    """
    Get the last used date for an access key.
    """
    try:
        resp = iam.get_access_key_last_used(AccessKeyId=access_key_id)
    except ClientError:
        return None
    used = resp.get("AccessKeyLastUsed", {})
    return used.get("LastUsedDate")


def _latest_key_activity(iam, access_key_ids: List[str]) -> Optional[datetime]:
    """
    Get the latest activity date among a user's access keys.
    """
    latest = None
    for ak in access_key_ids:
        d = _get_access_key_last_used(iam, ak)
        if d and (latest is None or d > latest):
            latest = d
    return latest


def audit_iam_users(
    session: Optional[boto3.Session] = None,
    *,
    stale_days: int = 100,
    treat_unknown_as_stale: bool = True,
) -> Dict[str, Any]:
    """
    Audit IAM users for security best practices.
    Returns a dict with users missing MFA, users with active keys, and stale users.
    """
    session = session or _get_session()
    iam = session.client("iam")

    users = _list_users(iam)
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=stale_days)

    out_no_mfa: List[Dict[str, Any]] = []
    out_keys: List[Dict[str, Any]] = []
    out_stale: List[Dict[str, Any]] = []

    for u in users:
        username = u["UserName"]
        if username == "<root_account>":
            continue

        created: Optional[datetime] = u.get("CreateDate")
        password_last_used: Optional[datetime] = u.get("PasswordLastUsed")

        # Console access (login profile)
        try:
            console_access = _user_has_console_access(iam, username)
        except (ClientError, BotoCoreError):
            console_access = None

        # MFA
        try:
            mfa_active = _user_has_mfa(iam, username)
        except (ClientError, BotoCoreError):
            mfa_active = False

        # Active access keys and their last-used
        try:
            active_keys = _list_active_access_keys(iam, username)
        except (ClientError, BotoCoreError):
            active_keys = []

        latest_key_used = _latest_key_activity(iam, active_keys) if active_keys else None

        # 1) Console access but NO MFA
        if console_access is True and not mfa_active:
            out_no_mfa.append({
                "user": username,
                "arn": u.get("Arn"),
                "created": int(created.timestamp()) if created else None,
                "console_access": True,
                "mfa_active": False,
            })

        # 2) Users with ACTIVE access keys
        if active_keys:
            out_keys.append({
                "user": username,
                "arn": u.get("Arn"),
                "created": int(created.timestamp()) if created else None,
                "access_keys_active": active_keys,
            })

        # 3) Stale last activity (max of password last used & any key last used)
        last_activity = password_last_used
        if latest_key_used and (last_activity is None or latest_key_used > last_activity):
            last_activity = latest_key_used

        reason = None
        if last_activity is None:
            if treat_unknown_as_stale:
                reason = "no-activity-data"
        elif last_activity < threshold:
            reason = "older-than-threshold"

        if reason:
            days_inactive = None if last_activity is None else (now - last_activity).days
            out_stale.append({
                "user": username,
                "arn": u.get("Arn"),
                "created": int(created.timestamp()) if created else None,
                "last_activity": int(last_activity.timestamp()) if last_activity else None,
                "days_inactive": days_inactive,
                "reason": reason,
            })

    return {
        "no_mfa_console_users": out_no_mfa,
        "users_with_access_keys": out_keys,
        "stale_users": out_stale,
        "generated_at": int(now.timestamp()) if now else None,
        "stale_days_threshold": stale_days,
        "treat_unknown_as_stale": treat_unknown_as_stale,
    }
