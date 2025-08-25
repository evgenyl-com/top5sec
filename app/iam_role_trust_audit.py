"""
iam_role_trust_audit.py

Detects IAM roles that are trusted by other AWS accounts and have high privileges.
Returns a dict:
{
    "role_name": {
        "trusted_accounts": [...],
        "high_privileges": bool,
        "privilege_details": {...}
    }
}
"""
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, Optional, List
import json

def _is_high_privilege(policy_doc: dict) -> bool:
    # Checks for wildcard actions or admin policies
    for stmt in policy_doc.get("Statement", []):
        if isinstance(stmt, str):
            # If statement is a string, skip (malformed or unexpected)
            continue
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action")
        if actions == "*" or (isinstance(actions, list) and "*" in actions):
            return True
        if isinstance(actions, list):
            for act in actions:
                if isinstance(act, str) and act.lower() in ["iam:*", "sts:*", "ec2:*", "s3:*", "*"]:
                    return True
        elif isinstance(actions, str) and actions.lower() in ["iam:*", "sts:*", "ec2:*", "s3:*", "*"]:
            return True
    return False

def audit_iam_role_trust(session: Optional[boto3.Session] = None) -> Dict[str, Any]:
    import concurrent.futures
    session = session or boto3.Session()
    iam = session.client("iam")
    result: Dict[str, Any] = {}
    try:
        paginator = iam.get_paginator("list_roles")
        roles = []
        for page in paginator.paginate():
            roles.extend(page.get("Roles", []))

        def role_worker(role):
            role_name = role["RoleName"]
            trust_doc = role["AssumeRolePolicyDocument"]
            trusted_accounts: List[str] = []
            for stmt in trust_doc.get("Statement", []):
                principal = stmt.get("Principal", {})
                aws = principal.get("AWS")
                if aws:
                    if isinstance(aws, str):
                        if ":root" in aws or ":user/" in aws:
                            parts = aws.split(":")
                            if len(parts) > 4:
                                acct = parts[4]
                                if acct != session.client("sts").get_caller_identity()["Account"]:
                                    trusted_accounts.append(acct)
                    elif isinstance(aws, list):
                        for arn in aws:
                            parts = arn.split(":")
                            if len(parts) > 4:
                                acct = parts[4]
                                if acct != session.client("sts").get_caller_identity()["Account"]:
                                    trusted_accounts.append(acct)
            # Check for high privilege policies
            high_priv = False
            priv_details = {}
            attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
            for pol in attached:
                pol_arn = pol["PolicyArn"]
                pol_ver = iam.get_policy(PolicyArn=pol_arn)["Policy"]["DefaultVersionId"]
                pol_doc = iam.get_policy_version(PolicyArn=pol_arn, VersionId=pol_ver)["PolicyVersion"]["Document"]
                if _is_high_privilege(pol_doc):
                    high_priv = True
                    priv_details[pol_arn] = pol_doc
            # Inline policies
            inline = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
            for pname in inline:
                pol_doc = iam.get_role_policy(RoleName=role_name, PolicyName=pname)["PolicyDocument"]
                if _is_high_privilege(pol_doc):
                    high_priv = True
                    priv_details[pname] = pol_doc
            if trusted_accounts and high_priv:
                return (role_name, {
                    "trusted_accounts": trusted_accounts,
                    "high_privileges": high_priv,
                    "privilege_details": priv_details
                })
            return None

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(role_worker, role) for role in roles]
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res:
                    result[res[0]] = res[1]
    except (ClientError, BotoCoreError) as e:
        result["error"] = str(e)
    return result
