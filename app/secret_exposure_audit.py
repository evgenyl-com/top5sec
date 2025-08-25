"""
secret_exposure_audit.py

Checks ECS task definitions and Lambda environment variables for exposed secrets.
Returns a dict:
{
    "ecs": {"task_def_arn": [list of exposed env vars]},
    "lambda": {"function_name": [list of exposed env vars]}
}
"""
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, Optional, List
import re

SECRET_PATTERNS = [
    re.compile(r"(?i)secret"),
    re.compile(r"(?i)key"),
    re.compile(r"(?i)token"),
    re.compile(r"(?i)password"),
    re.compile(r"(?i)aws_access_key_id"),
    re.compile(r"(?i)aws_secret_access_key"),
]


def _is_secret_var(name: str, value: str) -> bool:
    for pat in SECRET_PATTERNS:
        if pat.search(name) or pat.search(value):
            return True
    return False


def audit_secret_exposure(session: Optional[boto3.Session] = None) -> Dict[str, Any]:
    import concurrent.futures
    session = session or boto3.Session()
    result: Dict[str, Any] = {"ecs": {}, "lambda": {}}

    def ecs_task_worker(arn):
        try:
            ecs = session.client("ecs")
            td = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
            containers = td.get("containerDefinitions", [])
            exposed = []
            for c in containers:
                for env in c.get("environment", []):
                    name = env.get("name", "")
                    value = env.get("value", "")
                    if _is_secret_var(name, value):
                        exposed.append({"container": c.get("name"), "name": name, "value": value})
            if exposed:
                return (arn, exposed)
        except Exception:
            return None

    def lambda_worker(fn):
        try:
            lam = session.client("lambda")
            name = fn["FunctionName"]
            conf = lam.get_function_configuration(FunctionName=name)
            env = conf.get("Environment", {}).get("Variables", {})
            exposed = []
            for k, v in env.items():
                if _is_secret_var(k, v):
                    exposed.append({"name": k, "value": v})
            if exposed:
                return (name, exposed)
        except Exception:
            return None

    # ECS Task Definitions
    try:
        ecs = session.client("ecs")
        paginator = ecs.get_paginator("list_task_definitions")
        arns = []
        for page in paginator.paginate():
            arns.extend(page.get("taskDefinitionArns", []))
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(ecs_task_worker, arn) for arn in arns]
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res:
                    result["ecs"][res[0]] = res[1]
    except (ClientError, BotoCoreError):
        pass

    # Lambda Functions
    try:
        lam = session.client("lambda")
        paginator = lam.get_paginator("list_functions")
        fns = []
        for page in paginator.paginate():
            fns.extend(page.get("Functions", []))
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(lambda_worker, fn) for fn in fns]
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res:
                    result["lambda"][res[0]] = res[1]
    except (ClientError, BotoCoreError):
        pass

    return result
