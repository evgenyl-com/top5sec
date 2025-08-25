import boto3
import botocore
import sys
import os
import concurrent.futures
import time
import threading
import psutil
from generate_html_report import generate_html_report


# Local imports
from inventory_vpc_services import resource_inventory
from cloudtrail_logging_audit import audit_cloudtrail_logging_coverage
from network_public_subnets import analyze_public_subnets
from public_subnets import generate_public_subnet
from sg_world_open_finder import find_world_open_resources
from iam_audit_users import audit_iam_users
from s3_public_and_acl_audit import audit_s3_public_and_acls
from vpc_s3_endpoint_coverage import find_subnets_missing_s3_endpoints
from encryption_audit import audit_encryption
from iam_role_trust_audit import audit_iam_role_trust
from secret_exposure_audit import audit_secret_exposure
from public_subnets_report import describe_public_subnets
from sg_world_open_report import describe_world_open_sgs
from cloudtrail_logging_report import describe_cloudtrail_logging_coverage
from iam_users_report import describe_iam_users_audit
from iam_role_trust_report import describe_iam_role_trust_audit
from s3_public_acl_report import describe_s3_public_acl_audit
from encryption_report import describe_encryption_audit
from vpc_s3_endpoint_report import describe_vpc_s3_endpoint_coverage


def get_boto3_session() -> boto3.Session:
    """
    Create a boto3 session.
    If ROLE_ARN env var is set, assume role via STS. Otherwise, use default credentials.
    """
    role_arn = os.getenv("ROLE_ARN")
    if role_arn:
        try:
            sts_client = boto3.client("sts")
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="top5secSession"
            )
            credentials = response["Credentials"]
            return boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
            )
        except Exception as e:
            print(f"❌ Failed to assume role {role_arn}: {e}", file=sys.stderr)
            sys.exit(1)
    # Use default env vars or ~/.aws/credentials
    return boto3.Session()


def get_account_id(session: boto3.Session) -> str:
    """
    Retrieve AWS account ID using STS client.
    """
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        return identity["Account"]
    except botocore.exceptions.NoCredentialsError:
        print("❌ No AWS credentials found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Failed to retrieve account ID: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """
    Main entry point for top5sec AWS Scanner.
    Runs all audits and prints results.
    """

    session = get_boto3_session()
    account_id = get_account_id(session)
    print(f"✅ Connected to AWS Account: {account_id}")

    # Inventory collection (must be single-threaded, used by other audits)
    inventory = resource_inventory(session)
    net_analysis = analyze_public_subnets(inventory, session=session)

    # Define audit functions and their arguments
    audit_tasks = {
        "secret_exposure_results": (audit_secret_exposure, {"session": session}),
        "offenders": (find_world_open_resources, {"inventory": inventory, "session": session}),
        "ct_audit": (audit_cloudtrail_logging_coverage, {"session": session}),
        "public_subnets": (generate_public_subnet, {"inventory": inventory, "net_analysis": net_analysis}),
        "iam_audit": (audit_iam_users, {"session": session, "stale_days": 100}),
        "role_trust_results": (audit_iam_role_trust, {"session": session}),
        "s3_audit": (audit_s3_public_and_acls, {"session": session}),
        "encryption_results": (audit_encryption, {"session": session}),
        "coverage": (find_subnets_missing_s3_endpoints, {"inventory": inventory, "session": session}),
    }

    results = {}
    exec_times = {}
    resource_stats = []

    def monitor_resources(stop_event, stats_list):
        if not psutil:
            return
        proc = psutil.Process(os.getpid())
        net0 = psutil.net_io_counters()
        while not stop_event.is_set():
            cpu_times = psutil.cpu_times_percent(interval=None)
            mem = proc.memory_info().rss / (1024 * 1024)  # MB
            net = psutil.net_io_counters()
            net_sent = net.bytes_sent - net0.bytes_sent
            net_recv = net.bytes_recv - net0.bytes_recv
            stats_list.append({
                "timestamp": time.time(),
                "cpu_user": cpu_times.user,
                "cpu_system": cpu_times.system,
                "cpu_idle": cpu_times.idle,
                "memory_mb": mem,
                "net_sent_bytes": net_sent,
                "net_recv_bytes": net_recv
            })
            time.sleep(1)

    stop_event = threading.Event()
    monitor_thread = threading.Thread(target=monitor_resources, args=(stop_event, resource_stats))
    monitor_thread.start()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_map = {}
        start_times = {}
        for name, (func, kwargs) in audit_tasks.items():
            start_times[name] = time.time()
            future_map[name] = executor.submit(func, **kwargs)
        for name, future in future_map.items():
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = f"Error: {e}"
            exec_times[name] = time.time() - start_times[name]

    stop_event.set()
    monitor_thread.join()

    # Report max CPU and memory usage
    if resource_stats:
        max_cpu = max((s["cpu_user"] + s["cpu_system"] for s in resource_stats), default=0)
        max_mem = max((s["memory_mb"] for s in resource_stats), default=0)
        print(f"Max CPU usage: {max_cpu:.1f}% (user+system)")
        print(f"Max memory usage: {max_mem:.1f} MB")

    results_summary = {}
    next_key = 1

    world_open_sgs = describe_world_open_sgs(results["offenders"])
    if world_open_sgs:
        results_summary[next_key] = world_open_sgs
        next_key += 1

    ct_overall = results["ct_audit"].get("overall", {}) if isinstance(results["ct_audit"], dict) else {}
    has_logging = ct_overall.get("has_any_logging_trail", True)
    all_covered = ct_overall.get("all_regions_covered", True)
    if not has_logging or not all_covered:
        cloudtrail_logging_coverage = describe_cloudtrail_logging_coverage(results["ct_audit"])
        if cloudtrail_logging_coverage:
            results_summary[next_key] = cloudtrail_logging_coverage
            next_key += 1
        if not has_logging:
            print("CloudTrail logging is NOT enabled for this account. This is a critical security risk.")
        elif not all_covered:
            uncovered = ct_overall.get("uncovered_regions", [])
            print(f"CloudTrail logging is NOT enabled in the following regions: {', '.join(uncovered) if uncovered else 'Unknown'}.")

    public_subnets = describe_public_subnets(results["public_subnets"])
    if public_subnets:
        results_summary[next_key] = public_subnets
        next_key += 1

    iam_audit = describe_iam_users_audit(results["iam_audit"])
    if iam_audit:
        results_summary[next_key] = iam_audit
        next_key += 1

    role_trust_audit = describe_iam_role_trust_audit(results["role_trust_results"])
    if role_trust_audit:
        results_summary[next_key] = role_trust_audit
        next_key += 1

    s3_public_acl_audit = describe_s3_public_acl_audit(results["s3_audit"])
    if s3_public_acl_audit:
        results_summary[next_key] = s3_public_acl_audit
        next_key += 1

    encryption_audit = describe_encryption_audit(results["encryption_results"])
    if encryption_audit:
        results_summary[next_key] = encryption_audit
        next_key += 1

    vpc_s3_endpoint_coverage = describe_vpc_s3_endpoint_coverage(results["coverage"])
    if vpc_s3_endpoint_coverage:
        results_summary[next_key] = vpc_s3_endpoint_coverage
        next_key += 1
    print(results_summary)

    # Get current date/time and default region
    report_date = time.strftime('%d.%m.%Y %H:%M')
    region = session.region_name or os.getenv('AWS_DEFAULT_REGION', 'unknown')
    generate_html_report(results_summary, account_id=account_id, region=region, report_date=report_date)


if __name__ == "__main__":
    main()

