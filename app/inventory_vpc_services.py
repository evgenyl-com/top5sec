#!/usr/bin/env python3
"""
Build a VPC/Subnet/Service/Resource inventory.

Output shape:
{
  "<vpc_id>": {
    "<subnet_id>": {
      "<service>": {
        "<resource_id>": {
          "createdat": <epoch>,
          "name": "<resource name>"
        }
      }
    }
  }
}
"""

import os
import sys
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Iterable, List

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def _to_epoch(dt: Optional[datetime]) -> Optional[int]:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _add(tree: Dict[str, Any],
         vpc_id: str,
         subnet_id: str,
         service: str,
         resource_key: str,
         name: str,
         created_at: Optional[datetime]) -> None:
    v = tree.setdefault(vpc_id, {})
    s = v.setdefault(subnet_id, {})
    svc = s.setdefault(service, {})
    svc[resource_key] = {"createdat": _to_epoch(created_at), "name": name}


def _map_subnet_to_vpc(ec2, subnet_ids: Iterable[str]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    ids = list({sid for sid in subnet_ids if sid})
    for i in range(0, len(ids), 200):
        chunk = ids[i:i + 200]
        if not chunk:
            continue
        resp = ec2.describe_subnets(SubnetIds=chunk)
        for sn in resp.get("Subnets", []):
            mapping[sn["SubnetId"]] = sn["VpcId"]
    return mapping


def _collect_ec2_instances(session, tree):
    ec2 = session.client("ec2")
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    vpc = inst.get("VpcId")
                    subnet = inst.get("SubnetId")
                    if not vpc or not subnet:
                        continue
                    name = next((t["Value"] for t in inst.get("Tags", [])
                                 if t["Key"] == "Name"), inst["InstanceId"])
                    _add(tree, vpc, subnet, "ec2", inst["InstanceId"], name, inst.get("LaunchTime"))
    except (BotoCoreError, ClientError) as e:
        print(f"[warn] EC2: {e}", file=sys.stderr)


def _collect_elbv2(session, tree):
    elb = session.client("elbv2")
    ec2 = session.client("ec2")
    try:
        lbs: List[dict] = []
        p = elb.get_paginator("describe_load_balancers")
        for page in p.paginate():
            lbs.extend(page.get("LoadBalancers", []))

        subnet_ids = []
        for lb in lbs:
            for az in lb.get("AvailabilityZones", []):
                if "SubnetId" in az:
                    subnet_ids.append(az["SubnetId"])
        sn2vpc = _map_subnet_to_vpc(ec2, subnet_ids)

        for lb in lbs:
            name = lb["LoadBalancerName"]
            created = lb.get("CreatedTime")
            for az in lb.get("AvailabilityZones", []):
                sn = az.get("SubnetId")
                if not sn:
                    continue
                vpc = sn2vpc.get(sn) or lb.get("VpcId")
                if vpc:
                    _add(tree, vpc, sn, "elbv2", lb["LoadBalancerArn"], name, created)
    except (BotoCoreError, ClientError) as e:
        print(f"[warn] ELBv2: {e}", file=sys.stderr)


def _collect_nat_gateways(session, tree):
    ec2 = session.client("ec2")
    try:
        p = ec2.get_paginator("describe_nat_gateways")
        for page in p.paginate():
            for nat in page.get("NatGateways", []):
                vpc = nat.get("VpcId")
                sn = nat.get("SubnetId")
                if vpc and sn:
                    _add(tree, vpc, sn, "nat_gateway", nat["NatGatewayId"],
                         nat["NatGatewayId"], nat.get("CreateTime"))
    except (BotoCoreError, ClientError) as e:
        print(f"[warn] NAT Gateways: {e}", file=sys.stderr)


def _collect_rds(session, tree):
    rds = session.client("rds")
    try:
        p = rds.get_paginator("describe_db_instances")
        for page in p.paginate():
            for db in page.get("DBInstances", []):
                if db.get("Engine", "").startswith("docdb"):
                    continue  # DocumentDB handled separately
                name = db["DBInstanceIdentifier"]
                created = db.get("InstanceCreateTime")
                sg = db.get("DBSubnetGroup") or {}
                vpc = sg.get("VpcId")
                for sn in (sg.get("Subnets") or []):
                    sn_id = sn.get("SubnetIdentifier")
                    if vpc and sn_id:
                        _add(tree, vpc, sn_id, "rds", name, name, created)
    except (BotoCoreError, ClientError) as e:
        print(f"[warn] RDS: {e}", file=sys.stderr)


def _collect_docdb(session, tree):
    doc = session.client("docdb")
    try:
        clusters = []
        p = doc.get_paginator("describe_db_clusters")
        for page in p.paginate():
            clusters.extend(page.get("DBClusters", []))
        cluster_created = {c["DBClusterIdentifier"]: c.get("ClusterCreateTime") for c in clusters}

        p = doc.get_paginator("describe_db_instances")
        for page in p.paginate():
            for inst in page.get("DBInstances", []):
                if not inst.get("Engine", "").startswith("docdb"):
                    continue
                name = inst["DBInstanceIdentifier"]
                created = inst.get("InstanceCreateTime") or cluster_created.get(inst.get("DBClusterIdentifier"))
                sg = inst.get("DBSubnetGroup") or {}
                vpc = sg.get("VpcId")
                for sn in (sg.get("Subnets") or []):
                    sn_id = sn.get("SubnetIdentifier")
                    if vpc and sn_id:
                        _add(tree, vpc, sn_id, "documentdb", name, name, created)
    except (BotoCoreError, ClientError) as e:
        print(f"[warn] DocumentDB: {e}", file=sys.stderr)


def _collect_redshift(session, tree):
    red = session.client("redshift")
    try:
        subnet_groups = {}
        p = red.get_paginator("describe_cluster_subnet_groups")
        for page in p.paginate():
            for g in page.get("ClusterSubnetGroups", []):
                subnet_groups[g["ClusterSubnetGroupName"]] = g

        p = red.get_paginator("describe_clusters")
        for page in p.paginate():
            for c in page.get("Clusters", []):
                name = c["ClusterIdentifier"]
                created = c.get("ClusterCreateTime")
                sg_name = c.get("ClusterSubnetGroupName")
                sg = subnet_groups.get(sg_name, {})
                vpc = sg.get("VpcId")
                for sn in (sg.get("Subnets") or []):
                    sn_id = sn.get("SubnetIdentifier")
                    if vpc and sn_id:
                        _add(tree, vpc, sn_id, "redshift", name, name, created)
    except (BotoCoreError, ClientError) as e:
        print(f"[warn] Redshift: {e}", file=sys.stderr)


def _collect_elasticache(session, tree):
    ec = session.client("elasticache")
    try:
        subnet_groups = {}
        p = ec.get_paginator("describe_cache_subnet_groups")
        for page in p.paginate():
            for g in page.get("CacheSubnetGroups", []):
                subnet_groups[g["CacheSubnetGroupName"]] = g

        p = ec.get_paginator("describe_cache_clusters")
        for page in p.paginate(ShowCacheNodeInfo=False):
            for cl in page.get("CacheClusters", []):
                name = cl["CacheClusterId"]
                created = cl.get("CacheClusterCreateTime")
                sg_name = cl.get("CacheSubnetGroupName")
                sg = subnet_groups.get(sg_name, {})
                vpc = sg.get("VpcId")
                for sn in (sg.get("Subnets") or []):
                    sn_id = sn.get("SubnetIdentifier")
                    if vpc and sn_id:
                        _add(tree, vpc, sn_id, "elasticache", name, name, created)
    except (BotoCoreError, ClientError) as e:
        print(f"[warn] ElastiCache: {e}", file=sys.stderr)


def _collect_msk(session, tree):
    kafka = session.client("kafka")
    ec2 = session.client("ec2")
    try:
        clusters = []
        p = kafka.get_paginator("list_clusters_v2")
        for page in p.paginate():
            clusters.extend(page.get("ClusterInfoList", []))

        all_subnets = set()
        for c in clusters:
            bgi = c.get("BrokerNodeGroupInfo", {})
            for sn in bgi.get("ClientSubnets", []):
                all_subnets.add(sn)
        sn2vpc = _map_subnet_to_vpc(ec2, all_subnets)

        for c in clusters:
            arn = c["ClusterArn"]
            try:
                d = kafka.describe_cluster_v2(ClusterArn=arn)
                info = d.get("ClusterInfo", {})
                name = info.get("ClusterName", arn.split("/")[-1])
                created = info.get("CreationTime")
                bgi = info.get("BrokerNodeGroupInfo", {})
                for sn in bgi.get("ClientSubnets", []):
                    vpc = sn2vpc.get(sn)
                    if vpc:
                        _add(tree, vpc, sn, "msk", arn, name, created)
            except (BotoCoreError, ClientError) as inner:
                print(f"[warn] MSK describe {arn}: {inner}", file=sys.stderr)
    except (BotoCoreError, ClientError) as e:
        print(f"[warn] MSK: {e}", file=sys.stderr)


def _collect_ecs_fargate(session, tree):
    ecs = session.client("ecs")
    ec2 = session.client("ec2")
    try:
        clusters = []
        p = ecs.get_paginator("list_clusters")
        for page in p.paginate():
            clusters.extend(page.get("clusterArns", []))

        for cluster in clusters:
            task_arns = []
            p_tasks = ecs.get_paginator("list_tasks")
            for page in p_tasks.paginate(cluster=cluster, launchType="FARGATE"):
                task_arns.extend(page.get("taskArns", []))
            if not task_arns:
                continue

            for i in range(0, len(task_arns), 100):
                batch = task_arns[i:i + 100]
                desc = ecs.describe_tasks(cluster=cluster, tasks=batch)
                eni_ids = []
                task_by_eni = {}
                for t in desc.get("tasks", []):
                    if t.get("launchType") != "FARGATE":
                        continue
                    created = t.get("createdAt")
                    task_id = t["taskArn"].split("/")[-1]
                    for att in t.get("attachments", []):
                        if att.get("type") == "ElasticNetworkInterface":
                            eni = next((d["value"] for d in att.get("details", [])
                                        if d["name"] == "networkInterfaceId"), None)
                            if eni:
                                eni_ids.append(eni)
                                task_by_eni[eni] = (task_id, created)

                if eni_ids:
                    eni_desc = ec2.describe_network_interfaces(NetworkInterfaceIds=eni_ids)
                    for ni in eni_desc.get("NetworkInterfaces", []):
                        subnet = ni.get("SubnetId")
                        vpc = ni.get("VpcId")
                        task_id, created = task_by_eni.get(ni["NetworkInterfaceId"], (None, None))
                        if vpc and subnet and task_id:
                            _add(tree, vpc, subnet, "ecs_fargate_task", task_id, task_id, created)
    except (BotoCoreError, ClientError) as e:
        print(f"[warn] ECS Fargate: {e}", file=sys.stderr)


def build_inventory(session: boto3.Session) -> Dict[str, Any]:
    """
    Build and return the inventory tree for the session's region.
    Honors REGION env var (or AWS_REGION/AWS_DEFAULT_REGION) in the session.
    """
    tree: Dict[str, Any] = {}

    collectors = [
        _collect_ec2_instances,
        # _collect_elbv2,  # Uncomment to enable ELBv2 collection
        # _collect_nat_gateways,  # Uncomment to enable NAT Gateway collection
        _collect_rds,
        _collect_docdb,
        _collect_redshift,
        _collect_elasticache,
        _collect_msk,
        _collect_ecs_fargate,
    ]

    for fn in collectors:
        try:
            fn(session, tree)
        except Exception as e:
            print(f"[warn] collector {fn.__name__}: {e}", file=sys.stderr)

    return tree


def resource_inventory(session: boto3.Session) -> Dict[str, Any]:
    """
    Build and return the inventory for the given session.
    """
    return build_inventory(session)
