"""
encryption_audit.py

Checks encryption status for AWS services: EBS, RDS, Aurora, and returns a dict:
{
    "service": {
        "resource_id": { ...details... }
    }
}
"""
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, Optional

def audit_encryption(session: Optional[boto3.Session] = None) -> Dict[str, Dict[str, Any]]:
    import concurrent.futures
    session = session or boto3.Session()
    result: Dict[str, Dict[str, Any]] = {}

    def ebs_worker():
        try:
            ec2 = session.client("ec2")
            volumes = ec2.describe_volumes()["Volumes"]
            ebs = {}
            for v in volumes:
                if not v.get("Encrypted", False):
                    ebs[v["VolumeId"]] = {"kms_key_id": v.get("KmsKeyId")}
            return ("EBS", ebs) if ebs else None
        except (ClientError, BotoCoreError) as e:
            return ("EBS_error", {"error": str(e)})

    def rds_worker():
        try:
            rds = session.client("rds")
            dbs = rds.describe_db_instances()["DBInstances"]
            rds_dict = {}
            for db in dbs:
                if not db.get("StorageEncrypted", False):
                    rds_dict[db["DBInstanceIdentifier"]] = {
                        "kms_key_id": db.get("KmsKeyId"),
                        "engine": db.get("Engine"),
                        "multi_az": db.get("MultiAZ"),
                        "instance_class": db.get("DBInstanceClass"),
                    }
            return ("RDS", rds_dict) if rds_dict else None
        except (ClientError, BotoCoreError) as e:
            return ("RDS_error", {"error": str(e)})

    def aurora_worker():
        try:
            rds = session.client("rds")
            clusters = rds.describe_db_clusters()["DBClusters"]
            aurora = {}
            for cl in clusters:
                if not cl.get("StorageEncrypted", False):
                    aurora[cl["DBClusterIdentifier"]] = {
                        "kms_key_id": cl.get("KmsKeyId"),
                        "engine": cl.get("Engine"),
                        "database_name": cl.get("DatabaseName"),
                    }
            return ("Aurora", aurora) if aurora else None
        except (ClientError, BotoCoreError) as e:
            return ("Aurora_error", {"error": str(e)})

    def s3_worker():
        try:
            s3 = session.client("s3")
            buckets = s3.list_buckets()["Buckets"]
            s3_dict = {}
            for b in buckets:
                name = b["Name"]
                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                except ClientError as e:
                    code = e.response["Error"]["Code"]
                    if code == "ServerSideEncryptionConfigurationNotFoundError":
                        s3_dict[name] = {"encrypted": False}
                    else:
                        s3_dict[name] = {"error": str(e)}
            return ("S3", s3_dict) if s3_dict else None
        except (ClientError, BotoCoreError) as e:
            return ("S3_error", {"error": str(e)})

    def sqs_worker():
        try:
            sqs = session.client("sqs")
            queues = sqs.list_queues().get("QueueUrls", [])
            sqs_dict = {}
            for url in queues:
                resp = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["KmsMasterKeyId"])
                attrs = resp.get("Attributes", {})
                if attrs and not attrs.get("KmsMasterKeyId"):
                    sqs_dict[url] = {"encrypted": False}
            return ("SQS", sqs_dict) if sqs_dict else None
        except (ClientError, BotoCoreError) as e:
            return ("SQS_error", {"error": str(e)})

    def sns_worker():
        try:
            sns = session.client("sns")
            topics = sns.list_topics()["Topics"]
            sns_dict = {}
            for t in topics:
                arn = t["TopicArn"]
                attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
                key_id = attrs.get("KmsMasterKeyId")
                if not key_id:
                    sns_dict[arn] = {"encrypted": False}
            return ("SNS", sns_dict) if sns_dict else None
        except (ClientError, BotoCoreError) as e:
            return ("SNS_error", {"error": str(e)})

    def ecr_worker():
        try:
            ecr = session.client("ecr")
            repos = ecr.describe_repositories()["repositories"]
            ecr_dict = {}
            for r in repos:
                arn = r["repositoryArn"]
                enc_cfg = r.get("encryptionConfiguration", {})
                enc_type = enc_cfg.get("encryptionType")
                if not enc_type or enc_type == "NONE":
                    ecr_dict[arn] = {"encrypted": False}
            return ("ECR", ecr_dict) if ecr_dict else None
        except (ClientError, BotoCoreError) as e:
            return ("ECR_error", {"error": str(e)})

    workers = [ebs_worker, rds_worker, aurora_worker, s3_worker, sqs_worker, sns_worker, ecr_worker]
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(fn) for fn in workers]
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                result[res[0]] = res[1]

    # Add more services as needed
    return result
