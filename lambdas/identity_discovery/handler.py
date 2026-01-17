#lambdas/identity_discovery/handler.py
import boto3
from datetime import datetime
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import config, logger
from common.db import db
from common import repo

MOCK_IAM = config.MOCK_IAM

def _mock_identities():
    """Static seed data for offline demos."""
    return [
        {
            "UserId": "MOCK-USER-1",
            "UserName": "alice@example.com",
            "Arn": "arn:aws:iam::123456789012:user/alice",
            "CreateDate": datetime.utcnow(),
            "Policies": [
                {"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "PolicyName": "ReadOnlyAccess"},
                {"PolicyArn": "arn:aws:iam::aws:policy/PowerUserAccess", "PolicyName": "PowerUserAccess"}
            ]
        },
        {
            "UserId": "MOCK-USER-2",
            "UserName": "bob@example.com",
            "Arn": "arn:aws:iam::123456789012:user/bob",
            "CreateDate": datetime.utcnow(),
            "Policies": [
                {"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "PolicyName": "AdministratorAccess"}
            ]
        }
    ]

def _iter_identities():
    if MOCK_IAM:
        for entry in _mock_identities():
            yield entry
    else:
        iam_client = boto3.client('iam')
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                policies = iam_client.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
                yield {**user, "Policies": policies}

def discover_identities(event, context):
    logger.log("discover_identities", "start", "Starting Identity Discovery")
    user_count = 0

    with db.get_connection() as conn:
        for user in _iter_identities():
            try:
                u_id = user['UserId']
                u_name = user['UserName']
                u_arn = user['Arn']
                created_at = user['CreateDate'].isoformat()

                repo.insert_user(conn, u_id, u_name, u_arn, created_at)

                for poly in user.get("Policies", []):
                    p_arn = poly['PolicyArn']
                    p_name = poly['PolicyName']

                    repo.insert_role(conn, p_arn, p_name, "LOW")
                    repo.link_user_role(conn, u_id, p_arn)

                user_count += 1

            except Exception as e:
                logger.log(
                    "discover_identities",
                    "error",
                    f"Error processing user {user.get('UserName','UNKNOWN')}: {e}",
                    level="ERROR",
                    details={"user": user},
                )
                continue
        conn.commit()

    mode = "MOCK" if MOCK_IAM else "AWS"
    logger.log(
        "discover_identities",
        "success",
        f"Discovery Complete ({mode})",
        details={"users_processed": user_count},
    )
    return {"status": "success", "users_processed": user_count}


# --- LOCAL TESTING ---
if __name__ == "__main__":
    discover_identities(None, None)