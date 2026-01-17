#!/bin/bash

# ==================================================
# Cloud IAM Access Certification Engine - Demo Script
# Simulates a full quarterly identity governance cycle
# ==================================================

DB_FILE="iam_governance.db"
DB_URL=${DB_URL:-"sqlite:///$DB_FILE"}
MOCK_IAM=${MOCK_IAM:-false}

# Ensure Python can import local packages
export PYTHONPATH="${PYTHONPATH:-$PWD}"

echo "=================================================="
echo "STARTING CLOUD IDENTITY GOVERNANCE ENGINE DEMO"
echo "=================================================="

# Fail fast on missing AWS credentials unless running in mock mode
if [ "${MOCK_IAM,,}" != "true" ]; then
    if ! command -v aws >/dev/null 2>&1; then
        echo "aws CLI not found. Install AWS CLI or set MOCK_IAM=true."
        exit 1
    fi
    if ! aws sts get-caller-identity --no-cli-pager >/dev/null 2>&1; then
        echo "AWS credentials not resolved by CLI. Set AWS_PROFILE or env creds."
        exit 1
    fi
else
    echo "MOCK_IAM=true — using seeded mock IAM data (no AWS calls)."
fi

# --------------------------------------------------
# 1. Clean Slate
# --------------------------------------------------
if [ -f "$DB_FILE" ]; then
    echo "🧹 Cleaning up existing database..."
    rm "$DB_FILE"
fi

# --------------------------------------------------
# 2. Initialize Database Schema
# --------------------------------------------------
echo -e "\n[1/6] Initializing Database Schema..."
DB_URL="$DB_URL" python3 scripts/migrate.py
echo "      ✅ Schema initialized."

# --------------------------------------------------
# 3. Identity Discovery
# --------------------------------------------------
echo -e "\n[2/6] Running Identity Discovery (AWS IAM)..."
export AWS_DEFAULT_REGION=us-east-1
export DB_URL
export MOCK_IAM
python3 lambdas/identity_discovery/handler.py

# --------------------------------------------------
# 4. Risk Evaluation
# --------------------------------------------------
echo -e "\n[3/6] Evaluating Entitlement Risk..."
python3 lambdas/risk_evaluation/handler.py

# --------------------------------------------------
# 5. Certification Campaign Generation
# --------------------------------------------------
echo -e "\n[4/7] Generating Access Certification Campaign..."
python3 lambdas/generate_reviews/handler.py

# --------------------------------------------------
# 6. AI Risk Explanation (High Risk Only)
# --------------------------------------------------
echo -e "\n[5/7] Generating AI risk explanations (HIGH only)..."
python3 lambdas/ai_explanation/handler.py

# --------------------------------------------------
# INTERMISSION: Simulate Human Review
# --------------------------------------------------
echo -e "\nSimulating human access review..."
echo "      Rejecting Administrator-level access..."

if [[ "$DB_URL" == sqlite* ]]; then
sqlite3 "$DB_FILE" <<EOF
UPDATE access_reviews
SET status = 'REVOKED',
    reviewer_comment = 'Violation of Least Privilege',
    reviewed_at = CURRENT_TIMESTAMP
WHERE role_id IN (
    SELECT role_id FROM roles
    WHERE role_name LIKE '%AdministratorAccess%'
);
EOF
else
python3 - <<'PY'
from common.db import db
from common import logger

with db.get_connection() as conn:
    cur = conn.cursor()
    db.execute(
        cur,
        """
        UPDATE access_reviews
        SET status = 'REVOKED',
            reviewer_comment = 'Violation of Least Privilege',
            reviewed_at = CURRENT_TIMESTAMP
        WHERE role_id IN (
            SELECT role_id FROM roles
            WHERE role_name LIKE '%AdministratorAccess%'
        )
        """
    )
logger.log("demo_intermission", "info", "Marked AdministratorAccess reviews as REVOKED")
PY
fi

echo "      ✅ Review decisions recorded."

# --------------------------------------------------
# 7. Remediation (Dry Run)
# --------------------------------------------------
echo -e "\n[6/7] Executing Remediation Engine (DRY RUN)..."
export DRY_RUN=True
python3 lambdas/remediation/handler.py

# --------------------------------------------------
# 8. Audit Report Export
# --------------------------------------------------
echo -e "\n[7/7] Exporting Audit Report..."
python3 reports/export_audit.py

# --------------------------------------------------
# Done
# --------------------------------------------------
echo -e "\n=================================================="
echo "DEMO COMPLETE — GOVERNANCE CYCLE FINISHED"
echo "=================================================="
