#!/usr/bin/env bash
set -euo pipefail

# ==================================================
# Cloud IAM Access Certification Engine - Demo Script
# Simulates a full quarterly identity governance cycle
# ==================================================

DB_URL=${DB_URL:-"sqlite:///iam_governance.db"}
MOCK_IAM=${MOCK_IAM:-false}
AWS_REGION_VAL=${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}

# Ensure Python can import local packages
export PYTHONPATH="${PYTHONPATH:-$PWD}"

echo "=================================================="
echo "STARTING CLOUD IDENTITY GOVERNANCE ENGINE DEMO"
echo "=================================================="

# Portable lowercase (no ${VAR,,} bash4-only)
mock_lower=$(printf '%s' "$MOCK_IAM" | tr '[:upper:]' '[:lower:]')

# Fail fast on missing AWS credentials unless running in mock mode
if [ "$mock_lower" != "true" ]; then
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
# 2. Initialize Database Schema
# --------------------------------------------------
printf '\n[1/7] Initializing Database Schema...\n'
DB_URL="$DB_URL" python3 scripts/migrate.py
echo "      Schema initialized."

# --------------------------------------------------
# 3. Identity Discovery
# --------------------------------------------------
printf '\n[2/7] Running Identity Discovery (AWS IAM)...\n'
export AWS_DEFAULT_REGION="$AWS_REGION_VAL"
export AWS_REGION="$AWS_REGION_VAL"
export DB_URL
export MOCK_IAM
python3 lambdas/identity_discovery/handler.py

# --------------------------------------------------
# 4. Risk Evaluation
# --------------------------------------------------
printf '\n[3/7] Evaluating Entitlement Risk...\n'
python3 lambdas/risk_evaluation/handler.py

# --------------------------------------------------
# 5. Certification Campaign Generation
# --------------------------------------------------
printf '\n[4/7] Generating Access Certification Campaign...\n'
python3 lambdas/generate_reviews/handler.py

# --------------------------------------------------
# 6. AI Risk Explanation (High Risk Only, optional)
# --------------------------------------------------
SKIP_AI=${SKIP_AI:-false}
skip_ai_lower=$(printf '%s' "$SKIP_AI" | tr '[:upper:]' '[:lower:]')
if [ "$skip_ai_lower" = "true" ]; then
  printf '\n[5/7] Skipping AI risk explanations (--skip-ai / SKIP_AI=true)...\n'
elif [ "${ENABLE_GENAI:-false}" = "true" ] && [ -n "${GOOGLE_API_KEY:-}" ]; then
  printf '\n[5/7] Generating AI risk explanations (HIGH only, LIVE)...\n'
  python3 lambdas/ai_explanation/handler.py
else
  printf '\n[5/7] Skipping AI risk explanations (set ENABLE_GENAI=true and GOOGLE_API_KEY to enable)...\n'
fi
# Visibility: LIVE vs FALLBACK vs MISSING among HIGH reviews (works with or without key)
DB_URL="$DB_URL" python3 - <<'PY' || true
from common.db import db
with db.get_connection() as conn:
    cur = conn.cursor()
    db.execute(cur, "SELECT g.source FROM access_reviews r "
                    "JOIN roles rol ON r.role_id=rol.role_id "
                    "LEFT JOIN grant_risk_assessments gra ON gra.assessment_id=r.risk_assessment_id "
                    "LEFT JOIN ai_generations g ON g.review_id=r.review_id "
                    "WHERE (CASE WHEN r.grant_id IS NULL THEN rol.risk_level "
                    "ELSE gra.risk_level END)='HIGH' AND r.status='PENDING'")
    rows = [r[0] for r in cur.fetchall()]
live = sum(1 for t in rows if t == "MODEL")
fallback = sum(1 for t in rows if t == "FALLBACK")
missing = sum(1 for t in rows if not t)
print(f"      AI summary: LIVE={live} FALLBACK={fallback} MISSING={missing} (HIGH total={len(rows)})")
PY

# --------------------------------------------------
# INTERMISSION: Reviewer decisions via CLI (replaces hidden SQL)
# --------------------------------------------------
printf '\nSimulating human access review via review.py...\n'
if [ "$mock_lower" = "true" ]; then
  DB_URL="$DB_URL" python3 scripts/review.py auto-demo
  echo " Demo review decisions recorded."
else
  echo " Live IAM data detected; leaving all reviews pending for an authenticated reviewer service."
fi
echo " Try listing reviews: python3 scripts/review.py list --status PENDING"

# --------------------------------------------------
# 7. Remediation (Dry Run)
# --------------------------------------------------
printf '\n[6/7] Executing Remediation Engine (DRY RUN)...\n'
export DRY_RUN=True
python3 lambdas/remediation/handler.py

# --------------------------------------------------
# 8. Audit Report Export
# --------------------------------------------------
printf '\n[7/7] Exporting Audit Report...\n'
python3 reports/export_audit.py

# --------------------------------------------------
# Summary footer (counts + artifact hashes)
# --------------------------------------------------
printf '\n----- DEMO SUMMARY -----\n'
DB_URL="$DB_URL" python3 - <<'PY' || true
from common.db import db
with db.get_connection() as conn:
    cur = conn.cursor()
    db.execute(cur, "SELECT r.status, "
                    "CASE WHEN r.grant_id IS NULL THEN rol.risk_level ELSE gra.risk_level END, "
                    "COUNT(*) FROM access_reviews r "
                    "JOIN roles rol ON r.role_id=rol.role_id "
                    "LEFT JOIN grant_risk_assessments gra ON gra.assessment_id=r.risk_assessment_id "
                    "GROUP BY r.status, CASE WHEN r.grant_id IS NULL THEN rol.risk_level "
                    "ELSE gra.risk_level END ORDER BY 1, 2")
    for status, risk, n in cur.fetchall():
        print(f"      {status:8s} {risk:6s} {n}")
    db.execute(cur, "SELECT COUNT(*) FROM audit_logs")
    print(f"      audit_logs rows: {cur.fetchone()[0]}")
PY
printf '      Artifacts: reports/access_certification_<date>_<run-id>.csv/.json/.manifest.json\n'
sha256sum reports/access_certification_*.csv 2>/dev/null | tail -2 || true

# --------------------------------------------------
# Done
# --------------------------------------------------
printf '\n==================================================\n'
echo "DEMO COMPLETE — GOVERNANCE CYCLE FINISHED"
echo "=================================================="
