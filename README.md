# IAM Access Certification Engine

A Python-based, serverless-style prototype for IAM access certification. It discovers IAM users and their attached managed policies, classifies entitlement risk, generates campaign-based access reviews, simulates reviewer decisions, performs gated remediation, and exports audit artifacts (CSV + JSON) locally and optionally to S3.

### Features
- Identity discovery from AWS IAM (or mock data for offline use).
- Deterministic risk scoring on role/policy names.
- Campaign generation with per-entitlement review tasks.
- Safety-gated remediation (double opt-in, allow/deny lists, dry-run by default).
- Audit export with integrity checks, hashes, and optional S3 upload.
- Works with SQLite (local) or Postgres (RDS) via a shared repository layer.

---

### GenAI Risk Explanation Layer (Explainable Access Governance)

This engine includes an optional GenAI augmentation that converts technical IAM entitlements into human-readable risk justifications for access reviewers and auditors.

#### Purpose

Traditional access reviews fail because managers cannot interpret raw IAM policies. This layer solves the “review fatigue” problem by automatically explaining:

* **Why** a specific entitlement is risky for a given user.
* **What** remediation action is recommended.
* **How** the entitlement violates the Principle of Least Privilege.

> **Note:** The AI does not make decisions. It only produces explanations that support compliant human review.

#### How It Works

1. **Evaluation:** During risk evaluation, roles are classified using deterministic rules.
2. **Trigger:** High-risk access reviews trigger the GenAI explanation lambda (`lambdas/ai_explanation/handler.py`).
3. **Context:** The lambda sends structured context to the LLM:
* User identity and role
* IAM policy metadata
* Deterministic risk classification


4. **Generation:** The model returns a concise, plain-English explanation:
* Risk rationale
* Recommended action


5. **Storage:** The explanation is stored in the database as an immutable audit artifact.

#### Governance & Safety Controls

* **Scope:** Explanations are generated *only* for **HIGH-risk** entitlements.
* **Override:** Deterministic logic *always* overrides the AI.
* **Resilience:** Fallback text is used if the model fails.
* **Authority:** The AI **never** approves or revokes access.

#### Auditability

The generated explanation is persisted in the `access_reviews.ai_risk_summary` column.

**Example Artifact:**

> "User bob@example.com has AdministratorAccess but belongs to a non-admin role. This creates excessive privilege risk and should be revoked to enforce least privilege."

This creates a traceable chain:
**Identity → Risk Rules → AI Explanation → Human Review → Remediation → Audit Export**

Auditors can now see **why** access was revoked, not just *that* it was revoked.

### Configuration

Add one environment variable:

```bash
export GOOGLE_API_KEY=your_key_here

```

No other changes are required. If the key is missing, the system runs safely without AI.

### Why This Matters

This transforms the engine from a rules-based access checker into a GenAI-governed identity compliance platform, enabling:

* **Faster access reviews**
* **Lower reviewer error rates**
* **Stronger audit defensibility**
* **Clear separation** of AI assistance and human authority

---
### Prerequisites
- Python 3.10+
- AWS CLI (for real IAM/S3 use)
- SQLite (stdlib) or Postgres (with psycopg2-binary installed)
- Optional: AWS credentials with IAM list permissions and S3 write permissions

---
### Quickstart (local, mock IAM, SQLite)
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DB_URL=sqlite:///iam_governance.db
export MOCK_IAM=true
export LOCAL_ONLY=true   # skip S3
bash scripts/run_demo.sh
```

---
### Running with AWS IAM (SQLite or Postgres)
```bash
export DB_URL=postgres://USER:PASS@HOST:PORT/DBNAME?sslmode=require
export AWS_REGION=us-east-1
# Optionally: AWS_PROFILE=your_profile
# S3 export:
# export AUDIT_S3_BUCKET=your-bucket
# export AUDIT_S3_PREFIX=access-reviews
export LOCAL_ONLY=false
export MOCK_IAM=false
bash scripts/run_demo.sh
```
---
### Safety controls
- `DRY_RUN` (default true): no detachments executed.
- `ENABLE_REMEDIATION` (default false): must be true AND DRY_RUN=false to detach.
- `REMEDIATION_ALLOWLIST` / `REMEDIATION_DENYLIST`: comma-separated substrings; default deny includes AdministratorAccess/break-glass.

---
### Environment variables
- `DB_URL`: sqlite:///path or postgres URL
- `AWS_REGION`, `AWS_PROFILE` (optional)
- `MOCK_IAM`: true to use seeded mock identities (no AWS calls)
- `DRY_RUN`, `ENABLE_REMEDIATION`, `REMEDIATION_ALLOWLIST`, `REMEDIATION_DENYLIST`
- `AUDIT_S3_BUCKET`, `AUDIT_S3_PREFIX`, `LOCAL_ONLY` (skip S3 when true)
- `LOG_LEVEL`
- `GOOGLE_API_KEY`: Optional to enable AI explanation layer

---
### Data flow
1. Identity discovery (`lambdas/identity_discovery/handler.py`)
2. Risk evaluation (`lambdas/risk_evaluation/handler.py`)
3. Campaign generation (`lambdas/generate_reviews/handler.py`)
4. GenAI risk explanation (explainable governance layer)
5. Simulated reviewer decisions (demo script)
6. Remediation (`lambdas/remediation/handler.py`) with safety gates
7. Audit export (`reports/export_audit.py`) to CSV/JSON and optional S3

---
### Schema
- Base schema in `sql/schema_base.sql` with deltas for SQLite (`schema_sqlite.sql`) and Postgres (`schema_postgres.sql`).
- `scripts/migrate.py` applies base + engine delta based on `DB_URL`.

---
### S3 export
- Set `AUDIT_S3_BUCKET` (name only) and optional `AUDIT_S3_PREFIX`.
- Artifacts: CSV + JSON under `access_reviews/<date>/` with SHA-256 hashes in metadata.
- Set `LOCAL_ONLY=true` to skip uploads.

---
### Testing notes
- Pipeline can run fully offline with `MOCK_IAM=true`.
- For Postgres usage, ensure psycopg2-binary is installed and DB_URL reachable.

---
### Caveats
- Discovery currently covers IAM users and attached managed policies only (no groups/inline/SCP).
- Risk scoring is name-heuristic, not policy-document aware.
- Audit_logs table exists; lambdas log to stdout (CloudWatch in Lambda) and can be extended to persist logs if needed.

