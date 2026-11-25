# IAM Access Certification Engine

An evidence-first IAM governance prototype: collect account/source-scoped grant paths, triage frozen policy documents, run human review campaigns, verify audit exports, and gate direct-path remediation. A role-scoped frontend serves reviewers, campaign admins, independent remediation approvers, auditors, and operators. It runs with SQLite or PostgreSQL, a seeded offline dataset, Floci, or live AWS discovery. **It does not calculate a principal's complete effective AWS access and is not production-ready.**

## What exists

- Separate IAM user/direct/group, role policy/trust, and Identity Center assignment scans. A complete scan publishes immutable observations for its declared scope; failed or superseded attempts retain old evidence but block new campaign/live-remediation eligibility. Missing referenced documents and unassessed surfaces are explicit.
- Versioned, append-only policy and grant-path assessments. Severity, rule confidence, evidence completeness, and legacy HIGH routing remain distinct. Campaign reviews pin a published snapshot, observation, attachment, and assessment; old rows disclose missing provenance. Same-account/scope snapshot comparison reports observed changes, not cross-source effective access.
- OIDC API and five frontend workspaces with server-side role/account/assignment checks, decision and workflow events, independent approval, historical audit reconstruction, and scoped CSV/JSON/evidence/manifest exports with SHA-256 verification. The seeded CLI is a demo tool, not authentication.
- Default-off advisory explanation jobs and a default-off deterministic, stateless review Q&A endpoint. Explanation provider input is minimized and requires current versioned approval; accepted artifacts record provenance. Neither AI path decides or remediates. The candidate evaluation corpus is unreviewed and no real-provider quality result is claimed.
- Dry-run remediation by default. Controlled staging live actions support only direct managed IAM **user** policy detachment and direct inline user policy deletion, after independent approval and exact-path pre/postflight. Group, role, trust, and Identity Center paths have no live action; production mutation is code-blocked.

Read [roadmap and release status](docs/roadmap.md), [evidence/risk contract](docs/evidence-and-risk.md), [AI governance](docs/ai-governance.md), [API permission contract](docs/frontend-api-contract.md), [Floci testing](docs/floci.md), [product validation](docs/product-validation.md), and [deployment acceptance](docs/production-readiness.md). These are the maintained docs; generated OpenAPI is in `frontend/openapi.json`.

## Local seeded quickstart

If no Python environment exists, create one; otherwise use the existing environment. Install `requirements.txt` and choose a **fresh** SQLite `DB_URL` when you want a clean demo. In PowerShell:

```powershell
# Run only if .venv does not already exist:
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:DB_URL = 'sqlite:///iam_governance.db'
$env:MOCK_IAM = 'false'; $env:SEEDED_IAM = 'true'; $env:LOCAL_ONLY = 'true'
python scripts/migrate.py
python lambdas/identity_discovery/handler.py
python lambdas/role_discovery/handler.py
python lambdas/risk_evaluation/handler.py
python lambdas/generate_reviews/handler.py
python scripts/review.py list --status PENDING
```

`scripts/run_demo.sh` also runs a simulated reviewer cycle and preserves the configured database. The CLI can decide only seeded `MOCK` snapshot reviews; `auto-demo` decisions cannot authorize remediation. Use the OIDC API for authenticated review decisions. `python scripts/review.py --help` lists CLI operations.

## IAM modes and local stack

| Mode | `MOCK_IAM` | `SEEDED_IAM` | Source |
| --- | --- | --- | --- |
| Floci SDK integration | `false` | `false` | `FLOCI` |
| Real AWS credentials/endpoints | `true` | `false` | `AWS` |
| Deterministic offline dataset | `false` | `true` | `MOCK` |

Set `AWS_ACCOUNT_ID` for real IAM user/role scans before the first call; STS then verifies the intended account. In Floci mode it must match `FLOCI_ACCOUNT_ID` (default `111111111111`). The live client rejects AWS endpoint overrides. Floci evidence cannot be reused for live AWS remediation. See [Floci smoke, benchmark, fault, and crash tests](docs/floci.md).

For a local OIDC-backed integration stack, copy `.env.example` to `.env`, set a strong `POSTGRES_PASSWORD`, OIDC/API/frontend secrets and role groups, then run `docker compose up --build`. Migrations precede the API; Compose uses PostgreSQL and Floci with `MOCK_IAM=false`, GenAI off, and remediation dry-run. Frontend is bound to `127.0.0.1:3000` and Floci to `127.0.0.1:4566`. See [frontend setup](frontend/README.md). Compose does not provision a real identity provider, managed AWS resources, public TLS/WAF, worker fleet, backups, or monitoring.

## Configuration and verification

Use `.env.example` as the configuration inventory. Key groups are `DB_URL`; AWS/Floci account, region and credentials; `MOCK_IAM`/`SEEDED_IAM`; OIDC issuer/audience/JWKS/account-scope claim and role groups; frontend Auth.js settings; audit S3/local flags; and remediation environment, dry-run, allow/denylist and approval gates. `ENABLE_GENAI` and `ENABLE_REVIEW_QA` default off. Explanation traffic additionally needs provider key, pseudonym secret, `AI_PROVIDER_DATA_APPROVED`, region, and exact `AI_PROVIDER_APPROVAL_JSON`; do not enable it without the [AI data, quality, and operational gates](docs/ai-governance.md). Keep secrets outside Git.

Run `python scripts/migrate.py` before workers/API. Ordered SQL migrations are checksum-verified and applied transactionally; change schema with a **new** numbered migration, never an edited applied file. Export artifacts use unique run paths under `reports/`; `LOCAL_ONLY=true` skips S3. The CI workflow defines SQLite/PostgreSQL, Floci, frontend unit/browser/build, and image checks, but its existence is not a hosted result at this revision. Mocked browser journeys do not prove real OIDC/API/AWS behavior. Live AWS, Identity Center, provider, S3, and production deployment require separate controlled acceptance.
