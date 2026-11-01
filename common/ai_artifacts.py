"""Durable explanation jobs and the single reviewer-facing AI projection."""

import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timedelta, timezone

from common import config, evidence, repo
from common.db import db

TASK = "REVIEW_EXPLANATION"
PROMPT_VERSION = "review-explanation-v4"
SCHEMA_VERSION = "review-explanation-output-v1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical(value) -> str:
    return evidence.canonical_json(value)


def _redact(value, sensitive: list[str]):
    if isinstance(value, dict):
        return {key: _redact(item, sensitive) for key, item in value.items()
                if key not in {"policy_name", "principal_name", "user_name"}}
    if isinstance(value, list):
        return [_redact(item, sensitive) for item in value]
    if isinstance(value, str):
        for raw in sensitive:
            if raw:
                value = value.replace(raw, "<redacted>")
        value = re.sub(r"arn:[^\s\"',]+", "<arn>", value)
        value = re.sub(r"\b\d{12}\b", "<account>", value)
        value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "<email>", value)
    return value


def build_context(conn, review_id: str, *, pseudonym_key: str | None = None):
    row = repo.fetch_review_ai_context(conn, review_id)
    binding = repo.review_evidence_binding(conn, review_id)
    if not row or not binding or row[1] != "PENDING" or row[6] != "HIGH":
        return None
    subject_ref = (
        hmac.new(pseudonym_key.encode("utf-8"), str(row[2]).encode("utf-8"), hashlib.sha256).hexdigest()[:20]
        if pseudonym_key else "redacted"
    )
    sensitive = sorted(
        {str(value) for value in (row[4], binding["principal_arn"], row[2],
                                  binding["account_id"]) if value},
        key=len, reverse=True,
    )
    context = {
        "task": TASK,
        "subject_ref": subject_ref,
        "snapshot_id": binding["snapshot_id"],
        "observation_id": binding["observation_id"],
        "risk_assessment_id": binding["risk_assessment_id"],
        "grant_type": binding["grant_type"],
        "policy_sha256": row[18],
        "risk_level": row[6],
        "risk_reason": row[8],
        "risk_evidence": _redact(json.loads(row[9]), sensitive) if row[9] else {},
        "risk_rule_version": row[10],
        "policy_evidence_status": row[20],
        "missing_policy_reason": row[21],
        "source_coverage": json.loads(row[22]) if row[22] else None,
        "allowed_evidence_ids": [
            binding["snapshot_id"], binding["observation_id"],
            binding["risk_assessment_id"],
        ],
    }
    return context


def enqueue_review(
    conn, review_id: str, *, pseudonym_key: str | None = None,
    generation: int = 1, retry_of_job_id: str | None = None,
):
    context = build_context(conn, review_id, pseudonym_key=pseudonym_key)
    if not context:
        return None
    if generation < 1:
        raise ValueError("AI job generation must be positive")
    model = config.get_genai_model()
    input_hash = _hash(_canonical(context))
    key = evidence.stable_id(
        TASK, review_id, context["snapshot_id"], context["observation_id"],
        context["risk_assessment_id"], PROMPT_VERSION, SCHEMA_VERSION,
        model, str(generation),
    )
    job_id = str(uuid.uuid4())
    now = _now()
    db.execute(
        conn.cursor(),
        """INSERT INTO ai_jobs
           (job_id,idempotency_key,task_type,review_id,snapshot_id,observation_id,
            risk_assessment_id,prompt_version,schema_version,input_sha256,
            provider_model,generation,retry_of_job_id,status,
            run_after,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'PENDING',?,?,?)
           ON CONFLICT(idempotency_key) DO NOTHING""",
        (job_id, key, TASK, review_id, context["snapshot_id"],
         context["observation_id"], context["risk_assessment_id"],
         PROMPT_VERSION, SCHEMA_VERSION, input_hash, model, generation,
         retry_of_job_id, now, now, now),
    )
    cur = conn.cursor()
    db.execute(
        cur,
        "SELECT job_id,status,generation,provider_model FROM ai_jobs WHERE idempotency_key=?",
        (key,),
    )
    row = cur.fetchone()
    return {"job_id": row[0], "status": row[1], "generation": row[2],
            "provider_model": row[3], "idempotency_key": key}


def retry_failed_job(conn, job_id: str, *, actor_sub: str, pseudonym_key: str):
    cur = conn.cursor()
    suffix = " FOR UPDATE" if not db._is_sqlite_now() else ""
    db.execute(cur, """SELECT review_id,status FROM ai_jobs
        WHERE job_id=?""" + suffix, (job_id,))
    previous = cur.fetchone()
    if not previous:
        return None
    if previous[1] != "FAILED":
        raise ValueError("Only a failed AI job can be retried")
    # Serialize retries from different failed jobs for the same review too.
    db.execute(cur, "SELECT review_id FROM access_reviews WHERE review_id=?" + suffix,
               (previous[0],))
    if not cur.fetchone():
        raise ValueError("The review is no longer available")
    db.execute(cur, """SELECT job_id,status,generation,provider_model,idempotency_key
        FROM ai_jobs WHERE retry_of_job_id=?""", (job_id,))
    existing = cur.fetchone()
    if existing:
        if existing[1] == "FAILED":
            raise ValueError("This job was already retried; retry its failed successor")
        return dict(zip(("job_id", "status", "generation", "provider_model",
                         "idempotency_key"), existing))
    db.execute(cur, "SELECT COALESCE(MAX(generation),0) FROM ai_jobs WHERE review_id=?",
               (previous[0],))
    generation = cur.fetchone()[0] + 1
    job = enqueue_review(
        conn, previous[0], pseudonym_key=pseudonym_key,
        generation=generation, retry_of_job_id=job_id,
    )
    if not job:
        raise ValueError("The review is no longer eligible for AI explanation")
    repo.insert_audit_log(
        conn, str(uuid.uuid4()), datetime.now(timezone.utc), "INFO",
        "ai_job_retry", "queued", "Administrator queued a new AI generation",
        entity_type="access_review", entity_id=previous[0],
        details={"actor_sub": actor_sub, "previous_job_id": job_id,
                 "new_job_id": job["job_id"], "generation": job["generation"]},
    )
    return job


def claim_job(conn, *, job_id: str | None = None, lease_seconds: int = 120):
    now = _now()
    cur = conn.cursor()
    db.execute(
        cur,
        """UPDATE ai_jobs SET status='FAILED',last_error_code='lease_expired',
                  lease_token=NULL,lease_expires_at=NULL,updated_at=?
           WHERE status='RUNNING' AND lease_expires_at<=?
             AND attempt_count>=max_attempts""",
        (now, now),
    )
    condition = (
        "((status='PENDING' AND run_after<=?) OR "
        "(status='RUNNING' AND lease_expires_at<=?)) "
        "AND attempt_count<max_attempts"
    )
    extra = " AND job_id=?" if job_id else ""
    params = (now, now, job_id) if job_id else (now, now)
    db.execute(
        cur,
        f"""SELECT job_id FROM ai_jobs WHERE {condition}{extra}
            ORDER BY run_after,created_at,job_id LIMIT 1""",
        params,
    )
    candidate = cur.fetchone()
    if not candidate:
        return None
    token = str(uuid.uuid4())
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)).isoformat()
    db.execute(
        cur,
        f"""UPDATE ai_jobs SET status='RUNNING',attempt_count=attempt_count+1,
                   lease_token=?,lease_expires_at=?,updated_at=?
            WHERE job_id=? AND {condition}""",
        (token, expiry, now, candidate[0], now, now),
    )
    if cur.rowcount != 1:
        return None
    db.execute(
        cur,
        """SELECT job_id,review_id,snapshot_id,observation_id,risk_assessment_id,
                  input_sha256,attempt_count,max_attempts,lease_token,
                  provider_model,generation
           FROM ai_jobs WHERE job_id=?""",
        (candidate[0],),
    )
    row = cur.fetchone()
    return dict(zip(
        ("job_id", "review_id", "snapshot_id", "observation_id",
         "risk_assessment_id", "input_sha256", "attempt_count",
         "max_attempts", "lease_token", "provider_model", "generation"), row,
    ))


def validate_output(value, allowed_ids: list[str]):
    if not isinstance(value, dict) or set(value) != {"summary", "citations", "limitations"}:
        raise ValueError("AI output schema mismatch")
    summary = value["summary"]
    limitations = value["limitations"]
    citations = value["citations"]
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 500:
        raise ValueError("AI summary invalid")
    if not isinstance(limitations, str) or not limitations.strip() or len(limitations) > 300:
        raise ValueError("AI limitations invalid")
    if not isinstance(citations, list) or not citations or len(citations) > 3:
        raise ValueError("AI citations missing or excessive")
    if any(not isinstance(item, str) or item not in allowed_ids for item in citations):
        raise ValueError("AI citation does not resolve to review evidence")
    if len(set(citations)) != len(citations):
        raise ValueError("Duplicate AI citations")
    if re.search(r"\b(approve|approved|revoke|revoked|detach|execute)\b", summary, re.I):
        raise ValueError("AI summary attempts to direct a decision or action")
    return {
        "summary": " ".join(summary.split()),
        "citations": citations,
        "limitations": " ".join(limitations.split()),
    }


def fallback_output(context: dict):
    return validate_output({
        "summary": "Rule-based assessment flagged this grant path as high risk; inspect the cited assessment.",
        "citations": [context["risk_assessment_id"]],
        "limitations": "Deterministic fallback; model explanation unavailable.",
    }, context["allowed_evidence_ids"])


def _attempt(conn, job: dict, outcome: str, latency_ms: int, error_code: str | None):
    db.execute(
        conn.cursor(),
        """INSERT INTO ai_attempts
           (attempt_id,job_id,attempt_number,outcome,error_code,latency_ms,created_at)
           VALUES (?,?,?,?,?,?,?) ON CONFLICT(job_id,attempt_number) DO NOTHING""",
        (str(uuid.uuid4()), job["job_id"], job["attempt_count"],
         outcome, error_code, latency_ms, _now()),
    )


def complete_job(
    conn, job: dict, output: dict, *, source: str, provider: str | None,
    model: str | None, latency_ms: int, input_tokens: int | None = None,
    output_tokens: int | None = None, error_code: str | None = None,
):
    output = validate_output(
        output, [job["snapshot_id"], job["observation_id"], job["risk_assessment_id"]]
    )
    output_json = _canonical(output)
    status = "SUCCEEDED" if source == "MODEL" else "FALLBACK"
    cur = conn.cursor()
    review_lock = " FOR UPDATE" if not db._is_sqlite_now() else ""
    db.execute(
        cur,
        "SELECT status FROM access_reviews WHERE review_id=?" + review_lock,
        (job["review_id"],),
    )
    review = cur.fetchone()
    if not review or review[0] != "PENDING":
        return False
    db.execute(
        cur,
        """UPDATE ai_jobs SET status=?,lease_token=NULL,lease_expires_at=NULL,
                  updated_at=?,last_error_code=?
           WHERE job_id=? AND status='RUNNING' AND lease_token=?
             AND lease_expires_at>?
             AND EXISTS (SELECT 1 FROM access_reviews r
                         WHERE r.review_id=ai_jobs.review_id AND r.status='PENDING')""",
        (status, _now(), error_code, job["job_id"], job["lease_token"], _now()),
    )
    if cur.rowcount != 1:
        return False
    db.execute(
        cur,
        """INSERT INTO ai_artifacts
           (artifact_id,job_id,task_type,review_id,snapshot_id,observation_id,
            risk_assessment_id,source,validation_status,provider,model,
            prompt_version,schema_version,input_sha256,output_sha256,output_json,
            evidence_refs,latency_ms,input_tokens,output_tokens,cost_usd,created_at)
           SELECT ?,job_id,task_type,review_id,snapshot_id,observation_id,
                  risk_assessment_id,?,'VALIDATED',?,?,prompt_version,
                  schema_version,input_sha256,?,?,?,?,?,?,NULL,?
           FROM ai_jobs WHERE job_id=?""",
        (str(uuid.uuid4()), source, provider, model, _hash(output_json),
         output_json, _canonical(output["citations"]), latency_ms,
         input_tokens, output_tokens, _now(), job["job_id"]),
    )
    _attempt(
        conn, job, "MODEL_SUCCESS" if source == "MODEL" else "FALLBACK",
        latency_ms, error_code,
    )
    return True


def fail_or_retry(conn, job: dict, *, error_code: str, latency_ms: int):
    retry = job["attempt_count"] < job["max_attempts"]
    status = "PENDING" if retry else "FAILED"
    delay = min(300, 2 ** job["attempt_count"])
    next_run = (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat()
    cur = conn.cursor()
    db.execute(
        cur,
        """UPDATE ai_jobs SET status=?,run_after=?,lease_token=NULL,
                  lease_expires_at=NULL,last_error_code=?,updated_at=?
           WHERE job_id=? AND status='RUNNING' AND lease_token=?
             AND lease_expires_at>?""",
        (status, next_run, error_code, _now(), job["job_id"], job["lease_token"], _now()),
    )
    if cur.rowcount != 1:
        return "STALE"
    _attempt(conn, job, "RETRY" if retry else "FAILED", latency_ms, error_code)
    return status


def _resolved_citations(binding: dict, ids: list[str]):
    kinds = {
        binding["snapshot_id"]: "published_snapshot",
        binding["observation_id"]: "grant_observation",
        binding["risk_assessment_id"]: "grant_risk_assessment",
    }
    if any(item not in kinds for item in ids):
        raise ValueError("AI artifact cites evidence outside its review")
    return [{"id": item, "kind": kinds[item]} for item in ids]


def projection(conn, review_id: str):
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT artifact_id,source,provider,model,prompt_version,schema_version,
                  input_sha256,output_sha256,output_json,evidence_refs,created_at,
                  snapshot_id,observation_id,risk_assessment_id
           FROM ai_artifacts WHERE review_id=? AND validation_status='VALIDATED'
           ORDER BY created_at DESC,artifact_id DESC LIMIT 20""",
        (review_id,),
    )
    artifacts = cur.fetchall()
    if not artifacts:
        return repo.fetch_legacy_ai_explanation(conn, review_id)
    binding = repo.review_evidence_binding(conn, review_id)
    for row in artifacts:
        try:
            artifact_id, source, provider, model, prompt, schema, input_hash, output_hash, output_json, refs, created, snapshot, observation, assessment = row
            if not binding or (snapshot, observation, assessment) != (
                binding["snapshot_id"], binding["observation_id"], binding["risk_assessment_id"]
            ) or _hash(output_json) != output_hash:
                continue
            value = validate_output(json.loads(output_json), [snapshot, observation, assessment])
            if value["citations"] != json.loads(refs):
                continue
            return {
                "status": "available", "authority": "validated_artifact",
                "validated_artifact": True, "artifact_id": artifact_id,
                "summary": value["summary"], "limitations": value["limitations"],
                "citations": _resolved_citations(binding, value["citations"]),
                "source": source, "provider": provider, "model": model,
                "prompt_version": prompt, "schema_version": schema,
                "input_sha256": input_hash, "output_sha256": output_hash,
                "generated_at": str(created),
            }
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            continue
    return {
        "status": "invalid_artifact", "authority": "validated_artifact",
        "validated_artifact": False, "summary": None,
    }


def job_status(conn, job_id: str):
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT job_id,review_id,task_type,status,attempt_count,max_attempts,
                  last_error_code,created_at,updated_at,provider_model,
                  generation,retry_of_job_id
           FROM ai_jobs WHERE job_id=?""",
        (job_id,),
    )
    row = cur.fetchone()
    if not row:
        return None
    return dict(zip(
        ("job_id", "review_id", "task_type", "status", "attempt_count",
         "max_attempts", "last_error_code", "created_at", "updated_at",
         "provider_model", "generation", "retry_of_job_id"),
        [str(value) if isinstance(value, datetime) else value for value in row],
    ))


def metrics(conn):
    cur = conn.cursor()
    db.execute(cur, "SELECT status,COUNT(*) FROM ai_jobs GROUP BY status")
    jobs = dict(cur.fetchall())
    db.execute(cur, "SELECT source,COUNT(*),AVG(latency_ms) FROM ai_artifacts GROUP BY source")
    artifacts = [
        {"source": source, "count": count, "average_latency_ms": float(avg)}
        for source, count, avg in cur.fetchall()
    ]
    db.execute(cur, "SELECT outcome,COUNT(*) FROM ai_attempts GROUP BY outcome")
    attempts = dict(cur.fetchall())
    return {"jobs": jobs, "artifacts": artifacts, "attempts": attempts}
