"""Minimal OIDC-protected API for campaign reviewer assignment and decisions.

Run behind a TLS-terminating gateway with restricted network access:
    uvicorn api.review_service:app --host 127.0.0.1 --port 8080
"""

import json
import hashlib
import os
import re
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from common import ai_artifacts, auth, config, repo, workflow, workspaces
from common.db import db

app = FastAPI(
    title="IAM Access Review API", docs_url=None, redoc_url=None,
    openapi_url="/openapi.json",
)
bearer = HTTPBearer(auto_error=False)


class DecisionRequest(BaseModel):
    decision: Literal["APPROVED", "REVOKED"]
    comment: str = Field(default="", max_length=4000)


class ReviewerAssignmentRequest(BaseModel):
    reviewer_sub: str = Field(min_length=1, max_length=256)


class CampaignStateRequest(BaseModel):
    state: Literal["OPEN", "PAUSED", "CLOSED"]


class CampaignOwnerRequest(BaseModel):
    owner_sub: str = Field(min_length=1, max_length=256)


class DeadlineRequest(BaseModel):
    due_at: datetime


class ExceptionRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=4000)


class CampaignCreateRequest(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    snapshot_id: str = Field(min_length=1, max_length=128)
    due_at: datetime | None = None


class RemediationApprovalRequest(BaseModel):
    decision: Literal["APPROVED", "DECLINED"]
    reason: str = Field(min_length=1, max_length=4000)


class ExportRequest(BaseModel):
    campaign_id: str | None = Field(default=None, max_length=128)
    account_id: str | None = Field(default=None, min_length=12, max_length=12)


@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    request.state.request_id = uuid.uuid4().hex
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response


def _http_error_code(status_code: int, detail) -> str:
    explicit = detail.get("code") if isinstance(detail, dict) else None
    if explicit and re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", str(explicit)):
        return str(explicit)
    stable = {
        401: "AUTHENTICATION_REQUIRED",
        403: "PERMISSION_DENIED",
        404: "RESOURCE_NOT_FOUND",
        409: "STATE_CONFLICT",
        422: "INVALID_REQUEST",
    }
    if isinstance(detail, str):
        if "already decided" in detail.lower():
            return "REVIEW_ALREADY_DECIDED"
        if "snapshot" in detail.lower():
            return "SNAPSHOT_NOT_ELIGIBLE"
        if "decision raced" in detail.lower():
            return "REVIEW_DECISION_CONFLICT"
    return stable.get(status_code, "REQUEST_FAILED")


@app.exception_handler(HTTPException)
async def http_error_response(request: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else {}
    message = detail.get("message") if detail else exc.detail
    if not isinstance(message, str):
        message = "Request failed"
    return JSONResponse(
        status_code=exc.status_code,
        headers=exc.headers,
        content={"error": {
            "code": _http_error_code(exc.status_code, exc.detail),
            "message": message,
            "request_id": getattr(request.state, "request_id", None),
            **({"details": detail["details"]} if "details" in detail else {}),
        }},
    )


@app.exception_handler(RequestValidationError)
async def validation_error_response(request: Request, exc: RequestValidationError):
    errors = [
        {"field": ".".join(str(part) for part in error.get("loc", ())),
         "reason": error.get("type", "invalid")}
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={"error": {
            "code": "INVALID_REQUEST",
            "message": "Request validation failed",
            "request_id": getattr(request.state, "request_id", None),
            "details": errors,
        }},
    )


def current_reviewer(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = auth.verify_access_token(credentials.credentials)
    except auth.AuthenticationError:
        raise HTTPException(
            status_code=401,
            detail="Invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return claims


def require_account_scope(claims: dict, account_id: str | None):
    try:
        auth.require_account_scope(claims, account_id)
    except auth.AuthorizationError:
        raise HTTPException(status_code=403, detail="AWS account is outside the user's authorized scope")


def require_reviewer_group(claims: dict):
    try:
        auth.require_group(claims, os.getenv("REVIEWER_GROUP", ""))
    except auth.AuthorizationError:
        raise HTTPException(
            status_code=403, detail="Reviewer group membership required"
        )


def require_campaign_assignment(conn, campaign_id: str, reviewer_sub: str):
    if not repo.is_campaign_reviewer(conn, campaign_id, reviewer_sub):
        raise HTTPException(
            status_code=403, detail="Reviewer is not assigned to this campaign"
        )


def require_campaign_admin(claims: dict):
    try:
        auth.require_group(claims, os.getenv("CAMPAIGN_ADMIN_GROUP", ""))
    except auth.AuthorizationError:
        raise HTTPException(
            status_code=403, detail="Campaign administrator group membership required"
        )


def require_campaign_scope(conn, claims: dict, campaign_id: str, *, lock: bool = False):
    campaign = workflow.campaign(conn, campaign_id, lock=lock)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    require_account_scope(claims, campaign["account_id"])
    return campaign


def require_review_scope(conn, claims: dict, review_id: str):
    item = workflow.review_workflow(conn, review_id)
    if not item:
        raise HTTPException(status_code=404, detail="Review not found")
    require_account_scope(claims, item["account_id"])
    return item


def require_remediation_operator(claims: dict):
    try:
        auth.require_group(claims, os.getenv("REMEDIATION_OPERATOR_GROUP", ""))
    except auth.AuthorizationError:
        raise HTTPException(
            status_code=403, detail="Remediation operator group membership required"
        )


def require_remediation_approver(claims: dict):
    try:
        auth.require_group(claims, os.getenv("REMEDIATION_APPROVER_GROUP", ""))
    except auth.AuthorizationError:
        raise HTTPException(status_code=403, detail="Remediation approver group membership required")


def require_auditor_or_campaign_admin(claims: dict):
    if auth.has_group(claims, os.getenv("AUDITOR_GROUP", "")):
        return "auditor"
    if auth.has_group(claims, os.getenv("CAMPAIGN_ADMIN_GROUP", "")):
        return "campaign_admin"
    raise HTTPException(status_code=403, detail="Auditor or campaign administrator role required")


def require_review_assignment(
    conn, review_id: str, campaign_id: str, reviewer_sub: str,
    claims: dict | None = None,
):
    require_campaign_assignment(conn, campaign_id, reviewer_sub)
    item = workflow.review_workflow(conn, review_id)
    if item and item["assigned_reviewer_sub"] not in (None, reviewer_sub):
        raise HTTPException(status_code=403, detail="Review is assigned to another reviewer")
    if item and claims is not None:
        require_account_scope(claims, item["account_id"])
    return item


def _future_deadline(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise HTTPException(status_code=422, detail="Deadline must include a timezone")
    if value <= datetime.now(timezone.utc):
        raise HTTPException(status_code=422, detail="Deadline must be in the future")
    return value.astimezone(timezone.utc).isoformat()


def _nonblank(value: str, field: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise HTTPException(status_code=422, detail=f"{field} cannot be blank")
    return cleaned


def _workflow_result(result: str):
    if result == "not_found":
        raise HTTPException(status_code=404, detail="Resource not found")
    if result == "not_in_pool":
        raise HTTPException(status_code=422, detail="Reviewer is not in the campaign pool")
    if result in {"not_open", "invalid_transition", "incomplete", "conflict"}:
        raise HTTPException(status_code=409, detail=result)
    return result


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/me")
def get_me(claims: dict = Depends(current_reviewer)):
    return auth.identity_summary(claims)


@app.get("/reviews/summary")
def reviewer_summary(claims: dict = Depends(current_reviewer)):
    require_reviewer_group(claims)
    account_scopes = auth.identity_summary(claims)["account_scopes"]
    with db.get_connection() as conn:
        return workflow.queue_summary(conn, claims["sub"], account_scopes=account_scopes)


@app.get("/reviews/queue")
def reviewer_queue(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status: Literal["ALL", "PENDING", "APPROVED", "REVOKED"] = "PENDING",
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "UNKNOWN"] | None = None,
    campaign_id: str | None = Query(default=None, max_length=128),
    account_id: str | None = Query(default=None, min_length=12, max_length=12),
    principal: str | None = Query(default=None, max_length=256),
    search: str | None = Query(default=None, max_length=256),
    due_before: datetime | None = None,
    claims: dict = Depends(current_reviewer),
):
    require_reviewer_group(claims)
    account_scopes = auth.identity_summary(claims)["account_scopes"]
    if account_id:
        require_account_scope(claims, account_id)
    if due_before and (due_before.tzinfo is None or due_before.utcoffset() is None):
        raise HTTPException(status_code=422, detail="due_before must include a timezone")
    with db.get_connection() as conn:
        selected_status = None if status == "ALL" else status
        filters = {
            "status": selected_status, "risk_level": risk_level,
            "campaign_id": campaign_id, "account_id": account_id,
            "principal": principal, "search": search,
            "due_before": due_before.astimezone(timezone.utc).isoformat() if due_before else None,
            "account_scopes": account_scopes,
        }
        reviews = workflow.queue(
            conn, claims["sub"], limit=limit, offset=offset, **filters
        )
        total = workflow.queue_total(conn, claims["sub"], **filters)
        return {
            "reviews": reviews, "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(reviews) < total,
        }


@app.get("/campaigns")
def list_campaigns(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    state: Literal["OPEN", "PAUSED", "CLOSED"] | None = None,
    claims: dict = Depends(current_reviewer),
):
    require_auditor_or_campaign_admin(claims)
    scopes = auth.identity_summary(claims)["account_scopes"]
    with db.get_connection() as conn:
        return workspaces.campaigns(conn, scopes, limit=limit, offset=offset, state=state)


@app.get("/snapshots")
def list_snapshots(
    account_id: str | None = Query(default=None, min_length=12, max_length=12),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    claims: dict = Depends(current_reviewer),
):
    require_campaign_admin(claims)
    if account_id:
        require_account_scope(claims, account_id)
    with db.get_connection() as conn:
        return workspaces.snapshot_candidates(
            conn, auth.identity_summary(claims)["account_scopes"],
            account_id=account_id, limit=limit, offset=offset,
        )


@app.get("/snapshots/{snapshot_id}/readiness")
def get_snapshot_readiness(snapshot_id: str, claims: dict = Depends(current_reviewer)):
    require_campaign_admin(claims)
    with db.get_connection() as conn:
        readiness = workspaces.snapshot_readiness(
            conn, snapshot_id, auth.identity_summary(claims)["account_scopes"]
        )
        if not readiness:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        return readiness


@app.post("/campaigns", status_code=201)
def create_campaign(request: CampaignCreateRequest, claims: dict = Depends(current_reviewer)):
    require_campaign_admin(claims)
    with db.get_connection() as conn:
        readiness = workspaces.snapshot_readiness(
            conn, request.snapshot_id, auth.identity_summary(claims)["account_scopes"]
        )
    if not readiness:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    if not readiness["eligible_for_campaign"]:
        raise HTTPException(status_code=409, detail={
            "code": "SNAPSHOT_NOT_ELIGIBLE",
            "message": "This snapshot cannot be used to create a campaign.",
            "details": {"blockers": readiness["blockers"]},
        })
    event = {
        "account_id": readiness["account_id"],
        "source_scope": readiness["source_scope"],
        "snapshot_id": request.snapshot_id,
        "name": request.name.strip(),
        "owner_sub": claims["sub"],
    }
    if request.due_at:
        event["due_at"] = _future_deadline(request.due_at)
    from lambdas.generate_reviews.handler import generate_campaign
    created = generate_campaign(event, None)
    if created.get("status") != "success":
        codes = {
            "no_eligible_published_snapshot": "SNAPSHOT_NOT_ELIGIBLE",
            "snapshot_changed": "SNAPSHOT_NOT_ELIGIBLE",
            "snapshot_risk_incomplete": "RISK_ASSESSMENT_INCOMPLETE",
            "active_campaign_exists": "ACTIVE_CAMPAIGN_EXISTS",
            "no_reviewable_grants": "NO_REVIEWABLE_GRANTS",
        }
        raise HTTPException(status_code=409, detail={
            "code": codes.get(created.get("reason"), "CAMPAIGN_CREATION_BLOCKED"),
            "message": "Campaign creation was blocked by current evidence readiness.",
            "details": created,
        })
    return {**created, "name": request.name.strip(), "state": "OPEN"}


def _review_detail_payload(conn, review_id: str, review_state: dict):
    row = repo.fetch_review_ai_context(conn, review_id)
    if not row:
        raise HTTPException(status_code=404, detail="Review not found")
    return {
            "review_id": row[0],
            "status": row[1],
            "user": row[4],
            "entitlement": row[5],
            "risk_level": row[6],
            "policy_document": json.loads(row[7]) if row[7] else None,
            "risk_reason": row[8],
            "risk_evidence": json.loads(row[9]) if row[9] else None,
            "risk_rule_version": row[10],
            "snapshot_id": row[11],
            "grant_id": row[12],
            "observation_id": row[13],
            "risk_assessment_id": row[14],
            "grant_type": row[15],
            "grant_source": row[16],
            "policy_version": row[17],
            "policy_sha256": row[18],
            "evidence_state": row[19],
            "policy_evidence_status": row[20],
            "missing_policy_reason": row[21],
            "source_coverage": json.loads(row[22]) if row[22] else None,
            "source_account_id": row[23],
            "source_scope": row[24],
            "snapshot_published_at": str(row[25]) if row[25] else None,
            "snapshot_current_eligible": (
                bool(row[23] and row[24] and
                     (eligible := repo.eligible_published_snapshot(conn, row[23], row[24]))
                     and eligible["snapshot_id"] == row[11])
            ),
            "review_scope": "GRANT_PATH" if row[12] else "LEGACY_UNKNOWN_PATH",
            "principal_access_status": "not_evaluated",
            "ai_explanation": ai_artifacts.projection(conn, review_id),
            "assigned_reviewer_sub": review_state["assigned_reviewer_sub"],
            "due_at": review_state["due_at"],
            "exception_state": review_state["exception_state"],
        "campaign_state": review_state["campaign_state"],
    }


@app.get("/reviews/{review_id}")
def get_review(review_id: str, claims: dict = Depends(current_reviewer)):
    with db.get_connection() as conn:
        review = repo.fetch_review_for_decision(conn, review_id)
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")
        if auth.has_group(claims, os.getenv("CAMPAIGN_ADMIN_GROUP", "")):
            review_state = require_review_scope(conn, claims, review_id)
            require_campaign_scope(conn, claims, review[1])
        else:
            require_reviewer_group(claims)
            review_state = require_review_assignment(
                conn, review_id, review[1], claims["sub"], claims=claims
            )
        return _review_detail_payload(conn, review_id, review_state)


@app.get("/reviews/{review_id}/history")
def get_review_history(
    review_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    claims: dict = Depends(current_reviewer),
):
    with db.get_connection() as conn:
        review = repo.fetch_review_for_decision(conn, review_id)
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")
        if auth.has_group(claims, os.getenv("CAMPAIGN_ADMIN_GROUP", "")):
            require_review_scope(conn, claims, review_id)
            require_campaign_scope(conn, claims, review[1])
        else:
            require_reviewer_group(claims)
            require_review_assignment(conn, review_id, review[1], claims["sub"], claims=claims)
        events = workflow.review_history(conn, review_id)
        return {
            "review_id": review_id, "events": events[offset:offset + limit],
            "limit": limit, "offset": offset, "total": len(events),
        }


@app.post("/reviews/{review_id}/decision")
def decide_review(
    review_id: str, request: DecisionRequest, claims: dict = Depends(current_reviewer)
):
    require_reviewer_group(claims)
    if request.decision == "REVOKED" and not request.comment.strip():
        raise HTTPException(status_code=422, detail="A revocation requires a comment")
    with db.get_connection() as conn:
        review = repo.fetch_review_for_decision(conn, review_id)
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")
        state = require_review_assignment(
            conn, review_id, review[1], claims["sub"], claims=claims
        )
        campaign_row = workflow.campaign(conn, review[1], lock=True)
        if campaign_row["state"] != "OPEN" or state["exception_state"] == "OPEN":
            raise HTTPException(status_code=409, detail="Review is not decision-ready")
        if review[2] != "PENDING":
            raise HTTPException(
                status_code=409, detail="Review has already been decided"
            )
        binding = repo.review_evidence_binding(conn, review_id)
        if binding:
            eligible = repo.eligible_published_snapshot(
                conn, binding["account_id"], binding["source_scope"]
            )
            if not eligible or eligible["snapshot_id"] != binding["snapshot_id"]:
                raise HTTPException(
                    status_code=409,
                    detail="The review evidence snapshot is no longer eligible; refresh evidence before deciding",
                )
        now = datetime.now(timezone.utc)
        cur = conn.cursor()
        db.execute(
            cur,
            """UPDATE access_reviews SET status=?, reviewer_comment=?, reviewed_at=?, reviewer_sub=?
            WHERE review_id=? AND status='PENDING' AND exception_state<>'OPEN'
              AND (assigned_reviewer_sub IS NULL OR assigned_reviewer_sub=?)""",
            (
                request.decision,
                request.comment.strip(),
                now.isoformat(),
                claims["sub"],
                review_id,
                claims["sub"],
            ),
        )
        if cur.rowcount != 1:
            raise HTTPException(
                status_code=409, detail="Review decision raced with another update"
            )
        ai_projection = ai_artifacts.projection(conn, review_id)
        repo.record_review_decision_event(
            conn, str(uuid.uuid4()), review_id, request.decision,
            claims["sub"], request.comment.strip(), now.isoformat(),
            ai_projection.get("artifact_id") if ai_projection.get("validated_artifact") else None,
            decision_origin="OIDC_API",
        )
        repo.insert_audit_log(
            conn,
            str(uuid.uuid4()),
            now,
            "INFO",
            "review_decision",
            request.decision,
            "Authenticated campaign reviewer recorded a decision",
            entity_type="access_review",
            entity_id=review_id,
            details={
                "reviewer_sub": claims["sub"],
                "campaign_id": review[1],
                "decision": request.decision,
                "comment": request.comment.strip(),
            },
        )
    return {"review_id": review_id, "status": request.decision}


@app.post("/reviews/{review_id}/ai/explanation", status_code=202)
def enqueue_review_explanation(review_id: str, claims: dict = Depends(current_reviewer)):
    require_reviewer_group(claims)
    if (
        not config.is_genai_enabled()
        or os.getenv("AI_PROVIDER_DATA_APPROVED", "").lower() != "true"
        or not os.getenv("AI_PSEUDONYM_KEY")
        or not os.getenv("GOOGLE_API_KEY")
    ):
        raise HTTPException(status_code=409, detail="AI explanation is disabled")
    with db.get_connection() as conn:
        item = workflow.review_workflow(conn, review_id)
        if not item:
            raise HTTPException(status_code=404, detail="Review not found")
        require_review_assignment(
            conn, review_id, item["campaign_id"], claims["sub"], claims=claims
        )
        job = ai_artifacts.enqueue_review(
            conn, review_id, pseudonym_key=os.getenv("AI_PSEUDONYM_KEY")
        )
        if not job:
            raise HTTPException(status_code=409, detail="Review is not eligible for AI explanation")
    return job


@app.get("/ai/jobs/{job_id}")
def get_ai_job(job_id: str, claims: dict = Depends(current_reviewer)):
    require_reviewer_group(claims)
    with db.get_connection() as conn:
        job = ai_artifacts.job_status(conn, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="AI job not found")
        item = workflow.review_workflow(conn, job["review_id"])
        require_review_assignment(
            conn, job["review_id"], item["campaign_id"], claims["sub"], claims=claims
        )
        return job


@app.post("/ai/jobs/{job_id}/retry", status_code=202)
def retry_ai_job(job_id: str, claims: dict = Depends(current_reviewer)):
    require_campaign_admin(claims)
    if (
        not config.is_genai_enabled()
        or os.getenv("AI_PROVIDER_DATA_APPROVED", "").lower() != "true"
        or not os.getenv("AI_PSEUDONYM_KEY")
        or not os.getenv("GOOGLE_API_KEY")
    ):
        raise HTTPException(status_code=409, detail="AI explanation is disabled")
    with db.get_connection() as conn:
        try:
            job = ai_artifacts.retry_failed_job(
                conn, job_id, actor_sub=claims["sub"],
                pseudonym_key=os.environ["AI_PSEUDONYM_KEY"],
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        if not job:
            raise HTTPException(status_code=404, detail="AI job not found")
        item = require_review_scope(conn, claims, job["review_id"])
        require_campaign_scope(conn, claims, item["campaign_id"])
    return job


@app.get("/ai/metrics")
def get_ai_metrics(claims: dict = Depends(current_reviewer)):
    require_campaign_admin(claims)
    scopes = auth.identity_summary(claims)["account_scopes"]
    if scopes is not None and "*" not in scopes:
        raise HTTPException(status_code=403, detail="AI metrics do not support account-scoped aggregation")
    with db.get_connection() as conn:
        return ai_artifacts.metrics(conn)


@app.get("/sources/{account_id}/coverage")
def source_coverage(account_id: str, claims: dict = Depends(current_reviewer)):
    require_campaign_admin(claims)
    require_account_scope(claims, account_id)
    with db.get_connection() as conn:
        return {"sources": repo.list_source_coverage(conn, account_id)}


@app.post("/campaigns/{campaign_id}/reviewers", status_code=201)
def assign_reviewer(
    campaign_id: str,
    request: ReviewerAssignmentRequest,
    claims: dict = Depends(current_reviewer),
):
    require_campaign_admin(claims)
    reviewer_sub = _nonblank(request.reviewer_sub, "reviewer_sub")
    with db.get_connection() as conn:
        campaign_row = workflow.campaign(conn, campaign_id, lock=True)
        if not campaign_row:
            raise HTTPException(status_code=404, detail="Campaign not found")
        require_account_scope(claims, campaign_row["account_id"])
        if campaign_row["state"] == "CLOSED":
            raise HTTPException(status_code=409, detail="Campaign is closed")
        created = repo.assign_campaign_reviewer(
            conn, campaign_id, reviewer_sub, claims["sub"]
        )
        if created:
            workflow.record_event(
                conn, campaign_id, "CAMPAIGN_REVIEWER_ADDED", claims["sub"],
                new=reviewer_sub,
            )
            repo.insert_audit_log(
                conn,
                str(uuid.uuid4()),
                datetime.now(timezone.utc),
                "INFO",
                "campaign_reviewer_assignment",
                "success",
                "Campaign reviewer assigned",
                entity_type="campaign",
                entity_id=campaign_id,
                details={
                    "reviewer_sub": reviewer_sub,
                    "assigned_by": claims["sub"],
                },
            )
    return {
        "campaign_id": campaign_id,
        "reviewer_sub": reviewer_sub,
        "status": "assigned" if created else "already_assigned",
    }


@app.get("/campaigns/{campaign_id}/reviewers")
def get_campaign_reviewers(campaign_id: str, claims: dict = Depends(current_reviewer)):
    require_campaign_admin(claims)
    with db.get_connection() as conn:
        require_campaign_scope(conn, claims, campaign_id)
        return {"campaign_id": campaign_id,
                "reviewers": workspaces.campaign_reviewers(conn, campaign_id)}


@app.delete("/campaigns/{campaign_id}/reviewers")
def delete_campaign_reviewer(
    campaign_id: str,
    reviewer_sub: str = Query(min_length=1, max_length=256),
    claims: dict = Depends(current_reviewer),
):
    require_campaign_admin(claims)
    with db.get_connection() as conn:
        require_campaign_scope(conn, claims, campaign_id, lock=True)
        result = repo.remove_campaign_reviewer(conn, campaign_id, reviewer_sub)
        if result == "has_pending_reviews":
            raise HTTPException(status_code=409, detail={
                "code": "REVIEWER_HAS_PENDING_WORK",
                "message": "Reassign this reviewer's pending work before removing them from the campaign.",
            })
        if result == "not_found":
            raise HTTPException(status_code=404, detail="Campaign reviewer not found")
        repo.record_campaign_reviewer_event(
            conn, campaign_id=campaign_id, reviewer_sub=reviewer_sub,
            event_type="REMOVED", actor_sub=claims["sub"],
        )
    return {"campaign_id": campaign_id, "reviewer_sub": reviewer_sub, "result": "removed"}


@app.get("/campaigns/{campaign_id}/reviews")
def get_campaign_reviews(
    campaign_id: str,
    status: Literal["PENDING", "APPROVED", "REVOKED"] | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    claims: dict = Depends(current_reviewer),
):
    require_campaign_admin(claims)
    with db.get_connection() as conn:
        require_campaign_scope(conn, claims, campaign_id)
        return {"campaign_id": campaign_id,
                **workspaces.campaign_reviews(conn, campaign_id, status=status,
                                              limit=limit, offset=offset)}


@app.get("/campaigns/{campaign_id}/progress")
def get_campaign_progress(campaign_id: str, claims: dict = Depends(current_reviewer)):
    require_campaign_admin(claims)
    with db.get_connection() as conn:
        require_campaign_scope(conn, claims, campaign_id)
        return {"campaign_id": campaign_id, **workspaces.campaign_progress(conn, campaign_id)}


@app.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: str, claims: dict = Depends(current_reviewer)):
    with db.get_connection() as conn:
        item = workflow.campaign(conn, campaign_id)
        if not item:
            raise HTTPException(status_code=404, detail="Campaign not found")
        if auth.has_group(claims, os.getenv("CAMPAIGN_ADMIN_GROUP", "")):
            require_account_scope(claims, item["account_id"])
        else:
            require_reviewer_group(claims)
            require_campaign_assignment(conn, campaign_id, claims["sub"])
            require_account_scope(claims, item["account_id"])
        return item


@app.get("/campaigns/{campaign_id}/events")
def get_campaign_events(
    campaign_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    claims: dict = Depends(current_reviewer),
):
    with db.get_connection() as conn:
        item = workflow.campaign(conn, campaign_id)
        if not item:
            raise HTTPException(status_code=404, detail="Campaign not found")
        if auth.has_group(claims, os.getenv("CAMPAIGN_ADMIN_GROUP", "")):
            require_account_scope(claims, item["account_id"])
        else:
            require_reviewer_group(claims)
            require_campaign_assignment(conn, campaign_id, claims["sub"])
            require_account_scope(claims, item["account_id"])
        return {"events": workflow.events(conn, campaign_id, limit=limit, offset=offset),
                "limit": limit, "offset": offset}


@app.post("/campaigns/{campaign_id}/state")
def set_campaign_state(
    campaign_id: str, request: CampaignStateRequest,
    claims: dict = Depends(current_reviewer),
):
    require_campaign_admin(claims)
    with db.get_connection() as conn:
        require_campaign_scope(conn, claims, campaign_id, lock=True)
        result = _workflow_result(
            workflow.change_campaign_state(conn, campaign_id, request.state, claims["sub"])
        )
    return {"campaign_id": campaign_id, "state": request.state, "result": result}


@app.post("/campaigns/{campaign_id}/owner")
def set_campaign_owner(
    campaign_id: str, request: CampaignOwnerRequest,
    claims: dict = Depends(current_reviewer),
):
    require_campaign_admin(claims)
    owner_sub = _nonblank(request.owner_sub, "owner_sub")
    with db.get_connection() as conn:
        require_campaign_scope(conn, claims, campaign_id, lock=True)
        result = _workflow_result(
            workflow.change_campaign_field(conn, campaign_id, "owner_sub", owner_sub, claims["sub"])
        )
    return {"campaign_id": campaign_id, "owner_sub": owner_sub, "result": result}


@app.post("/campaigns/{campaign_id}/deadline")
def set_campaign_deadline(
    campaign_id: str, request: DeadlineRequest,
    claims: dict = Depends(current_reviewer),
):
    require_campaign_admin(claims)
    due_at = _future_deadline(request.due_at)
    with db.get_connection() as conn:
        require_campaign_scope(conn, claims, campaign_id, lock=True)
        result = _workflow_result(
            workflow.change_campaign_field(conn, campaign_id, "due_at", due_at, claims["sub"])
        )
    return {"campaign_id": campaign_id, "due_at": due_at, "result": result}


@app.post("/reviews/{review_id}/assignment")
def set_review_assignment(
    review_id: str, request: ReviewerAssignmentRequest,
    claims: dict = Depends(current_reviewer),
):
    require_campaign_admin(claims)
    reviewer_sub = _nonblank(request.reviewer_sub, "reviewer_sub")
    with db.get_connection() as conn:
        item = require_review_scope(conn, claims, review_id)
        require_campaign_scope(conn, claims, item["campaign_id"], lock=True)
        result = _workflow_result(
            workflow.assign_review(conn, review_id, reviewer_sub, claims["sub"])
        )
    return {"review_id": review_id, "reviewer_sub": reviewer_sub, "result": result}


@app.post("/reviews/{review_id}/deadline")
def set_review_deadline(
    review_id: str, request: DeadlineRequest,
    claims: dict = Depends(current_reviewer),
):
    require_campaign_admin(claims)
    due_at = _future_deadline(request.due_at)
    with db.get_connection() as conn:
        item = require_review_scope(conn, claims, review_id)
        require_campaign_scope(conn, claims, item["campaign_id"], lock=True)
        result = _workflow_result(
            workflow.change_review_deadline(conn, review_id, due_at, claims["sub"])
        )
    return {"review_id": review_id, "due_at": due_at, "result": result}


@app.post("/reviews/{review_id}/exception")
def open_review_exception(
    review_id: str, request: ExceptionRequest,
    claims: dict = Depends(current_reviewer),
):
    require_reviewer_group(claims)
    reason = _nonblank(request.reason, "reason")
    with db.get_connection() as conn:
        item = workflow.review_workflow(conn, review_id)
        if not item:
            raise HTTPException(status_code=404, detail="Review not found")
        require_review_assignment(
            conn, review_id, item["campaign_id"], claims["sub"], claims=claims
        )
        result = _workflow_result(
            workflow.set_exception(conn, review_id, "OPEN", claims["sub"], reason)
        )
    return {"review_id": review_id, "exception_state": "OPEN", "result": result}


@app.post("/reviews/{review_id}/exception/resolve")
def resolve_review_exception(
    review_id: str, request: ExceptionRequest,
    claims: dict = Depends(current_reviewer),
):
    require_campaign_admin(claims)
    reason = _nonblank(request.reason, "reason")
    with db.get_connection() as conn:
        item = require_review_scope(conn, claims, review_id)
        require_campaign_scope(conn, claims, item["campaign_id"], lock=True)
        result = _workflow_result(
            workflow.set_exception(conn, review_id, "RESOLVED", claims["sub"], reason)
        )
    return {"review_id": review_id, "exception_state": "RESOLVED", "result": result}


@app.post("/reviews/{review_id}/remediation-approval")
def approve_remediation(
    review_id: str, response: Response, claims: dict = Depends(current_reviewer),
    approval_request: RemediationApprovalRequest | None = None,
):
    require_remediation_approver(claims)
    if approval_request and approval_request.decision != "APPROVED":
        raise HTTPException(status_code=422, detail="Approval endpoint accepts APPROVED only")
    with db.get_connection() as conn:
        review = repo.fetch_review_for_decision(conn, review_id)
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")
        campaign_row = workflow.campaign(conn, review[1])
        if not campaign_row:
            raise HTTPException(status_code=404, detail="Review not found")
        require_account_scope(claims, campaign_row["account_id"])
        if review[2] != "REVOKED":
            raise HTTPException(
                status_code=409,
                detail="Only revoked reviews can be approved for remediation",
            )
        if not review[5]:
            raise HTTPException(
                status_code=409,
                detail="Review does not have a verified reviewer subject",
            )
        if review[5] == claims["sub"]:
            raise HTTPException(
                status_code=403,
                detail="The reviewer cannot approve their own remediation",
            )
        decision_event_id = repo.authenticated_revocation_event(conn, review_id)
        if not decision_event_id:
            raise HTTPException(
                status_code=409,
                detail="An authenticated, snapshot-bound revocation decision is required",
            )
        if repo.remediation_decline(conn, review_id):
            raise HTTPException(status_code=409, detail="This remediation request was already declined")
        repo.lock_inventory_remediation(conn)
        binding = repo.review_evidence_binding(conn, review_id)
        if (not binding or binding["grant_type"] not in repo.REMEDIATION_ACTIONS
                or binding["evidence_status"] != "COMPLETE"
                or not binding["principal_arn"]):
            raise HTTPException(
                status_code=409,
                detail="Only complete, snapshot-pinned direct user policy paths support remediation",
            )
        require_account_scope(claims, binding["account_id"])
        snapshot = repo.eligible_published_snapshot(
            conn, binding["account_id"], binding["source_scope"], require_aws=True
        )
        if (
            not snapshot
            or snapshot["snapshot_id"] != binding["snapshot_id"]
            or not repo.is_current_grant_for_review(conn, review_id)
        ):
            raise HTTPException(
                status_code=409,
                detail="Review grant path requires a current eligible AWS snapshot",
            )
        previous = repo.get_remediation_approval(conn, review_id)
        now = datetime.now(timezone.utc)
        approval_id = str(uuid.uuid4())
        created = repo.record_remediation_approval(
            conn,
            approval_id,
            review_id,
            claims["sub"],
            now.isoformat(),
            binding["snapshot_id"],
        )
        if not created:
            raise HTTPException(
                status_code=409,
                detail="A remediation approval already exists for this discovery run",
            )
        renewed = previous is not None
        response.status_code = 200 if renewed else 201
        status = "renewed" if renewed else "approved"
        approval_event_id = repo.record_remediation_approval_event(
            conn, approval_id, review_id, decision_event_id, claims["sub"],
            now.isoformat(), "RENEWED" if renewed else "APPROVED", binding,
            approval_request.reason if approval_request else "",
        )
        repo.insert_audit_log(
            conn,
            str(uuid.uuid4()),
            now,
            "INFO",
            "remediation_approval",
            status,
            "Independent authenticated approver authorized or renewed remediation",
            entity_type="access_review",
            entity_id=review_id,
            details={
                "approver_sub": claims["sub"],
                "reviewer_sub": review[5],
                "snapshot_id": binding["snapshot_id"],
                "grant_id": binding["grant_id"],
                "approval_event_id": approval_event_id,
                "renewed": renewed,
            },
        )
    return {"review_id": review_id, "status": status,
            "snapshot_id": binding["snapshot_id"],
            "discovery_run_id": binding["snapshot_id"],
            "approval_event_id": approval_event_id,
            "action_type": repo.REMEDIATION_ACTIONS[binding["grant_type"]]}


@app.get("/approvals")
def list_remediation_approvals(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    claims: dict = Depends(current_reviewer),
):
    require_remediation_approver(claims)
    scopes = auth.identity_summary(claims)["account_scopes"]
    with db.get_connection() as conn:
        return workspaces.remediation_queue(conn, scopes, claims["sub"],
                                            limit=limit, offset=offset)


@app.get("/approvals/{review_id}")
def get_remediation_approval_detail(review_id: str, claims: dict = Depends(current_reviewer)):
    require_remediation_approver(claims)
    with db.get_connection() as conn:
        review = repo.fetch_review_for_decision(conn, review_id)
        if not review:
            raise HTTPException(status_code=404, detail="Remediation request not found")
        state = workflow.review_workflow(conn, review_id)
        if not state:
            raise HTTPException(status_code=404, detail="Remediation request not found")
        require_account_scope(claims, state["account_id"])
        eligibility = workspaces.remediation_eligibility(conn, review_id, claims["sub"])
        return {
            "review": _review_detail_payload(conn, review_id, state),
            "remediation": eligibility,
            "execution_mode": "LIVE_ENABLED" if config.is_live_remediation_explicitly_allowed() else "DRY_RUN_OR_DISABLED",
            "reconciliation_required": repo.remediation_reconciliation_required(conn, review_id),
        }


@app.post("/approvals/{review_id}/decision")
def decide_remediation_approval(
    review_id: str, request: RemediationApprovalRequest, response: Response,
    claims: dict = Depends(current_reviewer),
):
    require_remediation_approver(claims)
    reason = _nonblank(request.reason, "reason")
    if request.decision == "APPROVED":
        response = Response()
        result = approve_remediation(
            review_id, response, claims,
            RemediationApprovalRequest(decision="APPROVED", reason=reason),
        )
        return result

    with db.get_connection() as conn:
        review = repo.fetch_review_for_decision(conn, review_id)
        if not review:
            raise HTTPException(status_code=404, detail="Remediation request not found")
        state = workflow.review_workflow(conn, review_id)
        if not state:
            raise HTTPException(status_code=404, detail="Remediation request not found")
        require_account_scope(claims, state["account_id"])
        if review[2] != "REVOKED":
            raise HTTPException(status_code=409, detail="Only revoked reviews can be declined for remediation")
        if not review[5]:
            raise HTTPException(status_code=409, detail="The original reviewer identity is not verified")
        if review[5] == claims["sub"]:
            raise HTTPException(status_code=403, detail="The reviewer cannot decline their own remediation request")
        decision_event_id = repo.authenticated_revocation_event(conn, review_id)
        binding = repo.review_evidence_binding(conn, review_id)
        if not decision_event_id or not binding:
            raise HTTPException(status_code=409, detail={
                "code": "VERIFIABLE_EVIDENCE_REQUIRED",
                "message": "A snapshot-bound revoke decision and grant evidence are required to record an auditable decline.",
            })
        if repo.get_remediation_approval(conn, review_id):
            raise HTTPException(status_code=409, detail="This remediation request has already been approved")
        if repo.remediation_decline(conn, review_id):
            raise HTTPException(status_code=409, detail="This remediation request has already been declined")
        now = datetime.now(timezone.utc)
        decline_id = str(uuid.uuid4())
        repo.record_remediation_decline(
            conn, decline_id=decline_id, review_id=review_id,
            decision_event_id=decision_event_id, approver_sub=claims["sub"],
            declined_at=now.isoformat(), binding=binding, reason=reason,
        )
        repo.insert_audit_log(
            conn, str(uuid.uuid4()), now, "INFO", "remediation_approval",
            "declined", "Independent approver declined remediation",
            entity_type="access_review", entity_id=review_id,
            details={"approver_sub": claims["sub"], "reviewer_sub": review[5],
                     "decline_id": decline_id, "snapshot_id": binding["snapshot_id"],
                     "grant_id": binding["grant_id"], "reason": reason},
        )
    return {"review_id": review_id, "status": "declined", "decline_id": decline_id}


@app.get("/reviews/{review_id}/remediation")
def get_remediation_history(review_id: str, claims: dict = Depends(current_reviewer)):
    with db.get_connection() as conn:
        review = repo.fetch_review_for_decision(conn, review_id)
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")
        campaign = workflow.campaign(conn, review[1])
        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")
        require_account_scope(claims, campaign["account_id"])
        try:
            require_campaign_admin(claims)
        except HTTPException:
            try:
                auth.require_group(claims, os.getenv("REMEDIATION_APPROVER_GROUP", ""))
            except auth.AuthorizationError:
                try:
                    require_remediation_operator(claims)
                except HTTPException:
                    require_reviewer_group(claims)
                    require_review_assignment(
                        conn, review_id, review[1], claims["sub"], claims=claims
                    )
        history = repo.remediation_history(conn, review_id)
        return {"review_id": review_id, "principal_access_status": "not_evaluated",
                **history}


@app.post("/reviews/{review_id}/remediation/reconciliation", status_code=202)
def request_remediation_reconciliation(
    review_id: str, request: ExceptionRequest,
    claims: dict = Depends(current_reviewer),
):
    require_remediation_operator(claims)
    reason = _nonblank(request.reason, "reason")
    with db.get_connection() as conn:
        review = repo.fetch_review_for_decision(conn, review_id)
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")
        campaign = require_campaign_scope(conn, claims, review[1])
        repo.lock_inventory_remediation(conn)
        request_id = repo.request_remediation_reconciliation(
            conn, review_id, claims["sub"], reason,
        )
        if not request_id:
            raise HTTPException(
                status_code=409, detail="No eligible unresolved hold or a recheck is pending"
            )
        repo.insert_audit_log(
            conn, str(uuid.uuid4()), datetime.now(timezone.utc), "INFO",
            "remediation_reconciliation_request", "requested",
            "Operator requested a read-only exact-path AWS recheck",
            entity_type="access_review", entity_id=review_id,
            details={"operator_sub": claims["sub"], "request_id": request_id},
        )
    return {"review_id": review_id, "request_id": request_id, "status": "requested"}


def _audit_reader_scope(claims: dict):
    role = require_auditor_or_campaign_admin(claims)
    return auth.identity_summary(claims)["account_scopes"], role


@app.get("/audit/events")
def list_audit_events(
    campaign_id: str | None = Query(default=None, max_length=128),
    account_id: str | None = Query(default=None, min_length=12, max_length=12),
    review_id: str | None = Query(default=None, max_length=128),
    principal: str | None = Query(default=None, max_length=256),
    actor_sub: str | None = Query(default=None, max_length=256),
    decision: Literal["APPROVED", "REVOKED"] | None = None,
    remediation_status: str | None = Query(default=None, max_length=48),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    claims: dict = Depends(current_reviewer),
):
    scopes, _role = _audit_reader_scope(claims)
    if account_id:
        require_account_scope(claims, account_id)
    if since and (since.tzinfo is None or since.utcoffset() is None):
        raise HTTPException(status_code=422, detail="since must include a timezone")
    if until and (until.tzinfo is None or until.utcoffset() is None):
        raise HTTPException(status_code=422, detail="until must include a timezone")
    with db.get_connection() as conn:
        if campaign_id:
            require_campaign_scope(conn, claims, campaign_id)
        return workspaces.audit_events(
            conn, scopes, limit=limit, offset=offset, campaign_id=campaign_id,
            account_id=account_id, review_id=review_id, principal=principal,
            actor_sub=actor_sub, decision=decision,
            remediation_status=remediation_status,
            since=since.astimezone(timezone.utc).isoformat() if since else None,
            until=until.astimezone(timezone.utc).isoformat() if until else None,
        )


def _export_record(conn, export_id: str, claims: dict):
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", export_id):
        raise HTTPException(status_code=404, detail="Export not found")
    cur = conn.cursor()
    db.execute(cur, """SELECT id,timestamp,status,details FROM audit_logs
        WHERE action='export_audit' AND status='success' ORDER BY timestamp DESC""")
    for row in cur.fetchall():
        try:
            details = json.loads(row[3]) if row[3] else {}
        except (TypeError, json.JSONDecodeError):
            continue
        if details.get("export_run_id") != export_id:
            continue
        scopes = details.get("account_scopes")
        campaign_id = details.get("campaign_id")
        if campaign_id:
            campaign = workflow.campaign(conn, campaign_id)
            if not campaign:
                raise HTTPException(status_code=404, detail="Export not found")
            require_account_scope(claims, campaign["account_id"])
        elif scopes is None or "*" in scopes:
            active_scopes = auth.identity_summary(claims)["account_scopes"]
            if active_scopes is not None and "*" not in active_scopes:
                raise HTTPException(status_code=404, detail="Export not found")
        else:
            for account in scopes:
                require_account_scope(claims, account)
        return {"id": row[0], "created_at": str(row[1]), "status": row[2],
                "details": details}
    raise HTTPException(status_code=404, detail="Export not found")


def _read_export_bytes(record: dict, artifact: str) -> bytes:
    details = record["details"]
    run_id = details["export_run_id"]
    if artifact not in {"csv", "json", "manifest"}:
        raise HTTPException(status_code=422, detail="Unsupported export artifact")
    s3_location = details.get("s3_location")
    if s3_location:
        parsed = urlparse(s3_location)
        bucket = parsed.netloc
        prefix = parsed.path.lstrip("/")
        suffix = "manifest.json" if artifact == "manifest" else f"access_certification.{artifact}"
        try:
            import boto3
            response = boto3.client("s3", region_name=config.get_aws_region()).get_object(
                Bucket=bucket, Key=f"{prefix}/{suffix}"
            )
            return response["Body"].read()
        except Exception:
            raise HTTPException(status_code=503, detail="The authorized export artifact is unavailable") from None
    reports_dir = Path(__file__).resolve().parents[1] / "reports"
    pattern = (f"access_certification_*_{run_id}.manifest.json" if artifact == "manifest"
               else f"access_certification_*_{run_id}.{artifact}")
    match = next(iter(reports_dir.glob(pattern)), None)
    if not match or match.resolve().parent != reports_dir.resolve():
        raise HTTPException(status_code=404, detail="Export artifact not found")
    return match.read_bytes()


@app.get("/exports")
def list_exports(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    claims: dict = Depends(current_reviewer),
):
    _audit_reader_scope(claims)
    with db.get_connection() as conn:
        cur = conn.cursor()
        db.execute(cur, """SELECT id,timestamp,status,details FROM audit_logs
            WHERE action='export_audit' ORDER BY timestamp DESC,id DESC""")
        visible = []
        for row in cur.fetchall():
            try:
                details = json.loads(row[3]) if row[3] else {}
            except (TypeError, json.JSONDecodeError):
                continue
            run_id = details.get("export_run_id")
            if not run_id:
                continue
            try:
                record = _export_record(conn, run_id, claims)
            except HTTPException:
                continue
            visible.append({
                "export_id": run_id, "created_at": record["created_at"],
                "status": record["status"], "requested_by": details.get("requested_by"),
                "campaign_id": details.get("campaign_id"),
                "record_count": details.get("record_count", 0),
                "csv_sha256": details.get("csv_sha256"),
                "json_sha256": details.get("json_sha256"),
                "manifest_sha256": details.get("manifest_sha256"),
            })
        return {"exports": visible[offset:offset + limit], "limit": limit,
                "offset": offset, "total": len(visible),
                "has_more": offset + limit < len(visible)}


@app.post("/exports", status_code=201)
def request_audit_export(request: ExportRequest, claims: dict = Depends(current_reviewer)):
    _audit_reader_scope(claims)
    scopes = auth.identity_summary(claims)["account_scopes"]
    if request.account_id:
        require_account_scope(claims, request.account_id)
        scopes = [request.account_id]
    with db.get_connection() as conn:
        if request.campaign_id:
            campaign = require_campaign_scope(conn, claims, request.campaign_id)
            if request.account_id and campaign["account_id"] != request.account_id:
                raise HTTPException(status_code=422, detail="Campaign is outside the selected account")
            scopes = [campaign["account_id"]] if campaign["account_id"] else scopes
    try:
        from reports.export_audit import export_audit_report
        result = export_audit_report(
            campaign_id=request.campaign_id, account_scopes=scopes,
            requested_by=claims["sub"], max_rows=5000,
        )
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from None
    except Exception:
        raise HTTPException(status_code=503, detail="The audit export could not be generated") from None
    return {"export_id": result["export_run_id"], "status": "complete",
            "created_at": result["generated_at"], "record_count": result["record_count"],
            "csv_sha256": result["csv_sha256"], "json_sha256": result["json_sha256"],
            "manifest_sha256": result["manifest_sha256"]}


@app.get("/exports/{export_id}")
def get_audit_export(export_id: str, claims: dict = Depends(current_reviewer)):
    _audit_reader_scope(claims)
    with db.get_connection() as conn:
        record = _export_record(conn, export_id, claims)
        details = record["details"]
        return {"export_id": export_id, "status": record["status"],
                "created_at": record["created_at"], "record_count": details.get("record_count"),
                "csv_sha256": details.get("csv_sha256"),
                "json_sha256": details.get("json_sha256"),
                "manifest_sha256": details.get("manifest_sha256"),
                "campaign_id": details.get("campaign_id")}


@app.get("/exports/{export_id}/verify")
def verify_audit_export(export_id: str, claims: dict = Depends(current_reviewer)):
    _audit_reader_scope(claims)
    with db.get_connection() as conn:
        record = _export_record(conn, export_id, claims)
        manifest_bytes = _read_export_bytes(record, "manifest")
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        try:
            manifest = json.loads(manifest_bytes)
        except json.JSONDecodeError:
            raise HTTPException(status_code=409, detail="Export manifest is invalid") from None
        checked = {}
        for artifact in ("csv", "json"):
            data = _read_export_bytes(record, artifact)
            actual = hashlib.sha256(data).hexdigest()
            expected = manifest.get("artifacts", {}).get(artifact, {}).get("sha256")
            checked[artifact] = {"valid": actual == expected, "sha256": actual}
        return {"export_id": export_id, "manifest_sha256": manifest_hash,
                "manifest_valid": manifest_hash == record["details"].get("manifest_sha256"),
                "artifacts": checked,
                "valid": manifest_hash == record["details"].get("manifest_sha256")
                         and all(item["valid"] for item in checked.values())}


@app.get("/exports/{export_id}/download")
def download_audit_export(
    export_id: str,
    artifact: Literal["csv", "json", "manifest"] = "csv",
    claims: dict = Depends(current_reviewer),
):
    _audit_reader_scope(claims)
    with db.get_connection() as conn:
        record = _export_record(conn, export_id, claims)
        data = _read_export_bytes(record, artifact)
        repo.insert_audit_log(
            conn, str(uuid.uuid4()), datetime.now(timezone.utc), "INFO",
            "export_download", "success", "Authorized audit artifact downloaded",
            entity_type="audit_export", entity_id=export_id,
            details={"actor_sub": claims["sub"], "artifact": artifact},
        )
    media_type = {"csv": "text/csv", "json": "application/json",
                  "manifest": "application/json"}[artifact]
    filename = f"access_certification_{export_id}.{artifact if artifact != 'manifest' else 'manifest.json'}"
    return Response(content=data, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"',
                             "Cache-Control": "no-store"})


@app.get("/operations/health")
def operations_health(claims: dict = Depends(current_reviewer)):
    require_remediation_operator(claims)
    database = "ready"
    try:
        with db.get_connection() as conn:
            db.execute(conn.cursor(), "SELECT 1")
    except Exception:
        database = "unavailable"
    return {"api": "ready", "database": database,
            "status": "ready" if database == "ready" else "degraded",
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "worker_heartbeat_available": False}


@app.get("/operations/integrations")
def operations_integrations(claims: dict = Depends(current_reviewer)):
    require_remediation_operator(claims)
    return {
        "oidc": {"configured": bool(os.getenv("OIDC_ISSUER") and os.getenv("OIDC_AUDIENCE") and os.getenv("OIDC_JWKS_URL"))},
        "aws": {"credential_source_configured": bool(os.getenv("AWS_ROLE_ARN") or os.getenv("AWS_PROFILE") or os.getenv("AWS_ACCESS_KEY_ID")),
                "mock_mode": config.is_mock_iam(), "region_configured": bool(os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")),
                "connectivity": "not_checked"},
        "genai": {"enabled": config.is_genai_enabled(), "provider_data_approved": os.getenv("AI_PROVIDER_DATA_APPROVED", "").lower() == "true"},
        "audit_storage": {"s3_bucket_configured": bool(os.getenv("AUDIT_S3_BUCKET")),
                          "kms_key_configured": bool(os.getenv("AUDIT_S3_KMS_KEY_ID"))},
        "remediation": {"enabled": config.is_remediation_enabled(),
                        "dry_run": config.is_dry_run(),
                        "live_gate_configured": config.is_live_remediation_explicitly_allowed()},
    }


@app.get("/operations/jobs")
def operations_jobs(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    claims: dict = Depends(current_reviewer),
):
    require_remediation_operator(claims)
    scopes = auth.identity_summary(claims)["account_scopes"]
    events = []
    with db.get_connection() as conn:
        cur = conn.cursor()
        values: list = []
        scope_sql = workspaces._scope_filter("h.account_id", scopes, values)
        where = f"WHERE {scope_sql}" if scope_sql else ""
        db.execute(cur, f"""SELECT d.run_id,d.started_at,d.completed_at,d.status,d.source,
            d.users_seen,d.errors,h.account_id,h.source_scope FROM discovery_runs d
            LEFT JOIN source_attempt_heads h ON h.attempt_id=d.run_id {where}
            ORDER BY d.started_at DESC,d.run_id LIMIT 1000""", values)
        for row in cur.fetchall():
            events.append({"job_id": row[0], "job_type": "DISCOVERY", "status": row[3],
                           "started_at": str(row[1]), "completed_at": str(row[2]) if row[2] else None,
                           "source": row[4], "account_id": row[7], "source_scope": row[8],
                           "items_seen": row[5], "errors": row[6]})
        ai_values: list = []
        ai_scope = workspaces._scope_filter("c.account_id", scopes, ai_values)
        ai_where = f" AND {ai_scope}" if ai_scope else ""
        db.execute(cur, f"""SELECT j.job_id,j.status,j.created_at,j.updated_at,
            j.last_error_code,j.review_id,c.account_id FROM ai_jobs j
            JOIN access_reviews r ON r.review_id=j.review_id
            JOIN campaigns c ON c.campaign_id=r.campaign_id
            WHERE 1=1 {ai_where} ORDER BY j.updated_at DESC,j.job_id LIMIT 1000""", ai_values)
        for row in cur.fetchall():
            events.append({"job_id": row[0], "job_type": "AI_EXPLANATION", "status": row[1],
                           "started_at": str(row[2]), "completed_at": str(row[3]),
                           "error_code": row[4], "review_id": row[5], "account_id": row[6]})
        rem_values: list = []
        rem_scope = workspaces._scope_filter("c.account_id", scopes, rem_values)
        rem_where = f"WHERE {rem_scope}" if rem_scope else ""
        db.execute(cur, f"""SELECT e.event_id,e.review_id,e.event_type,e.created_at,e.actor_id
            FROM remediation_action_events e
            JOIN access_reviews r ON r.review_id=e.review_id
            JOIN campaigns c ON c.campaign_id=r.campaign_id
            {rem_where} ORDER BY e.created_at DESC,e.event_id DESC LIMIT 1000""", rem_values)
        for row in cur.fetchall():
            state = workflow.review_workflow(conn, row[1])
            if state:
                try:
                    auth.require_account_scope(claims, state["account_id"])
                except auth.AuthorizationError:
                    continue
            events.append({"job_id": row[0], "job_type": "REMEDIATION", "status": row[2],
                           "started_at": str(row[3]), "review_id": row[1], "actor_sub": row[4]})
        events.sort(key=lambda item: (item["started_at"], item["job_id"]), reverse=True)
        return {"jobs": events[offset:offset + limit], "limit": limit,
                "offset": offset, "total": len(events),
                "has_more": offset + limit < len(events),
                "worker_heartbeat_available": False}


@app.get("/operations/audit")
def operations_audit(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    claims: dict = Depends(current_reviewer),
):
    require_remediation_operator(claims)
    with db.get_connection() as conn:
        cur = conn.cursor()
        values: list = []
        scope_sql = workspaces._scope_filter("COALESCE(c.account_id,rc.account_id)", scopes, values)
        scope_clause = f" AND {scope_sql}" if scope_sql else ""
        db.execute(cur, f"""SELECT DISTINCT a.id,a.timestamp,a.level,a.action,a.entity_type,a.status
            FROM audit_logs a
            LEFT JOIN campaigns c ON a.entity_type='campaign' AND c.campaign_id=a.entity_id
            LEFT JOIN access_reviews r ON a.entity_type='access_review' AND r.review_id=a.entity_id
            LEFT JOIN campaigns rc ON rc.campaign_id=r.campaign_id
            WHERE (a.entity_type='campaign' AND c.campaign_id IS NOT NULL
                   OR a.entity_type='access_review' AND rc.campaign_id IS NOT NULL){scope_clause}
            ORDER BY a.timestamp DESC,a.id DESC LIMIT ? OFFSET ?""",
            [*values, limit, offset])
        rows = [{"event_id": row[0], "created_at": str(row[1]), "level": row[2],
                 "action": row[3], "entity_type": row[4], "status": row[5],
                 "details_redacted": True} for row in cur.fetchall()]
        return {"events": rows, "limit": limit, "offset": offset,
                "next_offset": offset + len(rows) if len(rows) == limit else None}
