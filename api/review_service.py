"""Minimal OIDC-protected API for campaign reviewer assignment and decisions.

Run behind a TLS-terminating gateway with restricted network access:
    uvicorn api.review_service:app --host 127.0.0.1 --port 8080
"""

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from common import ai_artifacts, auth, config, repo, workflow
from common.db import db

app = FastAPI(
    title="IAM Access Review API", docs_url=None, redoc_url=None, openapi_url=None
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


def require_review_assignment(conn, review_id: str, campaign_id: str, reviewer_sub: str):
    require_campaign_assignment(conn, campaign_id, reviewer_sub)
    item = workflow.review_workflow(conn, review_id)
    if item and item["assigned_reviewer_sub"] not in (None, reviewer_sub):
        raise HTTPException(status_code=403, detail="Review is assigned to another reviewer")
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


@app.get("/reviews/queue")
def reviewer_queue(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    claims: dict = Depends(current_reviewer),
):
    require_reviewer_group(claims)
    with db.get_connection() as conn:
        return {"reviews": workflow.queue(conn, claims["sub"], limit=limit, offset=offset),
                "limit": limit, "offset": offset}


@app.get("/reviews/{review_id}")
def get_review(review_id: str, claims: dict = Depends(current_reviewer)):
    require_reviewer_group(claims)
    with db.get_connection() as conn:
        review = repo.fetch_review_for_decision(conn, review_id)
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")
        review_state = require_review_assignment(conn, review_id, review[1], claims["sub"])
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
        state = require_review_assignment(conn, review_id, review[1], claims["sub"])
        campaign_row = workflow.campaign(conn, review[1], lock=True)
        if campaign_row["state"] != "OPEN" or state["exception_state"] == "OPEN":
            raise HTTPException(status_code=409, detail="Review is not decision-ready")
        if review[2] != "PENDING":
            raise HTTPException(
                status_code=409, detail="Review has already been decided"
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
        require_review_assignment(conn, review_id, item["campaign_id"], claims["sub"])
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
        require_review_assignment(conn, job["review_id"], item["campaign_id"], claims["sub"])
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
    return job


@app.get("/ai/metrics")
def get_ai_metrics(claims: dict = Depends(current_reviewer)):
    require_campaign_admin(claims)
    with db.get_connection() as conn:
        return ai_artifacts.metrics(conn)


@app.get("/sources/{account_id}/coverage")
def source_coverage(account_id: str, claims: dict = Depends(current_reviewer)):
    require_campaign_admin(claims)
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


@app.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: str, claims: dict = Depends(current_reviewer)):
    with db.get_connection() as conn:
        item = workflow.campaign(conn, campaign_id)
        if not item:
            raise HTTPException(status_code=404, detail="Campaign not found")
        try:
            require_campaign_admin(claims)
        except HTTPException:
            require_reviewer_group(claims)
            require_campaign_assignment(conn, campaign_id, claims["sub"])
        return item


@app.get("/campaigns/{campaign_id}/events")
def get_campaign_events(
    campaign_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    claims: dict = Depends(current_reviewer),
):
    with db.get_connection() as conn:
        if not workflow.campaign(conn, campaign_id):
            raise HTTPException(status_code=404, detail="Campaign not found")
        try:
            require_campaign_admin(claims)
        except HTTPException:
            require_reviewer_group(claims)
            require_campaign_assignment(conn, campaign_id, claims["sub"])
        return {"events": workflow.events(conn, campaign_id, limit=limit, offset=offset),
                "limit": limit, "offset": offset}


@app.post("/campaigns/{campaign_id}/state")
def set_campaign_state(
    campaign_id: str, request: CampaignStateRequest,
    claims: dict = Depends(current_reviewer),
):
    require_campaign_admin(claims)
    with db.get_connection() as conn:
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
        require_review_assignment(conn, review_id, item["campaign_id"], claims["sub"])
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
        result = _workflow_result(
            workflow.set_exception(conn, review_id, "RESOLVED", claims["sub"], reason)
        )
    return {"review_id": review_id, "exception_state": "RESOLVED", "result": result}


@app.post("/reviews/{review_id}/remediation-approval")
def approve_remediation(
    review_id: str, response: Response, claims: dict = Depends(current_reviewer)
):
    try:
        auth.require_group(claims, os.getenv("REMEDIATION_APPROVER_GROUP", ""))
    except auth.AuthorizationError:
        raise HTTPException(
            status_code=403, detail="Remediation approver group membership required"
        )
    with db.get_connection() as conn:
        review = repo.fetch_review_for_decision(conn, review_id)
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")
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
        repo.lock_inventory_remediation(conn)
        binding = repo.review_evidence_binding(conn, review_id)
        if (not binding or binding["grant_type"] not in repo.REMEDIATION_ACTIONS
                or binding["evidence_status"] != "COMPLETE"):
            raise HTTPException(
                status_code=409,
                detail="Only complete, snapshot-pinned direct user policy paths support remediation",
            )
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


@app.get("/reviews/{review_id}/remediation")
def get_remediation_history(review_id: str, claims: dict = Depends(current_reviewer)):
    with db.get_connection() as conn:
        review = repo.fetch_review_for_decision(conn, review_id)
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")
        try:
            require_campaign_admin(claims)
        except HTTPException:
            try:
                auth.require_group(claims, os.getenv("REMEDIATION_APPROVER_GROUP", ""))
            except auth.AuthorizationError:
                require_reviewer_group(claims)
                require_review_assignment(conn, review_id, review[1], claims["sub"])
        history = repo.remediation_history(conn, review_id)
        return {"review_id": review_id, "principal_access_status": "not_evaluated",
                **history}
