export type AppIdentity = {
  subject: string;
  display_name: string;
  email: string;
  roles: string[];
  permissions: string[];
  account_scopes: string[] | null;
  scope_mode: "claim" | "global_admin";
  reviewer_assignment_available: boolean;
};

export type ReviewQueueItem = {
  review_id: string;
  campaign_id: string;
  status: "PENDING" | "APPROVED" | "REVOKED";
  assigned_reviewer_sub: string | null;
  due_at: string | null;
  exception_state: "NONE" | "OPEN" | "RESOLVED";
  state: "OPEN" | "PAUSED" | "CLOSED";
  name: string;
  account_id: string | null;
  source_scope: string | null;
  snapshot_id: string | null;
  principal: string;
  grant_name: string;
  grant_type: string | null;
  source_name: string | null;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";
};

export type ReviewQueueResponse = {
  reviews: ReviewQueueItem[];
  limit: number;
  offset: number;
  total: number;
  has_more: boolean;
};

export type ReviewSummary = {
  assigned: number;
  pending: number;
  approved: number;
  revoked: number;
  high_risk: number;
  overdue: number;
};

export type AiExplanation = {
  status?: string;
  authority?: string;
  validated_artifact?: boolean;
  artifact_id?: string;
  summary?: string | null;
  limitations?: string | null;
  citations?: Array<{ id: string; kind: string }>;
  source?: string;
  provider?: string | null;
  model?: string | null;
  generated_at?: string;
  message?: string;
};

export type AiJob = {
  job_id: string;
  status: "PENDING" | "RUNNING" | "COMPLETE" | "FAILED" | string;
  last_error_code?: string | null;
};

export type ReviewAssessment = {
  schema_version: string;
  risk_severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  assessment_status: "SUPPORTED" | "PARTIAL" | "UNASSESSED" | "UNSUPPORTED";
  assessment_confidence: "HIGH" | "MEDIUM" | "LOW" | "INSUFFICIENT";
  manual_review_required: boolean;
  reason_codes: string[];
  statement_refs?: Array<{
    statement_index: number;
    sid?: string | null;
    effect?: string;
    matched_actions?: string[];
    principal_values?: string[];
    reason_codes: string[];
    policy_sha256: string;
    attachment_id: string;
    policy_version: string | null;
  }>;
  evidence_completeness: {
    collection_status: string;
    source_coverage: string;
    unassessed_surfaces: string[];
    document_coverage: string;
    interpretability: string;
    missing_evidence_count: number;
    unsupported_constructs: Array<{ statement_index: number; construct: string }>;
    reason_codes: string[];
  };
};

export type ReviewDetail = {
  review_id: string;
  status: "PENDING" | "APPROVED" | "REVOKED";
  user: string;
  entitlement: string;
  risk_level: string;
  policy_document: Record<string, unknown> | null;
  risk_reason: string | null;
  risk_evidence: unknown;
  assessment?: ReviewAssessment | null;
  observed_path?: {
    principal_id: string;
    principal_name: string;
    principal_arn: string;
    grant_type: string;
    source_id: string;
    source_name: string;
    attachment_id: string;
    policy_id: string;
    policy_name: string;
    policy_version: string | null;
    policy_sha256: string;
    observed_at: string | null;
    collected_at: string | null;
    observation_id: string;
  } | null;
  source_manifest_sha256?: string | null;
  review_manifest_sha256?: string | null;
  evidence_invalidations?: Array<{
    invalidation_id: string;
    manifest_sha256: string;
    reason_code: string;
    detail: string;
    actor_sub: string;
    recorded_at: string;
  }>;
  risk_rule_version: string | null;
  snapshot_id: string | null;
  grant_id: string | null;
  observation_id: string | null;
  risk_assessment_id: string | null;
  grant_type: string | null;
  grant_source: string | null;
  policy_version: string | null;
  policy_sha256: string | null;
  evidence_state: string;
  policy_evidence_status: string;
  missing_policy_reason: string | null;
  source_coverage: unknown;
  source_account_id: string | null;
  source_scope: string | null;
  snapshot_published_at: string | null;
  snapshot_current_eligible: boolean;
  review_scope: "GRANT_PATH" | "LEGACY_UNKNOWN_PATH";
  principal_access_status: "not_evaluated";
  ai_explanation: AiExplanation;
  assigned_reviewer_sub: string | null;
  can_decide: boolean;
  can_decide_reason: string | null;
  due_at: string | null;
  exception_state: string;
  campaign_state: string;
};

export type ReviewHistoryEvent = {
  event_id: string;
  event_type: string;
  actor_sub: string | null;
  decision?: string;
  decision_origin?: string;
  comment?: string;
  previous_value?: string | null;
  new_value?: string | null;
  details?: Record<string, unknown>;
  created_at: string;
};

export type ApiErrorBody = {
  error?: { code?: string; message?: string; request_id?: string };
};
