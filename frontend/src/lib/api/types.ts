export type AppIdentity = {
  subject: string;
  display_name: string;
  email: string;
  roles: string[];
  permissions: string[];
  account_scopes: string[] | null;
  scope_mode: "claim" | "global_admin";
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

export type ReviewDetail = {
  review_id: string;
  status: "PENDING" | "APPROVED" | "REVOKED";
  user: string;
  entitlement: string;
  risk_level: string;
  policy_document: Record<string, unknown> | null;
  risk_reason: string | null;
  risk_evidence: unknown;
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
