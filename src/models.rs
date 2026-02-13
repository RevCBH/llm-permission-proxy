use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityBindings {
    pub mtls_subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub jti: String,
    pub iat: usize,
    pub nbf: usize,
    pub exp: usize,
    pub task_id: Option<String>,
    pub agent_id: String,
    pub allowed_ops: Vec<String>,
    pub resource_scopes: Vec<ResourceScope>,
    pub bindings: CapabilityBindings,
    pub perms_rev: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub jti: String,
    pub iat: usize,
    pub nbf: usize,
    pub exp: usize,
    pub bindings: CapabilityBindings,
    pub can_issue_tasks: bool,
    pub can_manage_permissions: bool,
    pub can_manage_approvers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalNonceClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub jti: String,
    pub iat: usize,
    pub nbf: usize,
    pub exp: usize,
    pub approval_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub jti: String,
    pub iat: usize,
    pub nbf: usize,
    pub exp: usize,
    pub approval_id: String,
    pub task_id: String,
    pub operation_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceScope {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum PermissionLevel {
    Read,
    Write,
    Admin,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Safe,
    Elevated,
    Sensitive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTaskRequest {
    pub task_name: String,
    #[serde(default)]
    pub operations: Vec<TaskOperationTemplate>,
    #[serde(default)]
    pub callback: Option<CallbackRegistrationInput>,
    #[serde(default)]
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskOperationTemplate {
    pub operation_id: String,
    pub scope_type: String,
    pub scope_id: String,
    #[serde(default)]
    pub required_level: Option<PermissionLevel>,
    #[serde(default)]
    pub risk_tier: Option<RiskTier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackRegistrationInput {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
    pub secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTaskResponse {
    pub task_id: String,
    pub status: String,
    pub capability_token: String,
    pub capability_ttl_seconds: i64,
    #[serde(default)]
    pub callback_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResponse {
    pub task_id: String,
    pub task_name: String,
    pub status: String,
    pub apply_state: String,
    #[serde(default)]
    pub callback_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyOperation {
    pub operation_id: String,
    pub scope_type: String,
    pub scope_id: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyRequest {
    pub operations: Vec<ApplyOperation>,
    #[serde(default)]
    pub callback: Option<CallbackRegistrationInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinueApplyRequest {
    pub resume_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCheck {
    pub requested: Vec<PermissionTuple>,
    pub pre_approved: Vec<PermissionTuple>,
    pub missing: Vec<PermissionGap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionTuple {
    pub operation_id: String,
    pub scope_type: String,
    pub scope_id: String,
    pub level: PermissionLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionGap {
    pub operation_id: String,
    pub scope_type: String,
    pub scope_id: String,
    pub needed: PermissionLevel,
    pub granted: Option<PermissionLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyPendingResponse {
    pub status: String,
    pub task_id: String,
    pub apply_state: String,
    pub approval_id: String,
    pub approval_status_url: String,
    pub resume_token: String,
    pub idempotency_key: String,
    pub retry_after_seconds: i64,
    #[serde(default)]
    pub callback_id: Option<String>,
    pub permission_check: PermissionCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplySuccessResponse {
    pub status: String,
    pub task_id: String,
    pub apply_state: String,
    pub idempotency_key: String,
    pub execution_id: String,
    pub results: Vec<OperationExecutionResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationExecutionResult {
    pub operation_id: String,
    pub success: bool,
    #[serde(default)]
    pub cloudflare_request_id: Option<String>,
    pub result: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalStatusResponse {
    pub approval_id: String,
    pub state: String,
    pub task_id: String,
    pub operation_fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub approved_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub denied_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApprovalRequest {
    #[serde(default)]
    pub approver_principal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApprovalResponse {
    pub task_id: String,
    pub approval_id: String,
    pub approval_url: String,
    pub approval_status_url: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordApprovalMessageResponse {
    pub approval_id: String,
    pub button_text: String,
    pub approver_summary: String,
    pub approve_url: String,
    pub expires_in_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPermissionItem {
    pub operation_id: String,
    pub scope_type: String,
    pub scope_id: String,
    pub granted_level: PermissionLevel,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPermissionsResponse {
    pub agent_id: String,
    pub permissions: Vec<AgentPermissionItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchAgentPermissionsRequest {
    pub permissions: Vec<AgentPermissionItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverCredentialItem {
    pub credential_id: String,
    pub status: String,
    #[serde(default = "default_credential_algorithm")]
    pub algorithm: String,
    #[serde(default = "default_credential_key_format")]
    pub public_key_format: String,
    #[serde(default)]
    pub public_key_thumbprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverCredentialsResponse {
    pub approver_principal: String,
    pub credentials: Vec<ApproverCredentialItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertApproverCredentialRequest {
    pub credential_id: String,
    pub public_key_b64: String,
    #[serde(default = "default_credential_status")]
    pub status: String,
    #[serde(default)]
    pub algorithm: Option<String>,
    #[serde(default)]
    pub public_key_format: Option<String>,
}

fn default_credential_algorithm() -> String {
    "ES256".to_string()
}

fn default_credential_key_format() -> String {
    "cose".to_string()
}

fn default_credential_status() -> String {
    "active".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnOptionsResponse {
    pub challenge: String,
    pub timeout: u32,
    pub rp_id: String,
    pub user_verification: String,
    pub allow_credentials: Vec<WebAuthnAllowCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAllowCredential {
    pub id: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnVerifyRequest {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    #[serde(default)]
    pub user_handle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnVerifyResponse {
    pub approval_id: String,
    pub status: String,
    pub task_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackEvent {
    pub event_id: String,
    pub event_type: String,
    pub task_id: String,
    #[serde(default)]
    pub approval_id: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackEnvelope {
    pub event: CallbackEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationCatalogEntry {
    pub operation_id: &'static str,
    pub required_level: PermissionLevel,
    pub risk_tier: RiskTier,
}
