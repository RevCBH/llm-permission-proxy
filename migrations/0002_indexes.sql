CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_capability_task ON capability_tokens(task_id);
CREATE INDEX IF NOT EXISTS idx_capability_expires ON capability_tokens(expires_at);

CREATE INDEX IF NOT EXISTS idx_agent_permissions_lookup
  ON agent_permissions(agent_id, operation_id, scope_type, scope_id, revoked_at, expires_at);

CREATE INDEX IF NOT EXISTS idx_task_permission_snapshot_task
  ON task_permission_snapshot(task_id);

CREATE INDEX IF NOT EXISTS idx_permission_evals_task
  ON permission_evaluations(task_id, apply_request_id);

CREATE INDEX IF NOT EXISTS idx_idempotency_lookup
  ON idempotency_records(task_id, idempotency_key_hash);

CREATE INDEX IF NOT EXISTS idx_approvals_task_state
  ON approvals(task_id, state, created_at);

CREATE INDEX IF NOT EXISTS idx_approvals_nonce_hash
  ON approvals(nonce_hash);

CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_approval
  ON webauthn_challenges(approval_id, used_at, created_at);

CREATE INDEX IF NOT EXISTS idx_callback_deliveries_due
  ON callback_deliveries(next_retry_at, delivered_at);

CREATE INDEX IF NOT EXISTS idx_callback_deliveries_callback
  ON callback_deliveries(callback_id);
