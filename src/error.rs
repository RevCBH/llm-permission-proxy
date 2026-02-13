use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("gone: {0}")]
    Gone(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("precondition required: {0}")]
    PreconditionRequired(String),
    #[error("rate limited: {0}")]
    RateLimited(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl AppError {
    pub fn internal<E: std::fmt::Display>(err: E) -> Self {
        Self::Internal(err.to_string())
    }

    pub fn bad_request<E: std::fmt::Display>(err: E) -> Self {
        Self::BadRequest(err.to_string())
    }
}

#[derive(Serialize)]
struct ProblemResponse<'a> {
    code: &'a str,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg),
            AppError::Gone(msg) => (StatusCode::GONE, "gone", msg),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg),
            AppError::PreconditionRequired(msg) => {
                (StatusCode::PRECONDITION_REQUIRED, "precondition_required", msg)
            }
            AppError::RateLimited(msg) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", msg),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "internal", msg),
        };

        (status, Json(ProblemResponse { code, message })).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(value: sqlx::Error) -> Self {
        AppError::internal(value)
    }
}

impl From<anyhow::Error> for AppError {
    fn from(value: anyhow::Error) -> Self {
        AppError::internal(value)
    }
}
