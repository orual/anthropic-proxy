use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Authentication required")]
    Unauthorized,

    #[error("Invalid OAuth state")]
    InvalidState,

    #[error("Token exchange failed: {0}")]
    TokenExchangeError(String),

    #[error("Token refresh failed: {0}")]
    TokenRefreshError(String),

    #[error("Proxy error: {0}")]
    ProxyError(String),

    #[error("Request error: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("Internal server error")]
    InternalError(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::InvalidState => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::TokenExchangeError(_) | AppError::TokenRefreshError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Authentication failed".to_string(),
            ),
            AppError::ProxyError(_) | AppError::RequestError(_) => {
                (StatusCode::BAD_GATEWAY, "Proxy error".to_string())
            }
            AppError::InternalError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        let body = Json(json!({
            "error": error_message
        }));

        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
