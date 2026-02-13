use reqwest::{Client, Method};
use serde_json::{Value, json};

use crate::{error::AppError, models::OperationExecutionResult};

#[derive(Clone)]
pub struct CloudflareExecutor {
    pub api_token: Option<String>,
    pub api_base: String,
    pub http: Client,
}

impl CloudflareExecutor {
    pub fn new(api_token: Option<String>, api_base: String, http: Client) -> Self {
        Self {
            api_token,
            api_base,
            http,
        }
    }

    pub async fn execute(&self, operation_id: &str, scope_type: &str, scope_id: &str, params: &Value) -> Result<OperationExecutionResult, AppError> {
        if self.api_token.is_none() {
            return Ok(OperationExecutionResult {
                operation_id: operation_id.to_string(),
                success: true,
                cloudflare_request_id: None,
                result: json!({
                    "simulated": true,
                    "operation_id": operation_id,
                    "scope_type": scope_type,
                    "scope_id": scope_id,
                    "params": params,
                }),
            });
        }

        let token = self
            .api_token
            .clone()
            .ok_or_else(|| AppError::internal("missing api token"))?;

        let (method, path, body) = self.route(operation_id, scope_type, scope_id, params)?;
        let url = format!("{}{}", self.api_base, path);

        let mut request = self
            .http
            .request(method, &url)
            .bearer_auth(token)
            .header("content-type", "application/json");

        if let Some(body) = body {
            request = request.json(&body);
        }

        let response = request
            .send()
            .await
            .map_err(|e| AppError::internal(format!("cloudflare request failed: {e}")))?;

        let status = response.status();
        let request_id = response
            .headers()
            .get("cf-ray")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());

        let value = response
            .json::<Value>()
            .await
            .unwrap_or_else(|_| json!({"raw": "unparseable"}));

        if !status.is_success() {
            return Ok(OperationExecutionResult {
                operation_id: operation_id.to_string(),
                success: false,
                cloudflare_request_id: request_id,
                result: json!({
                    "http_status": status.as_u16(),
                    "response": value,
                }),
            });
        }

        Ok(OperationExecutionResult {
            operation_id: operation_id.to_string(),
            success: true,
            cloudflare_request_id: request_id,
            result: json!({
                "http_status": status.as_u16(),
                "response": value,
            }),
        })
    }

    fn route(&self, operation_id: &str, scope_type: &str, scope_id: &str, params: &Value) -> Result<(Method, String, Option<Value>), AppError> {
        match operation_id {
            "dns.record.read" => {
                if scope_type != "zone" {
                    return Err(AppError::BadRequest("dns.record.read requires zone scope".to_string()));
                }
                let name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let path = format!("/zones/{scope_id}/dns_records?name={name}");
                Ok((Method::GET, path, None))
            }
            "dns.record.write" => {
                if scope_type != "zone" {
                    return Err(AppError::BadRequest("dns.record.write requires zone scope".to_string()));
                }
                let action = params
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("create");

                match action {
                    "create" => Ok((
                        Method::POST,
                        format!("/zones/{scope_id}/dns_records"),
                        Some(params.clone()),
                    )),
                    "update" => {
                        let record_id = params
                            .get("record_id")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| AppError::BadRequest("record_id required for dns update".to_string()))?;
                        Ok((
                            Method::PUT,
                            format!("/zones/{scope_id}/dns_records/{record_id}"),
                            Some(params.clone()),
                        ))
                    }
                    "delete" => {
                        let record_id = params
                            .get("record_id")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| AppError::BadRequest("record_id required for dns delete".to_string()))?;
                        Ok((Method::DELETE, format!("/zones/{scope_id}/dns_records/{record_id}"), None))
                    }
                    _ => Err(AppError::BadRequest("unsupported dns action".to_string())),
                }
            }
            "cache.purge.execute" => {
                if scope_type != "zone" {
                    return Err(AppError::BadRequest("cache.purge.execute requires zone scope".to_string()));
                }
                Ok((
                    Method::POST,
                    format!("/zones/{scope_id}/purge_cache"),
                    Some(params.clone()),
                ))
            }
            "workers.deploy.write" => {
                if scope_type != "account" {
                    return Err(AppError::BadRequest(
                        "workers.deploy.write requires account scope".to_string(),
                    ));
                }
                let script_name = params
                    .get("script_name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::BadRequest("script_name is required".to_string()))?;
                Ok((
                    Method::PUT,
                    format!("/accounts/{scope_id}/workers/scripts/{script_name}"),
                    Some(params.clone()),
                ))
            }
            "waf.rules.read" => {
                if scope_type != "zone" {
                    return Err(AppError::BadRequest("waf.rules.read requires zone scope".to_string()));
                }
                Ok((
                    Method::GET,
                    format!("/zones/{scope_id}/firewall/rules"),
                    None,
                ))
            }
            "waf.rules.write" => {
                if scope_type != "zone" {
                    return Err(AppError::BadRequest("waf.rules.write requires zone scope".to_string()));
                }
                Ok((
                    Method::PUT,
                    format!("/zones/{scope_id}/firewall/rules"),
                    Some(params.clone()),
                ))
            }
            _ => Err(AppError::BadRequest(format!(
                "unsupported mapped operation: {operation_id}"
            ))),
        }
    }
}
