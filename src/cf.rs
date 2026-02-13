use reqwest::{Client, Method, Url};
use serde_json::{Value, json};

use crate::{error::AppError, models::OperationExecutionResult};

#[derive(Clone)]
pub struct CloudflareExecutor {
    pub api_token: Option<String>,
    pub api_base: String,
    pub http: Client,
}

#[derive(Debug)]
struct RoutedRequest {
    method: Method,
    segments: Vec<String>,
    query_params: Vec<(String, String)>,
    body: Option<Value>,
}

impl CloudflareExecutor {
    pub fn new(api_token: Option<String>, api_base: String, http: Client) -> Self {
        Self {
            api_token,
            api_base,
            http,
        }
    }

    pub async fn execute(
        &self,
        operation_id: &str,
        scope_type: &str,
        scope_id: &str,
        params: &Value,
    ) -> Result<OperationExecutionResult, AppError> {
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

        let routed = self.route(operation_id, scope_type, scope_id, params)?;
        let url = self.build_url(&routed)?;

        let mut request = self
            .http
            .request(routed.method, url)
            .bearer_auth(token)
            .header("content-type", "application/json");

        if let Some(body) = routed.body {
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

    fn route(
        &self,
        operation_id: &str,
        scope_type: &str,
        scope_id: &str,
        params: &Value,
    ) -> Result<RoutedRequest, AppError> {
        validate_identifier("scope_id", scope_id)?;

        match operation_id {
            "dns.record.read" => {
                if scope_type != "zone" {
                    return Err(AppError::BadRequest(
                        "dns.record.read requires zone scope".to_string(),
                    ));
                }
                let mut query_params = Vec::new();
                if let Some(name) = params.get("name").and_then(|v| v.as_str()) {
                    query_params.push(("name".to_string(), name.to_string()));
                }

                Ok(RoutedRequest {
                    method: Method::GET,
                    segments: vec![
                        "zones".to_string(),
                        scope_id.to_string(),
                        "dns_records".to_string(),
                    ],
                    query_params,
                    body: None,
                })
            }
            "dns.record.write" => {
                if scope_type != "zone" {
                    return Err(AppError::BadRequest(
                        "dns.record.write requires zone scope".to_string(),
                    ));
                }
                let action = params
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("create");

                match action {
                    "create" => Ok(RoutedRequest {
                        method: Method::POST,
                        segments: vec![
                            "zones".to_string(),
                            scope_id.to_string(),
                            "dns_records".to_string(),
                        ],
                        query_params: vec![],
                        body: Some(params.clone()),
                    }),
                    "update" => {
                        let record_id = params
                            .get("record_id")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                AppError::BadRequest(
                                    "record_id required for dns update".to_string(),
                                )
                            })?;
                        validate_identifier("record_id", record_id)?;
                        Ok(RoutedRequest {
                            method: Method::PUT,
                            segments: vec![
                                "zones".to_string(),
                                scope_id.to_string(),
                                "dns_records".to_string(),
                                record_id.to_string(),
                            ],
                            query_params: vec![],
                            body: Some(params.clone()),
                        })
                    }
                    "delete" => {
                        let record_id = params
                            .get("record_id")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                AppError::BadRequest(
                                    "record_id required for dns delete".to_string(),
                                )
                            })?;
                        validate_identifier("record_id", record_id)?;
                        Ok(RoutedRequest {
                            method: Method::DELETE,
                            segments: vec![
                                "zones".to_string(),
                                scope_id.to_string(),
                                "dns_records".to_string(),
                                record_id.to_string(),
                            ],
                            query_params: vec![],
                            body: None,
                        })
                    }
                    _ => Err(AppError::BadRequest("unsupported dns action".to_string())),
                }
            }
            "cache.purge.execute" => {
                if scope_type != "zone" {
                    return Err(AppError::BadRequest(
                        "cache.purge.execute requires zone scope".to_string(),
                    ));
                }
                Ok(RoutedRequest {
                    method: Method::POST,
                    segments: vec![
                        "zones".to_string(),
                        scope_id.to_string(),
                        "purge_cache".to_string(),
                    ],
                    query_params: vec![],
                    body: Some(params.clone()),
                })
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
                validate_script_name(script_name)?;
                Ok(RoutedRequest {
                    method: Method::PUT,
                    segments: vec![
                        "accounts".to_string(),
                        scope_id.to_string(),
                        "workers".to_string(),
                        "scripts".to_string(),
                        script_name.to_string(),
                    ],
                    query_params: vec![],
                    body: Some(params.clone()),
                })
            }
            "waf.rules.read" => {
                if scope_type != "zone" {
                    return Err(AppError::BadRequest(
                        "waf.rules.read requires zone scope".to_string(),
                    ));
                }
                Ok(RoutedRequest {
                    method: Method::GET,
                    segments: vec![
                        "zones".to_string(),
                        scope_id.to_string(),
                        "firewall".to_string(),
                        "rules".to_string(),
                    ],
                    query_params: vec![],
                    body: None,
                })
            }
            "waf.rules.write" => {
                if scope_type != "zone" {
                    return Err(AppError::BadRequest(
                        "waf.rules.write requires zone scope".to_string(),
                    ));
                }
                Ok(RoutedRequest {
                    method: Method::PUT,
                    segments: vec![
                        "zones".to_string(),
                        scope_id.to_string(),
                        "firewall".to_string(),
                        "rules".to_string(),
                    ],
                    query_params: vec![],
                    body: Some(params.clone()),
                })
            }
            _ => Err(AppError::BadRequest(format!(
                "unsupported mapped operation: {operation_id}"
            ))),
        }
    }

    fn build_url(&self, routed: &RoutedRequest) -> Result<Url, AppError> {
        let mut url = Url::parse(&self.api_base)
            .map_err(|_| AppError::internal("invalid cloudflare api base URL"))?;
        {
            let mut path = url.path_segments_mut().map_err(|_| {
                AppError::internal("cloudflare api base URL cannot be a base for paths")
            })?;
            for segment in &routed.segments {
                path.push(segment);
            }
        }
        if !routed.query_params.is_empty() {
            let mut query = url.query_pairs_mut();
            for (k, v) in &routed.query_params {
                query.append_pair(k, v);
            }
        }
        Ok(url)
    }
}

fn validate_identifier(label: &str, value: &str) -> Result<(), AppError> {
    let is_valid = !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !is_valid {
        return Err(AppError::BadRequest(format!(
            "{label} has an invalid format"
        )));
    }
    Ok(())
}

fn validate_script_name(value: &str) -> Result<(), AppError> {
    let is_valid = !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if !is_valid {
        return Err(AppError::BadRequest(
            "script_name has an invalid format".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::CloudflareExecutor;
    use reqwest::{Client, Method};
    use serde_json::json;

    fn executor() -> CloudflareExecutor {
        CloudflareExecutor::new(
            None,
            "https://api.cloudflare.com/client/v4".to_string(),
            Client::new(),
        )
    }

    #[test]
    fn route_rejects_invalid_scope_for_dns_read() {
        let err = executor()
            .route("dns.record.read", "account", "acc1", &json!({}))
            .expect_err("scope validation should fail");
        assert!(err.to_string().contains("requires zone scope"));
    }

    #[test]
    fn route_rejects_invalid_script_name() {
        let err = executor()
            .route(
                "workers.deploy.write",
                "account",
                "acc-123",
                &json!({"script_name": "../bad", "script": "x"}),
            )
            .expect_err("invalid script name should fail");
        assert!(err.to_string().contains("invalid format"));
    }

    #[test]
    fn route_builds_workers_deploy_path() {
        let routed = executor()
            .route(
                "workers.deploy.write",
                "account",
                "acc-123",
                &json!({"script_name": "edge-script", "script": "addEventListener()"}),
            )
            .expect("route should succeed");

        assert_eq!(routed.method, Method::PUT);
        assert_eq!(
            routed.segments,
            vec![
                "accounts".to_string(),
                "acc-123".to_string(),
                "workers".to_string(),
                "scripts".to_string(),
                "edge-script".to_string()
            ]
        );
        assert!(routed.body.is_some());
    }

    #[test]
    fn build_url_encodes_query_params() {
        let routed = executor()
            .route(
                "dns.record.read",
                "zone",
                "zone1",
                &json!({"name": "example.com?a=b"}),
            )
            .expect("route should succeed");
        let url = executor().build_url(&routed).expect("url should build");
        assert!(url.as_str().contains("name=example.com%3Fa%3Db"));
    }

    #[tokio::test]
    async fn execute_simulates_without_api_token() {
        let result = executor()
            .execute(
                "dns.record.read",
                "zone",
                "zone-1",
                &json!({"name":"example.com"}),
            )
            .await
            .expect("simulated execution should succeed");
        assert!(result.success);
        assert_eq!(result.result["simulated"], json!(true));
    }
}
