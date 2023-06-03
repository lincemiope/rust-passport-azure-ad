pub mod enums;

#[derive(Clone)]
pub struct StrategyOptionsParams {
    pub clock_stew: Option<u32>,
    pub pass_req_to_cb: Option<bool>,
    pub validate_issuer: Option<bool>,
    pub allow_multi_audiences: Option<bool>,
    pub audience: Option<Vec<String>>,
    pub is_b2c: Option<bool>,
    pub policy_name: Option<String>,
    pub issuer: Option<Vec<String>>,
    pub client_id: Option<String>,
    pub identity_metadata: Option<String>,
    pub scope: Option<Vec<String>>,
    pub log_level: Option<enums::LogLevel>,
    pub logging_no_pii: Option<bool>
}