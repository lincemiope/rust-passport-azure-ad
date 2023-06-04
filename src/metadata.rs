use super::types::OidcKey;
use std::error::Error;
use alcoholic_jwt::JWKS;
use reqwest;
use serde::Deserialize;

pub struct Oidc {
    pub algorithms: Vec<String>,
    pub authorization_endpoint: String,
    pub end_session_endpoint: String,
    pub issuer: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub keys: Vec<OidcKey>
}

impl Oidc {
    pub fn new(keys: Vec<OidcKey>) -> Self {
        Self {
            algorithms: vec![],
            authorization_endpoint: String::new(),
            end_session_endpoint: String::new(),
            issuer: String::new(),
            token_endpoint: String::new(),
            userinfo_endpoint: String::new(),
            keys
        }
    }

    pub fn empty() -> Self {
        Self::new(vec![])
    }

    pub fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            algorithms: metadata.id_token_signing_alg_values_supported.clone(),
            authorization_endpoint: metadata.authorization_endpoint.clone(),
            end_session_endpoint: metadata.end_session_endpoint.clone(),
            issuer: metadata.issuer.clone(),
            token_endpoint: metadata.token_endpoint.clone(),
            userinfo_endpoint: metadata.userinfo_endpoint.clone(),
            keys: vec![]
        }
    }
}

#[derive(Deserialize)]
pub struct Metadata {
    pub token_endpoint: String,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub jwks_uri: String,
    pub response_modes_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub issuer: String,
    pub request_uri_parameter_supported: bool,
    pub userinfo_endpoint: String,
    pub authorization_endpoint: String,
    pub device_authorization_endpoint: String,
    pub http_logout_supported: bool,
    pub frontchannel_logout_supported: bool,
    pub end_session_endpoint: String,
    pub claims_supported: Vec<String>,
    pub kerberos_endpoint: String,
    pub tenant_region_scope: String,
    pub cloud_instance_name: String,
    pub msgraph_host: String,
    pub rbac_url: String
}

impl Metadata {
    pub fn empty() -> Self {
        Self {
            token_endpoint: String::new(),
            token_endpoint_auth_methods_supported: vec![],
            jwks_uri: String::new(),
            response_modes_supported: vec![],
            subject_types_supported: vec![],
            id_token_signing_alg_values_supported: vec![],
            response_types_supported: vec![],
            scopes_supported: vec![],
            issuer: String::new(),
            request_uri_parameter_supported: false,
            userinfo_endpoint: String::new(),
            authorization_endpoint: String::new(),
            device_authorization_endpoint: String::new(),
            http_logout_supported: false,
            frontchannel_logout_supported: false,
            end_session_endpoint: String::new(),
            claims_supported: vec![],
            kerberos_endpoint: String::new(),
            tenant_region_scope: String::new(),
            cloud_instance_name: String::new(),
            msgraph_host: String::new(),
            rbac_url: String::new()
        }
    }
}

pub struct MetadataHandler {
    pub url: String,
    pub oidc: Oidc,
    pub jwks: Option<JWKS>,
    pub metadata: Metadata,
    pub authtype: String,
    pub logging_no_pii: bool,
    pub https_proxy_agent: String,
}



impl MetadataHandler {
    pub fn new(url: String, authtype: String, logging_no_pii: bool, https_proxy_agent: Option<String>) -> Self {
        Self {
            url,
            oidc: Oidc::empty(),
            jwks: None,
            authtype,
            https_proxy_agent: https_proxy_agent.unwrap_or(String::new()),
            logging_no_pii,
            metadata: Metadata::empty()
        }
    }

    pub async fn fetch(&mut self) -> Result<(), Box<dyn Error>> {
        let metadata: Metadata = reqwest::Client::new()
            .get(&self.url)
            .header("User-Agent", &self.https_proxy_agent)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        self.metadata = metadata;
        self.oidc = Oidc::from_metadata(&self.metadata);

        let jwks: JWKS = reqwest::Client::new()
        .get(&self.metadata.jwks_uri)
        .header("User-Agent", &self.https_proxy_agent)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

        self.jwks = Some(jwks);

        Ok(())
    }
}