use alcoholic_jwt::JWKS;
use reqwest;
use serde::{de::DeserializeOwned, Deserialize};
use std::error::Error;

#[derive(Deserialize, Default)]
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
    pub rbac_url: String,
}

impl Metadata {
    pub fn empty() -> Self {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub struct MetadataHandler {
    pub url: String,
    pub jwks: Option<JWKS>,
    pub metadata: Metadata,
    pub authtype: String,
    pub https_proxy_agent: String,
}

impl MetadataHandler {
    pub fn new(url: String, authtype: String, https_proxy_agent: Option<String>) -> Self {
        Self {
            url,
            jwks: None,
            authtype,
            https_proxy_agent: https_proxy_agent.unwrap_or(String::new()),
            metadata: Metadata::empty(),
        }
    }

    async fn fetcher<T: DeserializeOwned>(&self, url: String) -> T {
        reqwest::Client::new()
            .get(url)
            .header("User-Agent", &self.https_proxy_agent)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    pub async fn fetch(&mut self) -> Result<(), Box<dyn Error>> {
        self.metadata = self.fetcher(self.url.clone()).await;
        let jwks: JWKS = self.fetcher(self.metadata.jwks_uri.clone()).await;
        self.jwks = Some(jwks);

        Ok(())
    }
}
