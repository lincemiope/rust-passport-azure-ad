use super::constants;
use super::error::PassportError;
use super::util::fail_with_log;
use alcoholic_jwt::JWKS;
use memory_cache::MemoryCache;
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize};
use std::time::Duration;

static CACHE_KEY: &str = "__metadata_cache__";

#[derive(Clone)]
pub struct CacheValue {
    pub jwks: JWKS,
    pub metadata: Metadata,
}

#[derive(Deserialize, Clone)]
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

pub struct MetadataHandler {
    pub url: String,
    pub authtype: String,
    pub https_proxy_agent: String,
    pub cache: MemoryCache<&'static str, CacheValue>,
}

impl MetadataHandler {
    pub fn new(url: String, authtype: String, https_proxy_agent: Option<String>) -> Self {
        Self {
            url,
            authtype,
            https_proxy_agent: https_proxy_agent.unwrap_or(String::new()),
            cache: MemoryCache::new(),
        }
    }

    async fn fetcher<T: DeserializeOwned>(&self, url: &String) -> T {
        Client::new()
            .get(url)
            .header("User-Agent", &self.https_proxy_agent)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn fetch_and_save(&mut self) -> Result<(), PassportError> {
        let metadata: Metadata = self.fetcher(&self.url).await;
        let jwks: JWKS = self.fetcher(&metadata.jwks_uri).await;

        self.cache.insert(
            CACHE_KEY,
            CacheValue { jwks, metadata },
            Some(Duration::from_secs(constants::CACHE_TTL)),
        );

        Ok(())
    }

    pub async fn metadata(&mut self) -> Result<Metadata, PassportError> {
        if !self.cache.contains_key(&CACHE_KEY) {
            self.fetch_and_save().await.unwrap();
        }
        if let Some(value) = self.cache.get(&CACHE_KEY) {
            Ok(value.metadata.clone())
        } else {
            fail_with_log(
                "MetadataHandler.metadata",
                "No 'metadata' could be retrieved",
            )
        }
    }

    pub async fn jwks(&mut self) -> Result<JWKS, PassportError> {
        if !self.cache.contains_key(&CACHE_KEY) {
            self.fetch_and_save().await.unwrap();
        }
        if let Some(value) = self.cache.get(&CACHE_KEY) {
            Ok(value.jwks.clone())
        } else {
            fail_with_log("MetadataHandler.jwks", "No 'jwks' could be retrieved")
        }
    }
}
