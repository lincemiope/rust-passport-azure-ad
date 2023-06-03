use super::aadutils::rsa_pub_key_pem;
use super::json_web_token::JWTKey;
use std::error::Error;

pub struct Oidc {
    pub algorithms: Option<Vec<String>>,
    pub authorization_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub issuer: Option<Vec<String>>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub keys: Vec<JWTKey>
}

impl Oidc {
    pub fn new(keys: Vec<JWTKey>) -> Self {
        Self {
            algorithms: None,
            authorization_endpoint: None,
            end_session_endpoint: None,
            issuer: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            keys
        }
    }

    pub fn empty() -> Self {
        Self::new(vec![])
    }
}

pub struct Metadata {
    pub url: String,
    pub oidc: Oidc,
    pub metadata: Option<()>,
    pub authtype: String,
    pub logging_no_pii: bool,
    pub https_proxy_agent: Option<String>,
}

pub struct MetadataParams;


impl Metadata {
    pub fn new(url: String, oidc: Oidc, authtype: String, https_proxy_agent: Option<String>) -> Self {
        Self {
            url,
            oidc,
            authtype,
            https_proxy_agent,
            logging_no_pii: false,
            metadata: None
        }
    }
    pub async fn build(url: String, oidc: Oidc, authtype: String, https_proxy_agent: Option<String>) -> Result<Self, Box<dyn Error>> {
        Ok(Metadata::new(url, oidc, authtype, https_proxy_agent))
    }

    pub fn fetch(&self, cb: impl FnOnce() -> ()) -> () {
        cb()
    }
    pub fn generate_oidc_pem(&self, kid: String) -> Result<String, Box<dyn Error>> {
        let mut pub_key: String = String::new();

        let cloned_keys = self.oidc.keys.clone();

        let found_key = cloned_keys
            .iter()
            .filter(|k| k.kid == kid && !k.n.is_empty() && !k.e.is_empty())
            .next();

        if let Some(key) = found_key {
            pub_key = rsa_pub_key_pem(&key.n, &key.e);
        } else {
            return Err("Key not found".into());
        }

        if pub_key.is_empty() {
            return Err("Key could not be translated into a PEM".into());
        }

        Ok(pub_key)
    }
}