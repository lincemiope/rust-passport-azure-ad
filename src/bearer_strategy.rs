use std::{error::Error};
use crate::{types::{StrategyOptions, Strategy}, constants, verifier, aadutils};
use super::metadata::MetadataHandler;
use poem::Request;
use super::types::StrategyOptionsParams;
use url::Url;
use regex::Regex;
use super::types::Payload;

static BEARER_NAME: &str = "oauth-bearer";

pub struct BearerStrategy {
    pub name: String,
    pub options: StrategyOptions
}

impl BearerStrategy {
    pub fn build(params: StrategyOptionsParams) -> Result<Self, Box<dyn Error>> {
        let mut options: StrategyOptions = StrategyOptions::new();

        // client_id
        let client_id: String;
        if params.client_id.is_some() {
            client_id = params.client_id.unwrap();
            options.client_id = client_id.clone();
        } else {
            return Err("In BearerStrategy constructor: client_id cannot be empty".into());
        }

        // identity_metadata
        if params.identity_metadata.is_none() {
            return Err("In BearerStrategy constructor: identity_metadata must be provided".into());
        }

        let identity_metadata = params.identity_metadata.unwrap();

        let identity_metadata_parsed = Url::parse(identity_metadata.as_str());
        if identity_metadata_parsed.is_err() || identity_metadata_parsed.unwrap().scheme() != "https" {
            return Err("In BearerStrategy constructor: identity_metadata must be a valid https url".into());
        }

        // check if we are using the common endpoint
        options.is_common_endpoint = identity_metadata.contains("/common/");
        options.identity_metadata = identity_metadata;

        // scope
        if let Some(scope) = params.scope {
            if scope.is_empty() {
                return Err("In BearerStrategy constructor: scope must be a non-empty array".into());
            }
            options.scope = scope;
        }

        // policy_name
        let mut policy_name_val: String = String::new();
        if let Some(policy_name) = params.policy_name {
            policy_name_val = policy_name;
            options.policy_name = policy_name_val.clone();
        }

        // is_b2c
        if let Some(is_b2c) = params.is_b2c {
            if is_b2c {
                let re = Regex::new(constants::POLICY_REGEX).unwrap();
                if !re.is_match(policy_name_val.as_str()) {
                    return Err("In BearerStrategy constructor: invalid policy for B2C".into());
                }
            }
        }

        // clock_stew
        if let Some(clock_stew) = params.clock_stew {
            options.clock_stew = clock_stew;
        }

        // pass_req_to_cb
        if let Some(pass_req_to_cb) = params.pass_req_to_cb {
            options.pass_req_to_cb = pass_req_to_cb;
        }

        // validate_issuer
        if let Some(validate_issuer) = params.validate_issuer {
            options.validate_issuer = validate_issuer;
        }

        // allow_multi_audiences
        if let Some(allow_multi_audiences) = params.allow_multi_audiences {
            options.allow_multi_audiences = allow_multi_audiences;
        }

        // audience
        if let Some(audience) = params.audience {
            if audience.is_empty() {
                options.audience = vec![
                    client_id.clone(),
                    vec![
                        String::from("spn:"),
                        client_id
                    ].join("")
                ];
            }
        }

        // issuer
        if let Some(issuer) = params.issuer {
            options.issuer = issuer;
        }

        // logging_no_pii
        if let Some(logging_no_pii) = params.logging_no_pii {
            options.logging_no_pii = logging_no_pii
        }

        Ok(Self::new(options))
    }

    fn new(options: StrategyOptions) -> Self {
        Self {
            name: String::from(BEARER_NAME),
            options
        }
    }

    pub async fn jwt_verify(&self, token: &str, metadata: &MetadataHandler) -> Result<Payload, Box<dyn Error>> {
        verifier::verify(token.to_string(), metadata, self.clone()).await
    }

    pub async fn authenticate(&self, req: Request) -> Result<Payload, Box<dyn Error>> {
        if let Some(bearer) = req.header("authorization") {
            let parts = bearer.split(" ").collect::<Vec<&str>>();

            if parts.len() != 2usize || parts[0].to_lowercase() != "bearer" || parts[1].is_empty() {
                return Err("Authorization is not valid".into());
            }

            let token = parts[1];
            let identity_metadata = self.options.clone().identity_metadata;
            let metadata_url = aadutils::concat_url(
                identity_metadata,
                vec![
                    format!("{}={}", constants::LIBRARY_PRODUCT_PARAMETER_NAME, constants::LIBRARY_PRODUCT),
                    format!("{}={}", constants::LIBRARY_VERSION_PARAMETER_NAME, constants::LIBRARY_VERSION)
                ]
            );
            let mut metadata = MetadataHandler::new(
                metadata_url,
                String::from("oidc"),
                false,
                None
            );

            metadata.fetch().await?;
    
            return self.jwt_verify(token, &metadata).await;
        } else {
            return Err("No 'authorization' header was found".into());
        }
    }

}

impl Strategy for BearerStrategy {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn options(&self) -> StrategyOptions {
        self.options.clone()
    }
}