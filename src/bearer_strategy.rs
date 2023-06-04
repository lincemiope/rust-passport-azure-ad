extern crate alcoholic_jwt;

use std::{error::Error};
use super::{types::{StrategyOptions, Strategy}, constants, aadutils};
use super::metadata::MetadataHandler;
use poem::Request;
use super::types::StrategyOptionsParams;
use url::Url;
use regex::Regex;
use super::types::Payload;
use jws::compact::decode_unverified;
use alcoholic_jwt::{Validation, validate, token_kid};

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
        let s_opts = &self.options;

        // nobody cares
        /*
        if s_opts.audience.is_empty() {
            return Err("In verifier.verify: audience is not valid".into());
        }
        */
    
        if metadata.oidc.algorithms.is_empty() {
            return Err("In verifier.verify: algorithms is not valid".into());
        }
    
        let parts: Vec<&str> = token.split(".").collect();
    
        if parts.len() != 3 {
            return Err("In verifier.verify: jwt_string is malformed".into());
        }
    
        if parts[2].is_empty() {
            return Err("In verifier.verify: signature is missing in jwt_string".into());
        }
    
        let decoded = decode_unverified(token.clone().as_bytes()).unwrap();
        let payload = Payload::from_message(&decoded.0.payload).unwrap();
    
        // Several types of built-in validations are provided:
        let validations = vec![
            Validation::Issuer(self.options.issuer[0].clone()),
            Validation::SubjectPresent
        ];
    
        // If a JWKS contains multiple keys, the correct KID first
        // needs to be fetched from the token headers.
        let kid = token_kid(&token)
            .expect("In verifier.verify: failed to decode token headers")
            .expect("In verifier.verify: no 'kid' claim present in token");
    
        if let Some(jwks) = &metadata.jwks {
            let jwk = jwks.find(&kid)
                .expect("In verifier.verify: specified key not found in set");
    
            if let Ok(valid) = validate(&token, jwk, validations) {
                let scopes: Vec<String> = valid.claims
                    .as_object()
                    .unwrap()
                    .get("scp")
                    .unwrap()
                    .as_array()
                    .unwrap_or(&vec![])
                    .into_iter()
                    .map(|e| e.to_string())
                    .collect();
                if !scopes.is_empty() && !scopes.contains(&payload.scp) {
                    return Err("In verifier.verify: token scopes are not valid".into());
                }
                return Ok(payload)
            } else {
                return Err("In verifier.verify: token validation has failed!".into());
            }
        } else {
            return Err("In verifier.verify: no JWKS are present".into());
        }
    }

    pub async fn authenticate(&self, req: &Request) -> Result<Payload, Box<dyn Error>> {
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