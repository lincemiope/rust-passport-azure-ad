extern crate alcoholic_jwt;
use super::metadata::MetadataHandler;
use super::types::Payload;
use super::types::StrategyOptionsParams;
use super::{
    constants,
    types::{Strategy, StrategyOptions},
    util,
};
use alcoholic_jwt::{token_kid, validate, Validation};
use jws::compact::decode_unverified;
//use poem::Request;
use regex::Regex;
use std::error::Error;
use url::Url;

static BEARER_NAME: &str = "oauth-bearer";

pub struct BearerStrategy {
    pub name: String,
    pub options: StrategyOptions,
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
            return util::fail_with_log::<Self>(
                "In BearerStrategy constructor: client_id cannot be empty",
            );
        }

        // identity_metadata
        if params.identity_metadata.is_none() {
            return util::fail_with_log::<Self>(
                "In BearerStrategy constructor: identity_metadata must be provided",
            );
        }

        let identity_metadata = params.identity_metadata.unwrap();

        let identity_metadata_parsed = Url::parse(identity_metadata.as_str());
        if identity_metadata_parsed.is_err()
            || identity_metadata_parsed.unwrap().scheme() != "https"
        {
            return util::fail_with_log::<Self>(
                "In BearerStrategy constructor: identity_metadata must be a valid https url",
            );
        }

        // check if we are using the common endpoint
        options.is_common_endpoint = identity_metadata.contains("/common/");
        options.identity_metadata = identity_metadata;

        // scope
        if let Some(scope) = params.scope {
            if scope.is_empty() {
                return util::fail_with_log::<Self>(
                    "In BearerStrategy constructor: scope must be a non-empty array",
                );
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
                    return util::fail_with_log::<Self>(
                        "In BearerStrategy constructor: invalid policy for B2C",
                    );
                }
            }
        }

        // clock_stew
        if let Some(clock_stew) = params.clock_stew {
            options.clock_stew = clock_stew;
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
                    vec![String::from("spn:"), client_id].join(""),
                ];
            }
        }

        // issuer
        if let Some(issuer) = params.issuer {
            options.issuer = issuer;
        }

        if let Some(ignore_expiration) = params.ignore_expiration {
            options.ignore_expiration = ignore_expiration;
        }

        Ok(Self::new(options))
    }

    fn new(options: StrategyOptions) -> Self {
        Self {
            name: String::from(BEARER_NAME),
            options,
        }
    }

    pub async fn jwt_verify(
        &self,
        token: String,
        metadata: &MetadataHandler,
    ) -> Result<Payload, Box<dyn Error>> {
        if metadata
            .metadata
            .id_token_signing_alg_values_supported
            .is_empty()
        {
            return util::fail_with_log::<Payload>("In verifier.verify: algorithms is not valid");
        }

        let parts: Vec<&str> = token.split(".").collect();

        if parts.len() != 3 {
            return util::fail_with_log::<Payload>("In verifier.verify: jwt_string is malformed");
        }

        if parts[2].is_empty() {
            return util::fail_with_log::<Payload>(
                "In verifier.verify: signature is missing in jwt_string",
            );
        }

        let decoded = decode_unverified(token.clone().as_bytes()).unwrap();
        let payload = Payload::from_message(&decoded.0.payload).unwrap();

        // Several types of built-in validations are provided:
        let mut validations = vec![Validation::SubjectPresent];

        // ignore expiration
        if !self.options.ignore_expiration {
            validations.push(Validation::NotExpired);
        }

        // validate issuer
        if self.options.validate_issuer {
            validations.push(Validation::Issuer(self.options.issuer[0].clone()));
        }

        // If a JWKS contains multiple keys, the correct KID first
        // needs to be fetched from the token headers.
        let kid = token_kid(&token)
            .expect("In verifier.verify: failed to decode token headers")
            .expect("In verifier.verify: no 'kid' claim present in token");

        if let Some(jwks) = &metadata.jwks {
            let jwk = jwks
                .find(&kid)
                .expect("In verifier.verify: specified key not found in set");

            if let Ok(valid) = validate(&token, jwk, validations) {
                // validate audience
                let token_audience: Vec<String> = util::extract_claim_vec(&valid.claims, "aud");

                // validate multiple audiences
                if !self.options.allow_multi_audiences && token_audience.len() > 1usize {
                    return util::fail_with_log::<Payload>(
                        "In verifier.verify: multiple audiences are not allowed",
                    );
                }

                if !&self.options.audience.is_empty()
                    && !util::contains_all(&self.options.audience, &token_audience)
                {
                    return util::fail_with_log::<Payload>(
                        "In verifier.verify: audience is not valid",
                    );
                }

                // validate scopes
                let token_scopes: Vec<String> = util::extract_claim_vec(&valid.claims, "scp");
                let opt_scopes = &metadata.metadata.scopes_supported;

                if !opt_scopes.is_empty() && util::contains_all(opt_scopes, &token_scopes) {
                    return util::fail_with_log::<Payload>(
                        "In verifier.verify: token scopes are not valid",
                    );
                }

                return Ok(payload);
            } else {
                return util::fail_with_log::<Payload>(
                    "In verifier.verify: token validation has failed!",
                );
            }
        } else {
            return util::fail_with_log::<Payload>("In verifier.verify: no JWKS are present");
        }
    }

    /*
        pub async fn authenticate_req(&self, req: &Request) -> Result<Payload, Box<dyn Error>> {
            if let Some(bearer) = req.header("authorization") {
                let parts = bearer.split(" ").collect::<Vec<&str>>();

                if parts.len() != 2usize || parts[0].to_lowercase() != "bearer" || parts[1].is_empty() {
                    return util::fail_with_log::<Payload>("Authorization is not valid");
                }

                let token = parts[1];
                return self.authenticate(token.to_string()).await;
            } else {
                return util::fail_with_log::<Payload>("No 'authorization' header was found");
            }
        }

    */
    pub async fn authenticate(&self, token: String) -> Result<Payload, Box<dyn Error>> {
        let identity_metadata = self.options.clone().identity_metadata;
        let metadata_url = util::concat_url(
            identity_metadata,
            vec![
                format!(
                    "{}={}",
                    constants::LIBRARY_PRODUCT_PARAMETER_NAME,
                    constants::LIBRARY_PRODUCT
                ),
                format!(
                    "{}={}",
                    constants::LIBRARY_VERSION_PARAMETER_NAME,
                    constants::LIBRARY_VERSION
                ),
            ],
        );
        let mut metadata = MetadataHandler::new(metadata_url, String::from("oidc"), None);

        metadata.fetch().await?;

        return self.jwt_verify(token, &metadata).await;
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
